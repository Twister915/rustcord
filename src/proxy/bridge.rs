use super::crypto::{DecryptReader, EncryptWriter};
use super::{ReadStream, WriteStream};
use anyhow::{anyhow, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use mcproto_rs::protocol::{Packet as PacketTrait, RawPacket};
use mcproto_rs::types::{BytesSerializer, VarInt};
use mcproto_rs::v1_15_2::{Id, Packet578 as Packet, PacketDirection, State};
use mcproto_rs::{Deserialize, Deserialized, Serialize, Serializer};
use std::io::{Cursor, Read, Write};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[macro_export]
macro_rules! read_check_closed {
    ($e:expr $(,)?) => {
        match $e.await? {
            PacketNext::Read(raw) => raw,
            PacketNext::Closed => {
                return Err(anyhow!("connection closed"));
            }
        }
    };
}

#[macro_export]
macro_rules! read_parse {
    ($e: expr $(,)?) => (Packet::mc_deserialize(read_check_closed!($e))?)
}

pub enum PacketNext<T> {
    Read(T),
    Closed,
}

pub struct Bridge {
    encryption_enabled: bool,
    stream: Option<(ReadBridge, WriteBridge)>,
    remote: SocketAddr,
}

pub struct ReadBridge {
    stream: Box<dyn ReadStream>,
    state: State,
    direction: PacketDirection,
    compression_threshold: Option<usize>,
    remote: SocketAddr,
    zlib_decoder: Option<ZlibDecoder<Cursor<Vec<u8>>>>,
}

pub struct WriteBridge {
    stream: Box<dyn WriteStream>,
    compression_threshold: Option<usize>,
    remote: SocketAddr,
    zlib_buf: Option<Vec<u8>>,
}

impl Bridge {
    pub fn initial(
        read_direction: PacketDirection,
        connection: TcpStream,
        remote: SocketAddr,
    ) -> Self {
        let (read_tcp, write_tcp) = connection.into_split();
        let reader = ReadBridge {
            stream: Box::new(read_tcp),
            state: State::Handshaking,
            direction: read_direction,
            compression_threshold: None,
            remote,
            zlib_decoder: None,
        };
        let writer = WriteBridge {
            stream: Box::new(write_tcp),
            compression_threshold: None,
            remote,
            zlib_buf: None,
        };
        let stream = Some((reader, writer));
        Self {
            encryption_enabled: false,
            stream,
            remote,
        }
    }

    pub fn split(&mut self) -> (&mut ReadBridge, &mut WriteBridge) {
        let (ref mut read_stream, ref mut write_stream) = self
            .stream
            .as_mut()
            .expect("connection should always be present");
        (read_stream, write_stream)
    }

    pub fn into_split(self) -> (ReadBridge, WriteBridge) {
        self.stream.expect("connection should always be present")
    }

    pub async fn read_packet(&mut self) -> Result<PacketNext<RawPacket<Id>>> {
        let (ref mut read_stream, _) = self
            .stream
            .as_mut()
            .expect("connection should always be present");
        read_stream.read_packet().await
    }

    pub async fn write_raw_packet(&mut self, raw_packet: RawPacket<Id>) -> Result<()> {
        let (_, ref mut write_stream) = self
            .stream
            .as_mut()
            .expect("connection should always be present");
        write_stream.write_raw_packet(raw_packet).await
    }

    pub async fn write_packet_bytes(&mut self, raw_body_data: Vec<u8>) -> Result<()> {
        let (_, ref mut write_stream) = self
            .stream
            .as_mut()
            .expect("connection should always be present");
        write_stream.write_packet_bytes(raw_body_data).await
    }

    pub async fn write_packet(&mut self, packet: Packet) -> Result<()> {
        let (_, ref mut write_stream) = self
            .stream
            .as_mut()
            .expect("connection should always be present");
        write_stream.write_packet(packet).await
    }

    pub fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        if self.encryption_enabled {
            return Err(anyhow!("cannot enable encryption more than once!"));
        }

        let (
            ReadBridge {
                stream: read_stream,
                state,
                direction: read_direction,
                compression_threshold: r_compression_threshold,
                remote: r_remote,
                zlib_decoder,
            },
            WriteBridge {
                stream: write_stream,
                compression_threshold: w_compression_threshold,
                remote: w_remote,
                zlib_buf,
            },
        ) = self.stream.take().expect("connection must exist always");

        let read_bridge = ReadBridge {
            stream: Box::new(DecryptReader::wrap(read_stream, key, iv)?),
            state,
            direction: read_direction,
            compression_threshold: r_compression_threshold,
            remote: r_remote,
            zlib_decoder,
        };

        let write_bridge = WriteBridge {
            stream: Box::new(EncryptWriter::wrap(write_stream, key, iv)?),
            compression_threshold: w_compression_threshold,
            remote: w_remote,
            zlib_buf,
        };

        self.stream = Some((read_bridge, write_bridge));
        Ok(())
    }

    pub fn set_compression_threshold(&mut self, threshold: usize) {
        let (read, write) = self.split();
        read.compression_threshold = Some(threshold);
        write.compression_threshold = Some(threshold);
    }

    pub fn set_state(&mut self, state: State) {
        let (read, _) = self.split();
        read.state = state;
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.remote
    }
}

impl ReadBridge {
    pub async fn read_packet(&mut self) -> Result<PacketNext<RawPacket<Id>>> {
        let packet_length: VarInt = match self.read_one_varint().await? {
            PacketNext::Read(value) => value,
            PacketNext::Closed => {
                return Ok(PacketNext::Closed);
            }
        };

        let mut data = vec![0u8; packet_length.into()];
        let result = self.stream.read_exact(data.as_mut_slice()).await;
        match result {
            Ok(size) => {
                if size == 0 {
                    return Ok(PacketNext::Closed);
                }
            }
            Err(err) => {
                return Err(err.into());
            }
        }

        let data = if let Some(threshold) = self.compression_threshold.as_ref() {
            let Deserialized {
                value: raw_data_len,
                data,
            } = VarInt::mc_deserialize(data.as_slice())?;
            let data_len: usize = raw_data_len.into();
            let data_vec = data.to_vec();
            // packet is not compressed
            if data_len == 0 {
                data_vec
            } else {
                if data_len < *threshold {
                    return Err(anyhow!(
                        "deserialize decompress below threshold {} < {}",
                        raw_data_len,
                        threshold
                    ));
                }

                let mut decompressed = vec![0u8; raw_data_len.into()];
                let cursor = Cursor::new(data_vec);
                let decoder = if let Some(decompressor) = self.zlib_decoder.as_mut() {
                    decompressor.reset(cursor);
                    decompressor
                } else {
                    self.zlib_decoder = Some(ZlibDecoder::new(cursor));
                    self.zlib_decoder.as_mut().expect("just set this")
                };

                decoder.read_exact(&mut decompressed)?;
                decompressed
            }
        } else {
            data
        };

        let Deserialized {
            value: packet_id,
            data,
        } = VarInt::mc_deserialize(data.as_slice())?;

        Ok(PacketNext::Read(RawPacket {
            data: data.to_vec(),
            id: Id {
                id: packet_id.into(),
                state: self.state.clone(),
                direction: self.direction.clone(),
            },
        }))
    }

    async fn read_one_varint(&mut self) -> Result<PacketNext<VarInt>> {
        let mut len = 0;
        let mut buf = [0u8; 5];
        let mut has_more = true;

        while has_more {
            if len == 5 {
                return Err(anyhow!(
                    "cannot deserialize VarInt, exceeds 5 bytes {:?}",
                    buf.to_vec()
                ));
            }

            let n_read = self.stream.read(&mut buf[len..len + 1]).await?;
            if n_read == 0 {
                return Ok(PacketNext::Closed);
            }
            has_more = buf[len] & 0x80 != 0;
            len += 1;
        }

        let Deserialized { value, data } = VarInt::mc_deserialize(&buf[..len])?;
        if !data.is_empty() {
            Err(anyhow!("extra data at end of VarInt... {:?}", &buf))
        } else {
            Ok(PacketNext::Read(value))
        }
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.remote
    }
}

impl WriteBridge {
    pub async fn write_packet(&mut self, packet: Packet) -> Result<()> {
        self.write_raw_packet(RawPacket {
            data: {
                let mut out = BytesSerializer::default();
                packet.mc_serialize(&mut out)?;
                out.into_bytes()
            },
            id: packet.id(),
        })
        .await
    }

    pub async fn write_raw_packet(&mut self, raw_packet: RawPacket<Id>) -> Result<()> {
        self.write_packet_bytes({
            let mut out = BytesSerializer::with_capacity(5 + raw_packet.data.len());
            let id = raw_packet.id;
            out.serialize_other(&id)?;
            out.serialize_bytes(raw_packet.data.as_slice())?;
            out.into_bytes()
        })
        .await
    }

    pub async fn write_packet_bytes(&mut self, raw_body_data: Vec<u8>) -> Result<()> {
        let body_data = if let Some(compression_threshold) = self.compression_threshold {
            if raw_body_data.len() < compression_threshold {
                let mut out = BytesSerializer::with_capacity(6 + raw_body_data.len());
                let serialized_len = VarInt((1 + raw_body_data.len()) as i32);
                // packet length
                out.serialize_other(&serialized_len)?;
                // data length
                out.serialize_other(&VarInt(0))?;
                // packet body (uncompressed)
                out.serialize_bytes(raw_body_data.as_slice())?;
                out.into_bytes()
            } else {
                let cursor = Cursor::new(if let Some(buf) = self.zlib_buf.as_mut() {
                    buf.clear();
                    buf
                } else {
                    self.zlib_buf = Some(Vec::with_capacity(8192));
                    self.zlib_buf.as_mut().expect("just set this up")
                });
                let mut encoder = ZlibEncoder::new(cursor, Compression::fast());
                encoder.write_all(raw_body_data.as_slice())?;
                let compressed = encoder.finish()?.into_inner();

                let with_data_len = {
                    let mut out = BytesSerializer::with_capacity(5 + compressed.len());
                    out.serialize_other(&VarInt(raw_body_data.len() as i32))?;
                    out.serialize_bytes(compressed.as_slice())?;
                    out.into_bytes()
                };

                let mut out = BytesSerializer::with_capacity(5 + with_data_len.len());
                out.serialize_other(&VarInt(with_data_len.len() as i32))?;
                out.serialize_bytes(with_data_len.as_slice())?;
                out.into_bytes()
            }
        } else {
            let mut out = BytesSerializer::with_capacity(5 + raw_body_data.len());
            out.serialize_other(&VarInt(raw_body_data.len() as i32))?;
            out.serialize_bytes(raw_body_data.as_slice())?;
            out.into_bytes()
        };

        self.stream.write_all(body_data.as_slice()).await?;
        Ok(())
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.remote
    }
}
