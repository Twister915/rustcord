use mcproto_rs::v1_15_2::{State, PacketDirection, Id, Packet578};
use std::net::SocketAddr;
use anyhow::Result;
use mcproto_rs::protocol::Packet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use mcproto_rs::types::VarInt;
use mcproto_rs::{Deserialize, Deserialized, Serializer, SerializeResult, Serialize};
use flate2::{Decompress, FlushDecompress, Status, Compression, FlushCompress};
use anyhow::anyhow;
use tokio::net::TcpStream;
use tokio::io::BufReader;
use super::crypto::{DecryptReader, EncryptWriter};
use super::{ReadStream, WriteStream};

pub struct Bridge {
    encryption_enabled: bool,
    reader: ReadBridge,
    writer: WriteBridge,
}

impl Bridge {
    pub fn initial(
        read_direction: PacketDirection,
        connection: TcpStream,
        remote: SocketAddr,
    ) -> Result<Self> {
        connection.set_nodelay(true)?;

        let (read_tcp, write_tcp) = connection.into_split();
        let buf_read_tcp = BufReader::new(read_tcp);

        let state = BridgeState {
            state: State::Handshaking,
            compression_threshold: None,
            read_direction,
            remote,
        };

        let reader = ReadBridge {
            raw_buf: Vec::with_capacity(512),
            decompressor_buf: None,
            state: state.clone(),
            reader: Some(Box::new(buf_read_tcp)),
        };

        let writer = WriteBridge {
            raw_buf: Vec::with_capacity(512),
            state: state.clone(),
            compress_buf: None,
            writer: Some(Box::new(write_tcp)),
        };

        Ok(Self {
            encryption_enabled: false,
            reader,
            writer,
        })
    }

    pub fn set_state(&mut self, state: State) {
        self.reader.state.state = state;
        self.writer.state.state = state;
    }

    pub async fn read_packet<'a>(&'a mut self) -> Result<Option<Box<dyn RawPacket + 'a>>> {
        self.reader.read_packet().await
    }

    pub async fn must_read_packet<'a>(&'a mut self) -> Result<Box<dyn RawPacket + 'a>> {
        match self.read_packet().await? {
            Some(packet) => Ok(packet),
            None => Err(anyhow!("unexpected eof"))
        }
    }

    pub async fn write_packet(&mut self, packet: Packet578) -> Result<()> {
        self.writer.write_packet(packet).await
    }

    pub fn split(self) -> (ReadBridge, WriteBridge) {
        (self.reader, self.writer)
    }

    pub fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        if self.encryption_enabled {
            return Err(anyhow!("encryption already enabled..."));
        }

        self.reader.reader = Some(
            Box::new(
                DecryptReader::wrap(
                    self.reader.reader.take().expect("it's always there"),
                    key.clone(),
                    iv.clone())?));

        self.writer.writer = Some(
            Box::new(
                EncryptWriter::wrap(
                    self.writer.writer.take().expect("it's always there"),
                    key.clone(),
                    iv.clone())?));

        self.encryption_enabled = true;
        Ok(())
    }

    pub fn set_compression_threshold(&mut self, threshold: usize) {
        self.reader.state.compression_threshold = Some(threshold);
        self.writer.state.compression_threshold = Some(threshold);
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.reader.state.remote
    }
}

pub struct ReadBridge {
    reader: Option<Box<dyn ReadStream>>,
    raw_buf: Vec<u8>,
    decompressor_buf: Option<Vec<u8>>,
    state: BridgeState,
}

impl ReadBridge {
    pub async fn read_packet<'a>(&'a mut self) -> Result<Option<Box<dyn RawPacket + 'a>>> {
        let this = &mut *self;
        let reader = this.reader.as_mut().expect("it's always there");
        let state = &this.state;
        let raw_buf = &mut this.raw_buf;
        let packet_len = match read_one_varint(reader).await? {
            Some(v) => v,
            None => return Ok(None)
        };

        let mut buf = get_sized_buf(raw_buf, packet_len.into());
        reader.read_exact(buf).await?;
        if let Some(_) = state.compression_threshold {
            let Deserialized { value: data_len, data: rest } = VarInt::mc_deserialize(buf)?;
            let bytes_consumed = buf.len() - rest.len();
            buf = &mut buf[bytes_consumed..];

            if data_len.0 != 0 {
                let mut decompress = flate2::Decompress::new(true);
                let needed = data_len.0 as usize;
                let decompress_buf = &mut this.decompressor_buf;
                let decompress_buf = match decompress_buf {
                    Some(buf) => get_sized_buf(buf, needed),
                    None => {
                        *decompress_buf = Some(Vec::with_capacity(needed));
                        decompress_buf.as_mut().unwrap().as_mut_slice()
                    }
                };
                match decompress.decompress(buf, &mut decompress_buf[..5], FlushDecompress::Sync)? {
                    Status::BufError => return Err(anyhow!("unable to deserialize because of buf err while reading id")),
                    Status::StreamEnd => return Err(anyhow!("stream end error while reading id")),
                    Status::Ok => {}
                }

                // number of bytes decompressed so far
                let decompressed_size = decompress.total_out() as usize;
                // bytes that we decompressed
                let decompressed_so_far = &decompress_buf[..decompressed_size];
                // packet id
                let Deserialized { value: packet_id, data: remaining_decompressed } = VarInt::mc_deserialize(decompressed_so_far)?;
                // remaining uncompressed data + a bunch of 0s for buf
                let n_decompressed_remain = remaining_decompressed.len();
                let decompress_buf = &mut decompress_buf[decompressed_size - n_decompressed_remain..];
                let source_offset = decompress.total_in() as usize;

                return Ok(Some(Box::new(CompressedRawPacket {
                    decompressor: decompress,
                    source: buf,
                    decompress_to: decompress_buf,
                    source_offset,
                    already_decompressed: n_decompressed_remain,
                    id: Id {
                        id: packet_id.0,
                        state: state.state.clone(),
                        direction: state.read_direction.clone(),
                    },
                })));
            }
        }

        let Deserialized { value: packet_id, data: buf } = VarInt::mc_deserialize(buf)?;
        Ok(Some(Box::new(RegularRawPacket {
            data: buf,
            id: Id {
                id: packet_id.0,
                state: state.state.clone(),
                direction: state.read_direction.clone(),
            },
        })))
    }
}

fn get_sized_buf(raw_buf: &mut Vec<u8>, needed: usize) -> &mut [u8] {
    let cur_len = raw_buf.len();
    if cur_len < needed {
        let additional = needed - cur_len;
        raw_buf.reserve(additional);
        let new_len = raw_buf.capacity();
        unsafe {
            let start_at = raw_buf.as_mut_ptr();
            let new_start_at = start_at.offset(cur_len as isize);
            std::ptr::write_bytes(new_start_at, 0, new_len - cur_len);
            raw_buf.set_len(new_len);
        }
    }

    &mut raw_buf[..needed]
}

async fn read_one_varint<R>(from: &mut R) -> Result<Option<VarInt>> where R: AsyncRead + Unpin {
    let mut buf = [0u8; 5];
    let mut len = 0usize;
    let mut has_more = true;
    while has_more {
        if len == 5 {
            return Err(anyhow!("varint too long while reading id/length/whatever"));
        }

        let size = from.read(&mut buf[len..len + 1]).await?;
        if size == 0 {
            return Ok(None);
        }

        has_more = buf[len] & 0x80 != 0;
        len += 1;
    }

    Ok(Some(VarInt::mc_deserialize(&buf[..len])?.value))
}

pub struct WriteBridge {
    writer: Option<Box<dyn WriteStream>>,
    state: BridgeState,
    raw_buf: Vec<u8>,
    compress_buf: Option<Vec<u8>>,
}

impl WriteBridge {
    pub async fn write_packet(&mut self, packet: Packet578) -> Result<()> {
        let this = &mut *self;
        // buf to serialize body bytes to
        let raw_buf = &mut this.raw_buf;

        // write body bytes
        let mut serializer = GrowVecSerializer {
            buf: raw_buf,
            at: 0,
        };
        packet.mc_serialize(&mut serializer)?;
        let len = serializer.at;

        // serialize the packet ID to the end of the body...
        const PREFIX_EXTRA: usize = 5;
        // make sure we have double extra capacity for the ID (max 5 bytes each)
        let prefix_buf = get_sized_buf(raw_buf, len + (PREFIX_EXTRA * 2));
        // the slice where we should serialize the id and len to
        let prefix_buf_len = prefix_buf.len();
        let prefix_buf = &mut prefix_buf[prefix_buf_len - PREFIX_EXTRA..];
        // the id to serialize
        let id = packet.id();
        let mut serializer = SliceSerializer {
            slice: prefix_buf,
            at: 0,
        };
        serializer.serialize_other(&id)?;
        let id = &serializer.slice[..serializer.at];
        let id_len = id.len();
        let data_len = VarInt((len + id_len) as i32);

        let (packet_buf, packet_len) = if let Some(threshold) = this.state.compression_threshold.as_ref() {
            if *threshold <= data_len.into() {
                // move id to front of body buf and then compress entire body buf:

                // move id
                unsafe {
                    let body_start_at = raw_buf.as_mut_ptr();
                    let id_start_at = body_start_at.offset((len + PREFIX_EXTRA) as isize);
                    let new_body_start_at = body_start_at.offset(id_len as isize);
                    std::ptr::copy(body_start_at, new_body_start_at, len);
                    std::ptr::copy(id_start_at, body_start_at, id_len);
                }

                // compress body buf
                let mut compressor = flate2::Compress::new(Compression::fast(), true);
                let compress_buf = &mut this.compress_buf;
                let compress_buf = match compress_buf.as_mut() {
                    Some(buf) => buf,
                    None => {
                        compress_buf.replace(Vec::with_capacity(512));
                        compress_buf.as_mut().unwrap()
                    }
                };
                match compressor.compress(&raw_buf[..data_len.into()], compress_buf.as_mut_slice(), FlushCompress::Finish)? {
                    Status::BufError => return Err(anyhow!("failed to compress packet bytes, got buf error")),
                    Status::StreamEnd => return Err(anyhow!("failed to compress packet bytes, got stream end error")),
                    Status::Ok => {}
                }

                let n_out = compressor.total_out() as usize;

                // prefix with data length
                const DATA_LEN_EXTRA: usize = 5;
                get_sized_buf(compress_buf, n_out + (2 * DATA_LEN_EXTRA)); // ignored - just for size
                let compress_buf_len = compress_buf.len();
                let mut serializer = SliceSerializer {
                    slice: &mut compress_buf[compress_buf_len - DATA_LEN_EXTRA..],
                    at: 0,
                };
                serializer.serialize_other(&data_len)?;
                let data_len_size = serializer.at;
                // move data length to front of compressed data
                unsafe {
                    let compressed_start_at = compress_buf.as_mut_ptr();
                    let data_len_start_at = compressed_start_at.offset((compress_buf_len - DATA_LEN_EXTRA) as isize);
                    let new_compressed_start_at = compressed_start_at.offset(data_len_size as isize);
                    std::ptr::copy(compressed_start_at, new_compressed_start_at, n_out);
                    std::ptr::copy(data_len_start_at, compressed_start_at, data_len_size);
                }

                (compress_buf, n_out + data_len_size)
            } else {
                // serialize a 0 VarInt and put it (and the ID) at the front of the buf
                // 0 var int is always 0

                // first move id to front of the slice, then add a 0 in front of it
                unsafe {
                    let body_start_at = raw_buf.as_mut_ptr();
                    let id_start_at = body_start_at.offset((len + PREFIX_EXTRA) as isize);
                    let new_id_start_at = body_start_at.offset(1);
                    let new_body_start_at = new_id_start_at.offset(id_len as isize);
                    std::ptr::copy(body_start_at, new_body_start_at, len);
                    std::ptr::copy(id_start_at, new_id_start_at, id_len);
                }
                raw_buf[0] = 0x00;
                (raw_buf, len + id_len + 1)
            }
        } else {
            // move id to front
            unsafe {
                let body_start_at = raw_buf.as_mut_ptr();
                let id_start_at = body_start_at.offset((len + PREFIX_EXTRA) as isize);
                let new_body_start_at = body_start_at.offset(id_len as isize);
                std::ptr::copy(body_start_at, new_body_start_at, len);
                std::ptr::copy(id_start_at, body_start_at, id_len);
            }

            (raw_buf, len + id_len)
        };

        const LEN_PREFIX_EXTRA: usize = 5;
        let packet_buf_out = get_sized_buf(packet_buf, packet_len + (LEN_PREFIX_EXTRA * 2));
        let packet_buf_out_len = packet_buf_out.len();
        let packet_len_buf = &mut packet_buf_out[packet_buf_out_len - LEN_PREFIX_EXTRA..];
        let mut serializer = SliceSerializer {
            at: 0,
            slice: packet_len_buf,
        };
        serializer.serialize_other(&VarInt(packet_len as i32))?;
        let packet_len_len = serializer.at;
        unsafe {
            let packet_start_at = packet_buf_out.as_mut_ptr();
            let new_packet_start_at = packet_start_at.offset(packet_len_len as isize);
            let len_start_at = packet_start_at.offset((packet_buf_out_len - LEN_PREFIX_EXTRA) as isize);
            std::ptr::copy(packet_start_at, new_packet_start_at, packet_len);
            std::ptr::copy(len_start_at, packet_start_at, packet_len_len);
        }

        let packet_bytes = &packet_buf_out[..packet_len_len + packet_len];

        this.writer.as_mut().expect("always there").write_all(packet_bytes).await?;
        Ok(())
    }
}

struct SliceSerializer<'a> {
    slice: &'a mut [u8],
    at: usize,
}

impl<'a> Serializer for SliceSerializer<'a> {
    fn serialize_bytes(&mut self, data: &[u8]) -> SerializeResult {
        let start_at = self.at;
        let end_at = start_at + data.len();
        if end_at > self.slice.len() {
            panic!("failed to serialize, out of space!")
        }

        self.slice[start_at..end_at].copy_from_slice(data);
        self.at = end_at;
        Ok(())
    }

    fn serialize_byte(&mut self, byte: u8) -> SerializeResult {
        self.serialize_bytes(&[byte])
    }
}

struct GrowVecSerializer<'a> {
    buf: &'a mut Vec<u8>,
    at: usize,
}

impl<'a> Serializer for GrowVecSerializer<'a> {
    fn serialize_bytes(&mut self, data: &[u8]) -> SerializeResult {
        let cur_len = self.buf.len() - self.at;
        let additional_len = data.len();
        let expected_len = cur_len + additional_len;
        let buf = get_sized_buf(self.buf, expected_len);
        let buf = &mut buf[self.at..];

        buf[..additional_len].copy_from_slice(data);
        self.at += additional_len;
        Ok(())
    }

    fn serialize_byte(&mut self, byte: u8) -> SerializeResult {
        self.serialize_bytes(&[byte])
    }

    fn serialize_other<S: Serialize>(&mut self, other: &S) -> SerializeResult {
        other.mc_serialize(self)
    }
}

#[derive(Debug, Clone)]
struct BridgeState {
    compression_threshold: Option<usize>,
    state: State,
    read_direction: PacketDirection,
    remote: SocketAddr,
}

pub trait RawPacket: Send {
    fn id(&self) -> &Id;

    fn deserialize(&mut self) -> Result<Packet578>;
}

#[derive(Debug)]
struct CompressedRawPacket<'a> {
    id: Id,
    decompressor: Decompress,
    source: &'a [u8],
    decompress_to: &'a mut [u8],
    already_decompressed: usize,
    source_offset: usize,
}

#[derive(Debug)]
struct RegularRawPacket<'a> {
    id: Id,
    data: &'a [u8],
}

impl<'a> RawPacket for RegularRawPacket<'a> {
    fn id(&self) -> &Id {
        &self.id
    }

    fn deserialize(&mut self) -> Result<Packet578> {
        Ok(Packet578::mc_deserialize(mcproto_rs::protocol::RawPacket {
            id: self.id,
            data: self.data,
        })?)
    }
}

impl<'a> RawPacket for CompressedRawPacket<'a> {
    fn id(&self) -> &Id {
        &self.id
    }

    fn deserialize(&mut self) -> Result<Packet578> {
        match self.decompressor.decompress(&self.source[self.source_offset..], &mut self.decompress_to[self.already_decompressed..], FlushDecompress::Finish)? {
            Status::BufError => return Err(anyhow!("buf error while decompressing packet")),
            Status::StreamEnd => return Err(anyhow!("stream end error while decompressing packet")),
            Status::Ok => {}
        }

        let size_read = self.decompressor.total_out() as usize;

        Ok(Packet578::mc_deserialize(mcproto_rs::protocol::RawPacket {
            id: self.id,
            data: &self.decompress_to[..size_read],
        })?)
    }
}