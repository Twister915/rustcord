use mcproto_rs::v1_15_2::{State, PacketDirection, Id, Packet578};
use std::net::SocketAddr;
use anyhow::Result;
use mcproto_rs::protocol::Packet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use mcproto_rs::types::VarInt;
use mcproto_rs::{Deserialize, Deserialized, Serializer, SerializeResult, Serialize};
use flate2::{FlushDecompress, Status, Compression, FlushCompress};
use anyhow::anyhow;
use tokio::net::TcpStream;
use tokio::io::BufReader;
use super::{ReadStream, WriteStream};
use std::ops::Range;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use crate::proxy::cfb8::MinecraftCipher;

pub type TcpBridge = Bridge<BufReader<OwnedReadHalf>, OwnedWriteHalf>;

pub type TcpReadBridge = ReadBridge<BufReader<OwnedReadHalf>>;

pub type TcpWriteBridge = WriteBridge<OwnedWriteHalf>;

pub struct Bridge<R, W> {
    reader: ReadBridge<R>,
    writer: WriteBridge<W>,
}

impl Bridge<BufReader<OwnedReadHalf>, OwnedWriteHalf> {
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
            state: state.clone(),
            reader: buf_read_tcp,
            encryption: None,
            decompressor_buf: None,
        };

        let writer = WriteBridge {
            raw_buf: Vec::with_capacity(512),
            state: state.clone(),
            writer: write_tcp,
            encryption: None,
            compress_buf: None,
        };

        Ok(Self {
            reader,
            writer,
        })
    }
}

impl<R, W> Bridge<R, W> where R: ReadStream, W: WriteStream {
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

    pub fn split(self) -> (ReadBridge<R>, WriteBridge<W>) {
        (self.reader, self.writer)
    }

    pub fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        self.reader.enable_encryption(key.clone(), iv.clone())?;
        self.writer.enable_encryption(key, iv)?;
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

pub struct ReadBridge<T> {
    reader: T,
    raw_buf: Vec<u8>,
    decompressor_buf: Option<Vec<u8>>,
    state: BridgeState,
    encryption: Option<MinecraftCipher>
}

impl<R> ReadBridge<R> where R: ReadStream {
    pub async fn read_packet<'a>(&'a mut self) -> Result<Option<Box<dyn RawPacket + 'a>>> {
        let this = &mut *self;

        let packet_len = match this.read_one_varint().await? {
            Some(v) => v,
            None => return Ok(None)
        };

        let reader = &mut this.reader;
        let state = &this.state;
        let raw_buf = &mut this.raw_buf;

        let mut buf = get_sized_buf(raw_buf, packet_len.into());
        reader.read_exact(buf).await?;
        if let Some(encryption) = this.encryption.as_mut() {
            encryption.decrypt(buf);
        }

        let buf = if let Some(_) = state.compression_threshold {
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
                        get_sized_buf(decompress_buf.as_mut().unwrap(), needed)
                    }
                };
                loop {
                    match decompress.decompress(buf, decompress_buf, FlushDecompress::Finish)? {
                        Status::BufError => return Err(anyhow!("unable to deserialize because of buf err while reading packet")),
                        Status::StreamEnd => break,
                        Status::Ok => {}
                    }
                }

                &mut decompress_buf[..(decompress.total_out() as usize)]
            } else {
                buf
            }
        } else {
            buf
        };

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

    //noinspection ALL
    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        self.encryption = Some(MinecraftCipher::new(key, iv)?);
        Ok(())
    }

    async fn read_one_varint(&mut self) -> Result<Option<VarInt>> {
        let mut buf = [0u8; 5];
        let mut len = 0usize;
        let mut has_more = true;
        while has_more {
            if len == 5 {
                return Err(anyhow!("varint too long while reading id/length/whatever"));
            }

            let target = &mut buf[len..len + 1];
            let size = self.reader.read(target).await?;
            if size == 0 {
                return Ok(None);
            }

            if let Some(encryption) = self.encryption.as_mut() {
                encryption.decrypt(target);
            }

            has_more = buf[len] & 0x80 != 0;
            len += 1;
        }

        Ok(Some(VarInt::mc_deserialize(&buf[..len])?.value))
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

pub struct WriteBridge<T> {
    writer: T,
    state: BridgeState,
    raw_buf: Vec<u8>,
    compress_buf: Option<Vec<u8>>,
    encryption: Option<MinecraftCipher>,
}

impl<W> WriteBridge<W> where W: WriteStream {
    pub async fn write_packet(&mut self, packet: Packet578) -> Result<()> {
        let this = &mut *self;
        let raw_buf = &mut this.raw_buf;
        const EXTRA_FREE_SPACE: usize = 15;

        get_sized_buf(raw_buf, EXTRA_FREE_SPACE);

        let mut serializer = GrowVecSerializer{
            buf: raw_buf,
            at: EXTRA_FREE_SPACE
        };

        packet.mc_serialize(&mut serializer)?;

        let body_len = serializer.at - EXTRA_FREE_SPACE;
        // now write packet id
        let mut id_serializer = SliceSerializer{
            slice: &mut raw_buf[EXTRA_FREE_SPACE-5..EXTRA_FREE_SPACE],
            at: 0,
        };
        let id = packet.id();
        id.mc_serialize(&mut id_serializer)?;
        // move the ID to right in front of the packet body
        // body starts at EXTRA_FREE_SPACE
        let id_len = id_serializer.at;
        let id_start_at = EXTRA_FREE_SPACE - 5;
        let id_end_at = id_start_at + id_len;
        let id_shift_n = 5 - id_len;
        copy_data_rightwards(raw_buf.as_mut_slice(), id_start_at..id_end_at, id_shift_n);

        let data_len = id_len + body_len;
        let data_start_at = EXTRA_FREE_SPACE - id_len;
        let (packet_buf, start_at, end_at) = if let Some(threshold) = this.state.compression_threshold.as_ref() {
            if data_len < *threshold {
                let data_len_at = data_start_at - 1;
                let packet_end_at = data_start_at + data_len;
                raw_buf[data_len_at] = 0;
                (raw_buf, data_len_at, packet_end_at)
            } else {
                let src = &raw_buf[data_start_at..data_start_at + data_len];

                let mut compressor = flate2::Compress::new_with_window_bits(Compression::fast(), true, 15);
                let compress_buf = &mut this.compress_buf;
                let compress_buf = match compress_buf.as_mut() {
                    Some(buf) => buf,
                    None => {
                        compress_buf.replace(Vec::with_capacity(src.len()));
                        compress_buf.as_mut().unwrap()
                    }
                };

                get_sized_buf(compress_buf, src.len());

                loop {
                    let input = &src[(compressor.total_in() as usize)..];
                    let eof = input.is_empty();
                    let output = &mut compress_buf[EXTRA_FREE_SPACE+(compressor.total_out() as usize)..];
                    let flush = if eof {
                        FlushCompress::Finish
                    } else {
                        FlushCompress::None
                    };
                    match compressor.compress(input, output, flush)? {
                        Status::Ok => {}
                        Status::BufError => {
                            // ensure size
                            get_sized_buf(compress_buf, compressor.total_out() as usize);
                        },
                        Status::StreamEnd => break
                    }
                }

                // write data_len to raw_buf
                let data_len_start_at = EXTRA_FREE_SPACE - 5;
                let data_len_target = &mut compress_buf[data_len_start_at..EXTRA_FREE_SPACE];
                let mut data_len_serializer = SliceSerializer{
                    slice: data_len_target,
                    at: 0
                };
                &VarInt(data_len as i32).mc_serialize(&mut data_len_serializer)?;
                let data_len_len = data_len_serializer.at;
                let data_len_end_at = data_len_start_at + data_len_len;
                let data_len_shift_n = 5 - data_len_len;
                copy_data_rightwards(compress_buf.as_mut_slice(), data_len_start_at..data_len_end_at, data_len_shift_n);
                let compressed_end_at = EXTRA_FREE_SPACE + (compressor.total_out() as usize);
                (compress_buf, data_len_start_at + data_len_shift_n, compressed_end_at)
            }
        } else {
            (raw_buf, data_start_at, data_start_at + data_len)
        };

        // now just prefix the actual length
        if start_at < 5 {
            panic!("need space to write length, not enough!");
        }

        let len = VarInt((end_at - start_at) as i32);
        let len_start_at = start_at - 5;
        let mut len_serializer = SliceSerializer{
            slice: &mut packet_buf[len_start_at..start_at],
            at: 0
        };
        len.mc_serialize(&mut len_serializer)?;
        let len_len = len_serializer.at;
        let len_end_at = len_start_at+len_len;
        let len_shift_n = 5 - len_len;

        copy_data_rightwards(packet_buf.as_mut_slice(), len_start_at..len_end_at, len_shift_n);
        let new_len_start_at = len_start_at + len_shift_n;
        let packet_data = &mut packet_buf[new_len_start_at..end_at];
        if let Some(enc) = this.encryption.as_mut() {
            enc.encrypt(packet_data);
        }

        this.writer.write_all(packet_data).await?;
        Ok(())
    }

    //noinspection ALL
    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        self.encryption = Some(MinecraftCipher::new(key, iv)?);
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
        let start_at = self.at;
        let additional_data_len = data.len();
        let end_at = start_at + additional_data_len;
        let buf = get_sized_buf(self.buf, end_at);
        let buf = &mut buf[start_at..end_at];

        buf.copy_from_slice(data);
        self.at += additional_data_len;
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

fn copy_data_rightwards(target: &mut [u8], range: Range<usize>, shift_amount: usize) {
    if shift_amount == 0 {
        return
    }

    // check bounds
    let buf_len = target.len();
    let src_start_at = range.start;
    let src_end_at = range.end;
    let data_len = src_end_at - src_start_at;
    if src_start_at >= buf_len || src_end_at > buf_len {
        panic!("source out of bounds!");
    }

    let dest_start_at = src_start_at + shift_amount;
    let dest_end_at = dest_start_at + data_len;
    if dest_start_at >= buf_len || dest_end_at > buf_len {
        panic!("dest out of bounds")
    }

    unsafe {
        let src_ptr = target.as_mut_ptr();
        let data_src_ptr = src_ptr.offset(src_start_at as isize);
        let data_dst_ptr = data_src_ptr.offset(shift_amount as isize);
        std::ptr::copy(data_src_ptr, data_dst_ptr, data_len);
    }
}