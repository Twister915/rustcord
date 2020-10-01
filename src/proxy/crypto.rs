use super::{ReadStream, WriteStream};
use aes::Aes128;
use cfb8::Cfb8;
use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncWrite, Error};
use futures::task::{Context, Poll};
use std::pin::Pin;
use cfb8::stream_cipher::{StreamCipher, NewStreamCipher, InvalidKeyNonceLength};
use pin_project::{pin_project};

#[pin_project]
pub struct EncryptWriter<C: WriteStream> {
    writer: Cfb8<Aes128>,
    #[pin]
    stream: C
}

impl<C: WriteStream> EncryptWriter<C> {
    pub fn wrap(stream: C, key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self{
            writer: Cfb8::new_var(key.clone(), iv.clone()).map_err(map_cfb8_init_err)?,
            stream
        })
    }
}

impl<C: WriteStream> AsyncWrite for EncryptWriter<C> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let this = self.project();

        let mut encrypted = buf.to_vec();
        this.writer.encrypt(encrypted.as_mut_slice());
        this.stream.poll_write(cx, encrypted.as_slice())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().stream.poll_shutdown(cx)
    }
}

#[pin_project]
pub struct DecryptReader<C: ReadStream> {
    reader: Cfb8<Aes128>,
    #[pin]
    stream: C
}

impl<C: ReadStream> DecryptReader<C> {
    pub fn wrap(stream: C, key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(Self {
            reader: Cfb8::new_var(key.clone(), iv.clone()).map_err(map_cfb8_init_err)?,
            stream
        })
    }
}

impl<C: ReadStream> AsyncRead for DecryptReader<C> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, std::io::Error>> {
        let this = self.project();
        match futures::ready!(this.stream.poll_read(cx, buf)) {
            Ok(size) => {
                this.reader.decrypt(&mut buf[..size]);
                Poll::Ready(Ok(size))
            },
            Err(err) => {
                Poll::Ready(Err(err))
            }
        }
    }
}

fn map_cfb8_init_err(err: InvalidKeyNonceLength) -> anyhow::Error {
    anyhow!("invalid key nonce length: {:?}", err)
}
