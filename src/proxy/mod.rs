mod bridge;
mod config;
mod initial_handler;
pub mod logger;
mod proxy;
mod session;
mod util;
mod cfb8;

pub use config::*;
pub use proxy::Proxy;

mod data_stream {
    use tokio::io::{AsyncRead, AsyncWrite};

    pub trait ReadStream: AsyncRead + Unpin + Send + Sync + 'static {}

    impl<T> ReadStream for T where T: AsyncRead + Unpin + Send + Sync + 'static {}

    pub trait WriteStream: AsyncWrite + Unpin + Send + Sync + 'static {}

    impl<T> WriteStream for T where T: AsyncWrite + Unpin + Send + Sync + 'static {}
}

pub use data_stream::{ReadStream, WriteStream};

#[derive(Debug, Clone)]
pub struct UnexpectedPacketErr<T: std::fmt::Debug + Send + Sync + 'static> {
    packet: T,
}

impl<T> std::fmt::Display for UnexpectedPacketErr<T>
where
    T: std::fmt::Debug + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("unexpected packet {:?}", self.packet))
    }
}

impl<T> std::error::Error for UnexpectedPacketErr<T> where T: std::fmt::Debug + Send + Sync + 'static
{}
