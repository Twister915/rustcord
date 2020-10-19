use tokio::sync::{Mutex, MutexGuard};
use mctokio::{TcpReadBridge, TcpWriteBridge, Bridge};
use mcproto_rs::v1_15_2::{State, Packet578 as Packet, RawPacket578 as RawPacket};
use anyhow::{Result, anyhow};
use super::proxy::Proxy;
use std::sync::Arc;
use mcproto_rs::uuid::UUID4;

pub type Streams = Arc<StreamsInner>;

pub struct StreamsInner {
    proxy: Proxy,
    name: String,
    reader: Mutex<Option<TcpReadBridge>>,
    writer: Mutex<Option<TcpWriteBridge>>,
    state: Mutex<State>,
}

impl StreamsInner {
    pub fn create(proxy: Proxy, name: String, read: TcpReadBridge, write: TcpWriteBridge, state: State) -> Streams {
        Arc::new(Self {
            proxy,
            name,
            reader: Mutex::new(Some(read)),
            writer: Mutex::new(Some(write)),
            state: Mutex::new(state),
        })
    }

    pub async fn take(&self) -> Result<Option<(TcpReadBridge, TcpWriteBridge)>> {
        let reader = &self.reader;
        let writer = &self.writer;

        let (mut reader, mut writer) = tokio::join!(
            async move { reader.lock().await },
            async move { writer.lock().await }
        );

        if reader.is_some() && writer.is_some() {
            let reader = reader.take().expect("it's there");
            let writer = writer.take().expect("it's there");
            self.proxy.logger.debug(format_args!("will drop {}, take() called", self.name));
            Ok(Some((reader, writer)))
        } else {
            Ok(None)
        }
    }

    pub async fn writer(&self) -> OwnedOptionalGuard<'_, TcpWriteBridge> {
        OwnedOptionalGuard {
            guard: self.writer.lock().await,
        }
    }

    pub async fn reader(&self) -> OwnedOptionalGuard<'_, TcpReadBridge> {
        OwnedOptionalGuard {
            guard: self.reader.lock().await,
        }
    }

    pub async fn set_state(&self, state: State) -> Result<()> {
        let mut known_state = self.state.lock().await;
        if *known_state == state {
            return Ok(());
        }

        let reader = self.reader();
        let writer = self.writer();

        let res: Result<((), ()), anyhow::Error> = tokio::try_join!(
            async move { Ok(reader.await.as_mut()?.set_state(state.clone())) },
            async move { Ok(writer.await.as_mut()?.set_state(state.clone())) }
        );
        res?;
        *known_state = state;
        Ok(())
    }

    pub async fn enable_encryption(&self, key: &[u8], iv: &[u8]) -> Result<()> {
        tokio::try_join!(
            async move { self.reader().await.as_mut()?.enable_encryption(key.clone(), iv.clone()) },
            async move { self.writer().await.as_mut()?.enable_encryption(key, iv) }
        )?;
        Ok(())
    }

    pub async fn set_compression_threshold(&self, threshold: Option<i32>) -> Result<()> {
        let res: Result<((), ()), anyhow::Error> = tokio::try_join!(
            async move { Ok(self.reader().await.as_mut()?.set_compression_threshold(threshold)) },
            async move { Ok(self.writer().await.as_mut()?.set_compression_threshold(threshold)) }
        );
        res?;
        Ok(())
    }

    pub async fn must_read_next_packet(&self) -> Result<Packet> {
        if let Some(packet) = self.read_next_packet().await? {
            Ok(packet)
        } else {
            Err(anyhow!("expected packet, got EOF"))
        }
    }

    pub async fn read_next_packet(&self) -> Result<Option<Packet>> {
        let mut locked_reader = self.reader().await;
        let reader = locked_reader.as_mut()?;
        if let Some(raw) = reader.read_packet().await? {
            Ok(Some(raw.deserialize()?))
        } else {
            Ok(None)
        }
    }

    pub async fn write_packet(&self, packet: Packet) -> Result<()> {
        self.writer().await.as_mut()?.write_packet(packet).await
    }

    pub async fn write_raw_packet(&self, packet: RawPacket<'_>) -> Result<()> {
        self.writer().await.as_mut()?.write_raw_packet(packet).await
    }

    pub async fn state(&self) -> State {
        self.state.lock().await.clone()
    }
}

impl Drop for StreamsInner {
    fn drop(&mut self) {
        let (r, w) = futures::executor::block_on(futures::future::join(
            self.reader(),
            self.writer()));
        if r.guard.is_some() && w.guard.is_some() {
            self.proxy.logger.debug(format_args!("will drop {}, drop of Streams", self.name));
        }
    }
}

pub struct OwnedOptionalGuard<'a, T> {
    guard: MutexGuard<'a, Option<T>>
}

impl<'a, T> OwnedOptionalGuard<'a, T> {
    pub fn as_mut(&mut self) -> Result<&mut T> {
        if let Some(out) = self.guard.as_mut() {
            Ok(out)
        } else {
            Err(anyhow!("player disconnected..."))
        }
    }

    pub fn as_ref(&self) -> Result<&T> {
        if let Some(out) = self.guard.as_ref() {
            Ok(out)
        } else {
            Err(anyhow!("player disconnected..."))
        }
    }
}

pub fn offline_id_for(name: &str) -> UUID4 {
    let key = format!("OfflinePlayer:{}", name);
    let mut hash = md5::compute(key.as_bytes()).0;
    hash[6] = hash[6] & 0x0f | 0x30;
    hash[8] = hash[8] & 0x3f | 0x80;
    let id_raw = u128::from_le_bytes(hash);
    id_raw.into()
}