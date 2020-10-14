use std::sync::Arc;
use crate::proxy::util::Streams;
use mcproto_rs::uuid::UUID4;
use std::net::SocketAddr;
use mcproto_rs::v1_15_2 as proto;
use proto::{HandshakeSpec, Packet578 as Packet, RawPacket578 as RawPacket, LoginDisconnectSpec, PlayDisconnectSpec, State, PlayServerChatMessageSpec, ChatPosition};
use mcproto_rs::types::Chat;
use anyhow::{Result, anyhow};
use crate::proxy::proxy::Proxy;
use crate::proxy::downstream::{DownstreamConnection, DownstreamConnectErr, DownstreamInner};
use mctokio::{TcpReadBridge, TcpWriteBridge};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::proxy::auth::UserProperty;
use tokio::sync::{Mutex, MutexGuard};
use tokio::net::ToSocketAddrs;
use mcproto_rs::protocol::Packet as PacketTrait;

pub type UpstreamConnection = Arc<UpstreamInner>;

pub struct UpstreamInner {
    pub proxy: Proxy,
    is_in_players: AtomicBool,
    streams: Streams,

    // basic required info
    pub username: String,
    pub id: UUID4,
    pub remote_addr: SocketAddr,
    pub handshake: HandshakeSpec,
    pub properties: Vec<UserProperty>,

    pub downstream: Mutex<UpstreamBridges>,
}

pub struct UpstreamBridges {
    pub connected_to: Option<DownstreamConnection>,
    pub pending_next: Option<DownstreamConnection>,
}

pub enum ForwardingStatus {
    ClientDisconnected(Option<anyhow::Error>),
    ServerDisconnected(Option<anyhow::Error>),
    KickedByServer(Chat),
    KickedByProxy,
    ClientBadPacket(anyhow::Error),
    ServerBadPacket(anyhow::Error),
    ConnectNext(String),
    OtherErr(anyhow::Error),
}

enum ClientToServerStatus {
    Disconnected,
    WriteErr(anyhow::Error),
    BadPacket(anyhow::Error),
    OtherErr(anyhow::Error),
}

impl Into<ForwardingStatus> for ClientToServerStatus {
    fn into(self) -> ForwardingStatus {
        use ClientToServerStatus::*;
        match self {
            Disconnected => ForwardingStatus::ClientDisconnected(None),
            BadPacket(err) => ForwardingStatus::ClientBadPacket(err),
            WriteErr(err) => ForwardingStatus::ServerDisconnected(Some(err)),
            OtherErr(err) => ForwardingStatus::OtherErr(err),
        }
    }
}

enum ServerToClientStatus {
    Disconnected,
    Kicked(Chat),
    ConnectNext(String),
    BadPacket(anyhow::Error),
    WriteErr(anyhow::Error),
    OtherErr(anyhow::Error),
}

impl Into<ForwardingStatus> for ServerToClientStatus {
    fn into(self) -> ForwardingStatus {
        use ServerToClientStatus::*;
        match self {
            ConnectNext(next) => ForwardingStatus::ConnectNext(next),
            Disconnected => ForwardingStatus::ServerDisconnected(None),
            Kicked(msg) => ForwardingStatus::KickedByServer(msg),
            BadPacket(err) => ForwardingStatus::ServerBadPacket(err),
            WriteErr(err) => ForwardingStatus::ClientDisconnected(Some(err)),
            OtherErr(err) => ForwardingStatus::OtherErr(err)
        }
    }
}

impl UpstreamInner {
    pub(crate) fn create(
        streams: Streams,
        proxy: Proxy,
        username: String,
        id: UUID4,
        remote_addr: SocketAddr,
        properties: Vec<UserProperty>,
        handshake: HandshakeSpec,
    ) -> Self
    {
        Self {
            streams,
            proxy,
            username,
            id,
            remote_addr,
            properties,
            handshake,

            is_in_players: AtomicBool::new(false),
            downstream: Mutex::new(UpstreamBridges {
                connected_to: None,
                pending_next: None,
            }),
        }
    }

    pub async fn serve(self: &UpstreamConnection) {
        let mut res = self.connect_default().await;
        loop {
            match &res {
                ForwardingStatus::ClientDisconnected(err) => {
                    // nothing we can do, drop
                    self.take_streams_disconnect().await; // ignore error
                    return;
                }
                ForwardingStatus::ServerDisconnected(err) => {
                    // try to connect to another default?
                    res = self.connect_default().await;
                }
                ForwardingStatus::KickedByServer(msg) => {
                    // todo handle
                    self.kick_or_log(msg.clone()).await;
                    return;
                }
                ForwardingStatus::KickedByProxy => {
                    self.take_streams_disconnect().await; //ignore error
                    return;
                }
                ForwardingStatus::ClientBadPacket(err) => {
                    let msg = format!("&cbad packet: &f{:?}", err);
                    self.kick_or_log(Chat::from_traditional(msg.as_str(), true)).await;
                    return;
                }
                ForwardingStatus::ServerBadPacket(err) => {
                    let msg = format!("&cbad packet from server: &f{:?}", err);
                    self.kick_or_log(Chat::from_traditional(msg.as_str(), true)).await;
                    return;
                }
                ForwardingStatus::ConnectNext(next) => {
                    res = self.connect_named(next).await;
                }
                ForwardingStatus::OtherErr(err) => {
                    let msg = format!("&cerror: &r{:?}", err);
                    self.kick_or_log(Chat::from_traditional(msg.as_str(), true)).await;
                    return;
                }
            }
        }
    }

    async fn connect_named(self: &UpstreamConnection, name: &String) -> ForwardingStatus {
        let downstream_state = self.downstream.lock().await;
        if let Some(next) = self.proxy.config.servers.iter()
            .filter(move |server| server.name.eq(name))
            .nth(0) {
            self.connect_next(downstream_state, &next.name, next.address.clone()).await
        } else {
            let msg = format!("&cserver &f{}&c does not exist!", name);
            self.handle_connect_err(downstream_state, Chat::from_traditional(msg.as_str(), true)).await
        }
    }

    async fn connect_default(self: &UpstreamConnection) -> ForwardingStatus {
        let downstream_state = self.downstream.lock().await;

        let target = {
            let mut connect_to: Vec<_> = self.proxy.config.servers.iter().filter(move |s| s.connect_to).collect();
            if connect_to.is_empty() {
                if let Err(err) = self.kick(Chat::from_traditional("&cNo servers to connect to...", true)).await {
                    self.proxy.logger.warning(format_args!("could not send message to downstream due to {:?}", err));
                }
                return ForwardingStatus::KickedByProxy;
            }

            connect_to.remove(rand::random::<usize>() % connect_to.len())
        };

        self.connect_next(downstream_state, &target.name, target.address.clone()).await
    }

    pub async fn connect_next<A: ToSocketAddrs + std::fmt::Debug + Clone>(self: &UpstreamConnection, mut state: MutexGuard<'_, UpstreamBridges>, name: &String, to: A) -> ForwardingStatus {
        match DownstreamInner::connect(self.clone(), to).await {
            Ok(pending) => {
                state.pending_next.replace(pending);
            }
            Err(err) => {
                return match err {
                    DownstreamConnectErr::Kicked(message) => {
                        ForwardingStatus::KickedByServer(message)
                    }
                    DownstreamConnectErr::OnlineMode => {
                        self.handle_connect_err(state, Chat::from_traditional("&cServer is in Online Mode!", true)).await
                    }
                    DownstreamConnectErr::Other(err) => {
                        let msg = format!("&cfailed to connect to {}: &f{}", name, err.root_cause().to_string());
                        self.handle_connect_err(state, Chat::from_traditional(msg.as_str(), true)).await
                    }
                };
            }
        }

        if state.connected_to.is_some() {
            self.join_next_pending_downstream(state).await
        } else {
            self.join_initial_downstream(state).await
        }
    }

    async fn handle_connect_err(self: &UpstreamConnection, mut state: MutexGuard<'_, UpstreamBridges>, msg: Chat) -> ForwardingStatus {
        state.pending_next.take();

        if let Some(connected_to) = state.connected_to.as_ref() {
            if let Err(err) = self.send_message(msg.clone()).await {
                self.proxy.logger.warning(format_args!("failed to notify client of error {:?} {:?}", msg, err));
                ForwardingStatus::ClientDisconnected(None)
            } else {
                self.forward_forever(connected_to.clone()).await
            }
        } else {
            self.kick_or_log(msg.clone()).await;
            ForwardingStatus::KickedByProxy
        }
    }

    async fn join_next_pending_downstream(self: &UpstreamConnection, state: MutexGuard<'_, UpstreamBridges>) -> ForwardingStatus {
        panic!("unimplemented")
    }

    async fn join_initial_downstream(self: &UpstreamConnection, mut state: MutexGuard<'_, UpstreamBridges>) -> ForwardingStatus {
        let pending = if let Some(next) = state.pending_next.take() {
            next
        } else {
            return ForwardingStatus::OtherErr(anyhow!("no pending downstream..."));
        };
        state.connected_to = Some(pending.clone());
        self.forward_forever(pending).await
    }

    async fn forward_forever(self: &UpstreamConnection, to: DownstreamConnection) -> ForwardingStatus {
        tokio::pin! {
            let client_to_server = self.forward_client_to_server(&to);
            let server_to_client = self.forward_server_to_client(&to);
        }

        tokio::select! {
            result = &mut client_to_server => result.into(),
            result = &mut server_to_client => result.into(),
        }
    }

    async fn forward_client_to_server(self: &UpstreamConnection, to: &DownstreamConnection) -> ClientToServerStatus {
        loop {
            match self.streams.reader().await.as_mut() {
                Ok(bridge) => {
                    let next_read = match bridge.read_packet().await {
                        Err(err) => {
                            return ClientToServerStatus::OtherErr(err);
                        },
                        Ok(Some(next_read)) => next_read,
                        Ok(None) => {
                            return ClientToServerStatus::Disconnected;
                        }
                    };

                    if let Err(err) = to.streams.write_raw_packet(next_read).await {
                        return ClientToServerStatus::WriteErr(err);
                    }
                },
                Err(err) => {
                    return ClientToServerStatus::OtherErr(err);
                }
            }
        }
    }

    async fn forward_server_to_client(self: &UpstreamConnection, from: &DownstreamConnection) -> ServerToClientStatus {
        loop {
            match from.streams.reader().await.as_mut() {
                Ok(bridge) => {
                    let next_read = match bridge.read_packet().await {
                        Err(err) => {
                            return ServerToClientStatus::OtherErr(err);
                        }
                        Ok(Some(next_read)) => next_read,
                        Ok(None) => {
                            return ServerToClientStatus::Disconnected;
                        }
                    };

                    use RawPacket::PlayDisconnect as RawPlayDisconnect;
                    use Packet::PlayDisconnect;

                    match &next_read {
                        RawPlayDisconnect(_) => {
                            return match next_read.deserialize() {
                                Err(err) => {
                                    ServerToClientStatus::BadPacket(err.into())
                                }
                                Ok(PlayDisconnect(body)) => {
                                    ServerToClientStatus::Kicked(body.reason)
                                }
                                Ok(other) => {
                                    ServerToClientStatus::OtherErr(anyhow!("unexpected packet {:?}", other))
                                }
                            };
                        }
                        _ => {
                            if let Err(err) = self.streams.write_raw_packet(next_read).await {
                                return ServerToClientStatus::WriteErr(err);
                            }
                        }
                    }
                }
                Err(err) => {
                    return ServerToClientStatus::OtherErr(err);
                }
            }
        }
    }

    pub(crate) fn mark_connected(self: &UpstreamConnection) {
        self.is_in_players.store(true, Ordering::SeqCst);
    }

    pub async fn send_message(self: &UpstreamConnection, message: Chat) -> Result<()> {
        self.streams.write_packet(Packet::PlayServerChatMessage(PlayServerChatMessageSpec {
            message,
            position: ChatPosition::ChatBox,
        })).await
    }

    pub async fn kick_or_log(&self, msg: Chat) {
        if let Err(err) = self.kick(msg.clone()).await {
            self.proxy.logger.warning(format_args!("failed to write kick message to client: {} - {}", msg.to_traditional().unwrap_or_else(|| format!("{:?}", msg)), err))
        }
    }

    pub async fn kick(&self, msg: Chat) -> Result<()> {
        self.proxy.logger.info(format_args!("kick {}/{} for {}", self.username, self.id, msg.to_traditional().unwrap_or_else(|| format!("{:?}", msg))));
        let packet = if self.streams.state().await == State::Login {
            Packet::LoginDisconnect(LoginDisconnectSpec {
                message: msg,
            })
        } else {
            Packet::PlayDisconnect(PlayDisconnectSpec {
                reason: msg,
            })
        };

        let (_, mut writer) = self.take_streams_disconnect().await?;
        writer.write_packet(packet).await
    }

    async fn take_streams_disconnect(&self) -> Result<(TcpReadBridge, TcpWriteBridge)> {
        if let Some((reader, writer)) = self.streams.take().await? {
            if self.is_in_players.compare_and_swap(true, false, Ordering::SeqCst) {
                self.proxy.has_disconnected(&self.id).await;
            }
            Ok((reader, writer))
        } else {
            Err(anyhow!("user is already disconnected, can't take streams"))
        }
    }
}