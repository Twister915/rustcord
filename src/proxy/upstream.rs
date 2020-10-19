use std::sync::Arc;
use crate::proxy::util::Streams;
use mcproto_rs::uuid::UUID4;
use std::net::SocketAddr;
use mcproto_rs::v1_15_2 as proto;
use proto::{HandshakeSpec, Packet578 as Packet, RawPacket578 as RawPacket, LoginDisconnectSpec, PlayDisconnectSpec, State, PlayServerChatMessageSpec, ChatPosition};
use mcproto_rs::types::{Chat, VarInt};
use anyhow::{Result, anyhow};
use crate::proxy::proxy::Proxy;
use crate::proxy::downstream::{DownstreamConnection, DownstreamConnectErr, DownstreamInner};
use mctokio::{TcpReadBridge, TcpWriteBridge};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::proxy::auth::UserProperty;
use tokio::sync::{Mutex, MutexGuard};
use std::collections::HashSet;
use std::pin::Pin;

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
    pub plugin_channels: Mutex<HashSet<String>>,
    pub dimension: Mutex<Option<proto::Dimension>>,
}

pub struct UpstreamBridges {
    pub connected_to: Option<DownstreamConnection>,
    pub pending_next: Option<DownstreamConnection>,
    pub tablist_members: HashSet<UUID4>,
    pub client_entity_id: Option<i32>
}

#[derive(Debug)]
pub enum ForwardingStatus {
    ClientDisconnected(Option<anyhow::Error>),
    ServerDisconnected(Option<anyhow::Error>, String),
    KickedByServer(Chat),
    KickedByProxy,
    ClientBadPacket(anyhow::Error),
    ServerBadPacket(anyhow::Error),
    ConnectNext(String),
    OtherErr(anyhow::Error),
}

#[derive(Debug)]
enum ClientToServerStatus {
    Disconnected,
    WriteErr(anyhow::Error, String),
    BadPacket(anyhow::Error),
    OtherErr(anyhow::Error),
}

impl Into<ForwardingStatus> for ClientToServerStatus {
    fn into(self) -> ForwardingStatus {
        use ClientToServerStatus::*;
        match self {
            Disconnected => ForwardingStatus::ClientDisconnected(None),
            BadPacket(err) => ForwardingStatus::ClientBadPacket(err),
            WriteErr(err, name) => ForwardingStatus::ServerDisconnected(Some(err), name),
            OtherErr(err) => ForwardingStatus::OtherErr(err),
        }
    }
}

#[derive(Debug)]
enum ServerToClientStatus {
    Disconnected(String),
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
            Disconnected(name) => ForwardingStatus::ServerDisconnected(None, name),
            Kicked(msg) => ForwardingStatus::KickedByServer(msg),
            BadPacket(err) => ForwardingStatus::ServerBadPacket(err),
            WriteErr(err) => ForwardingStatus::ClientDisconnected(Some(err)),
            OtherErr(err) => ForwardingStatus::OtherErr(err)
        }
    }
}

macro_rules! deserialize_raw {
    ($packet: expr, $e: ty) => {
        match $packet.deserialize() {
            Ok(body) => body,
            Err(err) => {
                return Some(<$e>::BadPacket(err.into()));
            }
        }
    }
}

macro_rules! remap_entity_id_field {
    ($bod: ident, $typ: ident, $field: ident, $remap: ident) => {
        let mut packet = $bod.deserialize()?;
        $remap(&mut packet.$field);
        return Ok(Some(Packet::$typ(packet)));
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
                client_entity_id: None,
                tablist_members: HashSet::default(),
            }),
            plugin_channels: {
                let mut out = HashSet::default();
                out.insert("rustcord:send".to_owned());
                Mutex::new(out)
            },
            dimension: Mutex::new(None),
        }
    }

    pub async fn serve(self: &UpstreamConnection) {
        let mut res = self.connect_default().await;
        loop {
            match res {
                ForwardingStatus::ClientDisconnected(err) => {
                    // nothing we can do, drop
                    self.proxy.logger.info(format_args!("{} left the proxy", self.username));
                    self.take_streams_disconnect().await; // ignore error
                    return;
                }
                ForwardingStatus::ServerDisconnected(err, name) => {
                    // try to connect to another default?
                    self.proxy.logger.info(format_args!("{} was disconnected from downstream {}", self.username, name));
                    res = self.connect_default().await;
                }
                ForwardingStatus::KickedByServer(msg) => {
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
                    self.proxy.logger.info(format_args!("{} wants to connect to {}", self.username, next));
                    res = self.connect_named(&next).await;
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
            self.proxy.logger.info(format_args!("failed to connect {} to {} because {} does not exist", self.username, name, name));
            let msg = format!("&cserver &f{}&c does not exist!", name);
            self.handle_connect_err(downstream_state, name, Chat::from_traditional(msg.as_str(), true)).await
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

    pub async fn connect_next(self: &UpstreamConnection, mut state: MutexGuard<'_, UpstreamBridges>, name: &String, to: String) -> ForwardingStatus {
        if let Some(current) = &state.connected_to {
            if current.target_addr == to {
                let msg = format!("&calready connected to &f{}", name);
                return self.handle_connect_err(state, name, Chat::from_traditional(msg.as_str(), true)).await;
            }
        }

        self.proxy.logger.info(format_args!("connecting {} to downstream {}", self.username, name));
        match DownstreamInner::connect(self.clone(), to).await {
            Ok(pending) => {
                state.pending_next.replace(pending);
            }
            Err(err) => {
                self.proxy.logger.warning(format_args!("failed to connect {} to {} because of {:?}", self.username, name, err));
                return match err {
                    DownstreamConnectErr::Kicked(message) => {
                        ForwardingStatus::KickedByServer(message)
                    }
                    DownstreamConnectErr::OnlineMode => {
                        self.handle_connect_err(state, name, Chat::from_traditional("&cServer is in Online Mode!", true)).await
                    }
                    DownstreamConnectErr::Other(err) => {
                        let msg = format!("&cfailed to connect to {}: &f{}", name, err.root_cause().to_string());
                        self.handle_connect_err(state, name, Chat::from_traditional(msg.as_str(), true)).await
                    }
                };
            }
        }

        if state.connected_to.is_some() {
            self.join_next_pending_downstream(name, state).await
        } else {
            self.join_initial_downstream(name, state).await
        }
    }

    async fn handle_connect_err(self: &UpstreamConnection, mut state: MutexGuard<'_, UpstreamBridges>, name: &String, msg: Chat) -> ForwardingStatus {
        state.pending_next.take();

        if let Some(connected_to) = state.connected_to.as_ref() {
            if let Err(err) = self.send_message(msg.clone()).await {
                self.proxy.logger.warning(format_args!("failed to notify client of error {:?} {:?}", msg, err));
                ForwardingStatus::ClientDisconnected(None)
            } else {
                self.forward_forever(name, connected_to.clone()).await
            }
        } else {
            self.kick_or_log(msg.clone()).await;
            ForwardingStatus::KickedByProxy
        }
    }

    async fn join_next_pending_downstream(self: &UpstreamConnection, name: &String, mut state: MutexGuard<'_, UpstreamBridges>) -> ForwardingStatus {
        let next = state.pending_next.take().expect("has pending_next");
        let prev = state.connected_to.take().expect("has current connection");

        use Packet::*;
        use proto::{PlayRespawnSpec, PlayUpdateViewDistanceSpec};
        use proto::Dimension;
        let mut dimension_mutex = self.dimension.lock().await;
        let cur_dimension = dimension_mutex.as_ref().cloned().expect("has current dimension");
        if next.join_game.dimension == cur_dimension {
            let fake_dimension = match cur_dimension {
                Dimension::Nether => Dimension::Overworld,
                Dimension::Overworld => Dimension::Nether,
                Dimension::End => Dimension::Nether,
            };

            if let Err(err) = self.streams.write_packet(PlayRespawn(PlayRespawnSpec{
                dimension: fake_dimension,
                hashed_seed: next.join_game.hashed_seed.clone(),
                gamemode: next.join_game.gamemode.clone(),
                level_type: next.join_game.level_type.clone(),
            })).await {
                return ForwardingStatus::ServerDisconnected(Some(err), name.clone());
            }
        }

        if let Err(err) = self.streams.write_packet(PlayRespawn(PlayRespawnSpec{
            dimension: next.join_game.dimension.clone(),
            hashed_seed: next.join_game.hashed_seed.clone(),
            gamemode: next.join_game.gamemode.clone(),
            level_type: next.join_game.level_type.clone(),
        })).await {
            return ForwardingStatus::ServerDisconnected(Some(err), name.clone());
        }

        *dimension_mutex = Some(next.join_game.dimension.clone());

        if let Err(err) = self.streams.write_packet(PlayUpdateViewDistance(PlayUpdateViewDistanceSpec{
            view_distance: next.join_game.view_distance,
        })).await {
            return ForwardingStatus::ServerDisconnected(Some(err), name.clone());
        }

        prev.streams.take().await;

        state.connected_to = Some(next.clone());
        std::mem::drop(state);


        self.forward_forever(name, next).await
    }

    async fn join_initial_downstream(self: &UpstreamConnection, name: &String, mut state: MutexGuard<'_, UpstreamBridges>) -> ForwardingStatus {
        let pending = if let Some(next) = state.pending_next.take() {
            next
        } else {
            return ForwardingStatus::OtherErr(anyhow!("no pending downstream..."));
        };
        state.connected_to = Some(pending.clone());
        state.client_entity_id = Some(pending.join_game.entity_id);
        std::mem::drop(state);

        if let Err(err) = self.streams.write_packet(Packet::PlayJoinGame(pending.join_game.clone())).await {
            return ForwardingStatus::ClientDisconnected(Some(err));
        }

        *self.dimension.lock().await = Some(pending.join_game.dimension.clone());

        self.forward_forever(name, pending).await
    }

    async fn forward_forever(self: &UpstreamConnection, name: &String, to: DownstreamConnection) -> ForwardingStatus {
        let mut client_to_server = self.forward_client_to_server_once(name, &to);
        let mut server_to_client = self.forward_server_to_client_once(name, &to);

        loop {
            let mut c2s = unsafe { Pin::new_unchecked(&mut client_to_server) };
            let mut s2c = unsafe { Pin::new_unchecked(&mut server_to_client) };
            tokio::select! {
                result = &mut c2s => {
                    if let Some(result) = result {
                        s2c.await; // drop this
                        return result.into();
                    } else {
                        client_to_server = self.forward_client_to_server_once(name, &to);
                    }
                }
                result = &mut s2c => {
                    if let Some(result) = result {
                        c2s.await;
                        return result.into();
                    } else {
                        server_to_client = self.forward_server_to_client_once(name, &to);
                    }
                }
            }
        }
    }

    async fn forward_client_to_server_once(self: &UpstreamConnection, name: &String, to: &DownstreamConnection) -> Option<ClientToServerStatus> {
        match self.streams.reader().await.as_mut() {
            Ok(bridge) => {
                let next_read = match bridge.read_packet().await {
                    Err(err) => {
                        return Some(ClientToServerStatus::OtherErr(err));
                    }
                    Ok(Some(next_read)) => next_read,
                    Ok(None) => {
                        return Some(ClientToServerStatus::Disconnected);
                    }
                };

                use RawPacket::*;
                let result = match next_read {
                    PlayClientPluginMessage(raw) => {
                        let body = deserialize_raw!(raw, ClientToServerStatus);
                        let is_register = match body.channel.as_str() {
                            "REGISTER" => true,
                            "register" => true,
                            "minecraft:register" => true,
                            _ => false
                        };
                        if is_register {
                            let mut all_channels = self.plugin_channels.lock().await;
                            let mut new = HashSet::new();
                            for channel in body.data.data.split(|b| *b == 0x00) {
                                let channel = String::from_utf8_lossy(channel).to_string();
                                if all_channels.insert(channel.clone()) {
                                    new.insert(channel);
                                }
                            }

                            if !new.is_empty() {
                                let channels = new.iter().cloned().collect::<Vec<_>>();
                                to.register_plugin_channels(channels).await
                            } else {
                                Ok(())
                            }
                        } else {
                            to.streams.write_raw_packet(PlayClientPluginMessage(raw)).await
                        }
                    },
                    other => {
                        to.streams.write_raw_packet(other).await
                    }
                };

                if let Err(err) = result {
                    Some(ClientToServerStatus::WriteErr(err, name.clone()))
                } else {
                    None
                }
            }
            Err(err) => {
                return Some(ClientToServerStatus::OtherErr(err));
            }
        }
    }

    async fn forward_server_to_client_once(self: &UpstreamConnection, name: &String, from: &DownstreamConnection) -> Option<ServerToClientStatus> {
        match from.streams.reader().await.as_mut() {
            Ok(bridge) => {
                let next_read = match bridge.read_packet().await {
                    Err(err) => {
                        return Some(ServerToClientStatus::OtherErr(err));
                    }
                    Ok(Some(next_read)) => next_read,
                    Ok(None) => {
                        return Some(ServerToClientStatus::Disconnected(name.clone()));
                    }
                };

                use RawPacket::*;
                match &next_read {
                    PlayDisconnect(raw) => {
                        let body = deserialize_raw!(raw, ServerToClientStatus);
                        return Some(ServerToClientStatus::Kicked(body.reason));
                    }
                    PlayPlayerInfo(raw) => {
                        let body = deserialize_raw!(raw, ServerToClientStatus);
                        self.handle_tablist_update(body).await;
                    }
                    PlayServerPluginMessage(raw) => {
                        let body = deserialize_raw!(raw, ServerToClientStatus);
                        match body.channel.as_str() {
                            "rustcord:send" => {
                                return Some(ServerToClientStatus::ConnectNext(String::from_utf8_lossy(body.data.data.as_slice()).into()));
                            }
                            _ => {}
                        }
                    }
                    PlayRespawn(raw) => {
                        let body = deserialize_raw!(raw, ServerToClientStatus);
                        *self.dimension.lock().await = Some(body.dimension)
                    }
                    _ => {}
                }

                let write_result = match self.rewrite_entity_clientbound(&next_read).await {
                    Ok(Some(changed)) => {
                        self.streams.write_packet(changed).await
                    },
                    Ok(None) => {
                        self.streams.write_raw_packet(next_read).await
                    },
                    Err(err) => {
                        return Some(ServerToClientStatus::OtherErr(err))
                    }
                };

                if let Err(err) = write_result {
                    return Some(ServerToClientStatus::WriteErr(err));
                }

                None
            }
            Err(err) => {
                return Some(ServerToClientStatus::OtherErr(err));
            }
        }
    }

    async fn handle_tablist_update(self: &UpstreamConnection, data: proto::PlayPlayerInfoSpec) {
        use proto::PlayerInfoActionList::*;
        match data.actions {
            Add(adds) => {
                let mut state = self.downstream.lock().await;
                let tablist = &mut state.tablist_members;
                for add in adds {
                    let id = &add.uuid;
                    if !tablist.contains(id) {
                        tablist.insert(*id);
                    }
                }
            }
            Remove(ids) => {
                let mut state = self.downstream.lock().await;
                let tablist = &mut state.tablist_members;
                for id in ids {
                    tablist.remove(&id);
                }
            }
            _ => {}
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

    pub(crate) async fn take_streams_disconnect(&self) -> Result<(TcpReadBridge, TcpWriteBridge)> {
        if let Some((reader, writer)) = self.streams.take().await? {
            if self.is_in_players.compare_and_swap(true, false, Ordering::SeqCst) {
                self.proxy.has_disconnected(&self.id).await;
            }

            if let Ok(mut downstream) = self.downstream.try_lock() {
                downstream.connected_to.take();
                downstream.pending_next.take();
            }

            Ok((reader, writer))
        } else {
            Err(anyhow!("user is already disconnected, can't take streams"))
        }
    }

    async fn rewrite_entity_clientbound(self: &UpstreamConnection, raw_packet: &RawPacket<'_>) -> Result<Option<Packet>> {
        let entity_ids = {
            let downstream = self.downstream.lock().await;

            downstream
                .connected_to
                .as_ref()
                .map(move |v| v.join_game.entity_id)
                .and_then(move |server_id| downstream.client_entity_id.as_ref()
                    .filter(move |client_id| **client_id != server_id)
                    .map(move |client_id| (*client_id, server_id)))
        };

        if entity_ids.is_none() {
            return Ok(None);
        }

        let (client_id, server_id) = entity_ids.expect("exists");

        let remap_id = |target: &mut i32| {
            if *target == client_id {
                *target = server_id
            } else if *target == server_id {
                *target = client_id
            }
        };

        let remap_varint = |target: &mut VarInt| {
            remap_id(&mut target.0)
        };

        match raw_packet {
            RawPacket::PlaySpawnEntity(body) => {
                let mut packet = body.deserialize()?;
                let entity_type = packet.entity_type.0;
                let is_arrow = entity_type == 2;
                let is_fishing_bobber = entity_type == 102;
                let is_spectral_arrow = entity_type == 72;

                if is_arrow || is_fishing_bobber || is_fishing_bobber {
                    if is_arrow || is_spectral_arrow {
                        packet.data -= 1;
                    }

                    remap_id(&mut packet.data);

                    if is_arrow || is_spectral_arrow {
                        packet.data += 1;
                    }
                }

                Ok(Some(Packet::PlaySpawnEntity(packet)))
            },
            RawPacket::PlaySpawnExperienceOrb(body) => {
                remap_entity_id_field!(body, PlaySpawnExperienceOrb, entity_id, remap_varint);
            }
            RawPacket::PlaySpawnLivingEntity(body) => {
                remap_entity_id_field!(body, PlaySpawnLivingEntity, entity_id, remap_varint);
            }
            RawPacket::PlaySpawnPainting(body) => {
                remap_entity_id_field!(body, PlaySpawnPainting, entity_id, remap_varint);
            }
            // RawPacket::PlaySpawnPlayer(body) => {
            //     let packet = body.deserialize()?;
            //     self.proxy.players.lock().await.player_by_id(packet.uuid).
            // }
            _ => Ok(None)
        }
    }
}