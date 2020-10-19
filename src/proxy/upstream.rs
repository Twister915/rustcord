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
use tokio::sync::{Mutex, MutexGuard, RwLock};
use std::collections::HashSet;
use std::pin::Pin;
use mcproto_rs::protocol::PacketErr;
use mcproto_rs::v1_15_2::TeamAction;

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
    pub tablist_members: Mutex<HashSet<UUID4>>,
    pub entity_ids: RwLock<EntityIds>,
    pub scoreboard_teams: Mutex<HashSet<String>>,
    pub scoreboard_objectives: Mutex<HashSet<String>>,
    pub boss_bars: Mutex<HashSet<UUID4>>,
}

#[derive(Default, Debug)]
pub struct EntityIds {
    pub client: Option<i32>,
    pub server: Option<i32>,
}

pub struct UpstreamBridges {
    pub connected_to: Option<DownstreamConnection>,
    pub pending_next: Option<DownstreamConnection>,
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
            }),
            plugin_channels: {
                let mut out = HashSet::default();
                out.insert("rustcord:send".to_owned());
                Mutex::new(out)
            },
            dimension: Mutex::new(None),
            tablist_members: Mutex::new(HashSet::default()),
            entity_ids: RwLock::new(EntityIds::default()),
            scoreboard_teams: Mutex::new(HashSet::default()),
            scoreboard_objectives: Mutex::new(HashSet::default()),
            boss_bars: Mutex::new(HashSet::default()),
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
            .nth(0)
        {
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
        let cloned = state.connected_to.as_ref().cloned();

        std::mem::drop(state);

        if let Some(connected_to) = cloned {
            if let Err(err) = self.send_message(msg.clone()).await {
                self.proxy.logger.warning(format_args!("failed to notify client of error {:?} {:?}", msg, err));
                ForwardingStatus::ClientDisconnected(None)
            } else {
                self.forward_forever(name, connected_to).await
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
        let mut entity_ids_mutex = self.entity_ids.write().await;

        let cur_dimension = dimension_mutex.as_ref().cloned().expect("has current dimension");
        if next.join_game.dimension == cur_dimension {
            let fake_dimension = match cur_dimension {
                Dimension::Nether => Dimension::Overworld,
                Dimension::Overworld => Dimension::Nether,
                Dimension::End => Dimension::Nether,
            };

            if let Err(err) = self.streams.write_packet(PlayRespawn(PlayRespawnSpec {
                dimension: fake_dimension,
                hashed_seed: next.join_game.hashed_seed.clone(),
                gamemode: next.join_game.gamemode.clone(),
                level_type: next.join_game.level_type.clone(),
            })).await {
                return ForwardingStatus::ServerDisconnected(Some(err), name.clone());
            }
        }

        if let Err(err) = self.streams.write_packet(PlayRespawn(PlayRespawnSpec {
            dimension: next.join_game.dimension.clone(),
            hashed_seed: next.join_game.hashed_seed.clone(),
            gamemode: next.join_game.gamemode.clone(),
            level_type: next.join_game.level_type.clone(),
        })).await {
            return ForwardingStatus::ServerDisconnected(Some(err), name.clone());
        }

        *dimension_mutex = Some(next.join_game.dimension.clone());

        if let Err(err) = self.streams.write_packet(PlayUpdateViewDistance(PlayUpdateViewDistanceSpec {
            view_distance: next.join_game.view_distance,
        })).await {
            return ForwardingStatus::ServerDisconnected(Some(err), name.clone());
        }

        prev.streams.take().await;

        entity_ids_mutex.server = Some(next.join_game.entity_id);

        state.connected_to = Some(next.clone());
        std::mem::drop(state);
        std::mem::drop(dimension_mutex);
        std::mem::drop(entity_ids_mutex);

        if let Err(err) = self.clear_state_on_next_server().await {
            return ForwardingStatus::ClientDisconnected(Some(err));
        }

        self.forward_forever(name, next).await
    }

    async fn join_initial_downstream(self: &UpstreamConnection, name: &String, mut state: MutexGuard<'_, UpstreamBridges>) -> ForwardingStatus {
        let pending = if let Some(next) = state.pending_next.take() {
            next
        } else {
            return ForwardingStatus::OtherErr(anyhow!("no pending downstream..."));
        };
        state.connected_to = Some(pending.clone());

        let mut entity_ids = self.entity_ids.write().await;
        entity_ids.server = Some(pending.join_game.entity_id);
        entity_ids.client = Some(pending.join_game.entity_id);
        std::mem::drop(entity_ids);
        std::mem::drop(state);

        if let Err(err) = self.streams.write_packet(Packet::PlayJoinGame(pending.join_game.clone())).await {
            return ForwardingStatus::ClientDisconnected(Some(err));
        }

        let mut dimension = self.dimension.lock().await;
        *dimension = Some(pending.join_game.dimension.clone());
        std::mem::drop(dimension);

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
                    }
                    other => {
                        match self.rewrite_entity_serverbound(&other).await {
                            Ok(Some(packet)) => to.streams.write_packet(packet).await,
                            Ok(None) => to.streams.write_raw_packet(other).await,
                            Err(err) => {
                                return Some(ClientToServerStatus::OtherErr(err.into()));
                            }
                        }
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
                        let mut tablist_members = self.tablist_members.lock().await;
                        use proto::PlayerInfoActionList::*;
                        match &body.actions {
                            Add(players) => {
                                for player in players {
                                    tablist_members.insert(player.uuid);
                                }
                            },
                            Remove(players) => {
                                for player in players {
                                    tablist_members.remove(player);
                                }
                            },
                            _ => {}
                        }
                        std::mem::drop(tablist_members);
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
                        let mut dimension = self.dimension.lock().await;
                        *dimension = Some(body.dimension);
                        std::mem::drop(dimension);
                    }
                    PlayScoreboardObjective(raw) => {
                        let body = deserialize_raw!(raw, ServerToClientStatus);
                        let mut scoreboard_objectives = self.scoreboard_objectives.lock().await;
                        use proto::ScoreboardObjectiveAction::*;
                        match &body.action {
                            Create(_) => {
                                scoreboard_objectives.insert(body.objective_name.clone());
                            },
                            Remove => {
                                scoreboard_objectives.remove(&body.objective_name);
                            },
                            _ => {}
                        }
                        std::mem::drop(scoreboard_objectives);
                    }
                    PlayTeams(raw) => {
                        let body = deserialize_raw!(raw, ServerToClientStatus);
                        let mut scoreboard_teams = self.scoreboard_teams.lock().await;
                        use proto::TeamAction::*;
                        match &body.action {
                            Create(_) => {
                                scoreboard_teams.insert(body.team_name.clone());
                            },
                            Remove => {
                                scoreboard_teams.remove(&body.team_name);
                            },
                            _ => {}
                        }
                        std::mem::drop(scoreboard_teams);
                    }
                    PlayBossBar(raw) => {
                        let body = deserialize_raw!(raw, ServerToClientStatus);
                        let mut boss_bars = self.boss_bars.lock().await;
                        use proto::BossBarAction::*;
                        match &body.action {
                            Add(_) => {
                                boss_bars.insert(body.uuid);
                            },
                            Remove => {
                                boss_bars.remove(&body.uuid);
                            },
                            _ => {}
                        }
                        std::mem::drop(boss_bars);
                    }
                    _ => {}
                }

                let write_result = match self.rewrite_entity_clientbound(&next_read).await {
                    Ok(Some(changed)) => {
                        self.streams.write_packet(changed).await
                    }
                    Ok(None) => {
                        self.streams.write_raw_packet(next_read).await
                    }
                    Err(err) => {
                        return Some(ServerToClientStatus::OtherErr(err.into()));
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

    async fn clear_state_on_next_server(self: &UpstreamConnection) -> Result<()> {
        self.send_clear_tablist().await?;
        self.send_clear_bossbars().await?;
        self.send_clear_scoreboard_objectives().await?;
        self.send_clear_scoreboard_teams().await?;
        Ok(())
    }

    async fn send_clear_tablist(self: &UpstreamConnection) -> Result<()> {
        let mut members = self.tablist_members.lock().await;
        let old_members: proto::VarIntCountedArray<UUID4> = members.drain().collect::<Vec<_>>().into();
        std::mem::drop(members);

        self.streams.write_packet(Packet::PlayPlayerInfo(proto::PlayPlayerInfoSpec {
            actions: proto::PlayerInfoActionList::Remove(old_members)
        })).await?;
        Ok(())
    }

    async fn send_clear_bossbars(self: &UpstreamConnection) -> Result<()> {
        let mut bossbars = self.boss_bars.lock().await;
        for boss_bar_id in bossbars.drain() {
            self.streams.write_packet(Packet::PlayBossBar(proto::PlayBossBarSpec{
                uuid: boss_bar_id,
                action: proto::BossBarAction::Remove,
            })).await?;
        }

        Ok(())
    }

    async fn send_clear_scoreboard_objectives(self: &UpstreamConnection) -> Result<()> {
        let mut objectives = self.scoreboard_objectives.lock().await;
        for objective in objectives.drain() {
            self.streams.write_packet(Packet::PlayScoreboardObjective(proto::PlayScoreboardObjectiveSpec{
                objective_name: objective,
                action: proto::ScoreboardObjectiveAction::Remove,
            })).await?;
        }

        Ok(())
    }

    async fn send_clear_scoreboard_teams(self: &UpstreamConnection) -> Result<()> {
        let mut teams = self.scoreboard_teams.lock().await;
        for team in teams.drain() {
            self.streams.write_packet(Packet::PlayTeams(proto::PlayTeamsSpec{
                action: proto::TeamAction::Remove,
                team_name: team,
            })).await?;
        }

        Ok(())
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

    //noinspection DuplicatedCode
    async fn rewrite_entity_clientbound(self: &UpstreamConnection, raw_packet: &RawPacket<'_>) -> Result<Option<Packet>, PacketErr> {
        let (client_id, server_id) = match self.get_remapped_id_pair().await {
            Some(data) => data,
            None => {
                return Ok(None);
            }
        };

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
                remap_varint(&mut packet.entity_id);
                // todo give better type stuff in mcproto-rs instead of using numeric ids here
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
            }
            RawPacket::PlaySpawnExperienceOrb(body) => {
                remap_entity_id_field!(body, PlaySpawnExperienceOrb, entity_id, remap_varint);
            }
            RawPacket::PlaySpawnLivingEntity(body) => {
                remap_entity_id_field!(body, PlaySpawnLivingEntity, entity_id, remap_varint);
            }
            RawPacket::PlaySpawnPainting(body) => {
                remap_entity_id_field!(body, PlaySpawnPainting, entity_id, remap_varint);
            }
            RawPacket::PlaySpawnPlayer(body) => {
                let mut packet = body.deserialize()?;
                remap_varint(&mut packet.entity_id);
                let players = self.proxy.players.lock().await;
                if let Some(other) = players.player_by_offline_id(&packet.uuid) {
                    packet.uuid = other.id;
                }

                Ok(Some(Packet::PlaySpawnPlayer(packet)))
            }
            RawPacket::PlayEntityAnimation(body) => {
                remap_entity_id_field!(body, PlayEntityAnimation, entity_id, remap_varint);
            }
            RawPacket::PlayBlockBreakAnimation(body) => {
                remap_entity_id_field!(body, PlayBlockBreakAnimation, entity_id, remap_varint);
            }
            RawPacket::PlayEntityStatus(body) => {
                remap_entity_id_field!(body, PlayEntityStatus, entity_id, remap_id);
            }
            RawPacket::PlayEntityPosition(body) => {
                remap_entity_id_field!(body, PlayEntityPosition, entity_id, remap_varint);
            }
            RawPacket::PlayEntityPositionAndRotation(body) => {
                remap_entity_id_field!(body, PlayEntityPositionAndRotation, entity_id, remap_varint);
            }
            RawPacket::PlayEntityRotation(body) => {
                remap_entity_id_field!(body, PlayEntityRotation, entity_id, remap_varint);
            }
            RawPacket::PlayEntityMovement(body) => {
                remap_entity_id_field!(body, PlayEntityMovement, entity_id, remap_varint);
            }
            RawPacket::PlayRemoveEntityEffect(body) => {
                remap_entity_id_field!(body, PlayRemoveEntityEffect, entity_id, remap_varint);
            }
            RawPacket::PlayEntityHeadLook(body) => {
                remap_entity_id_field!(body, PlayEntityHeadLook, entity_id, remap_varint);
            }
            RawPacket::PlayCamera(body) => {
                remap_entity_id_field!(body, PlayCamera, camera_id, remap_varint);
            }
            RawPacket::PlayEntityMetadata(body) => {
                // todo the actual metadata section
                remap_entity_id_field!(body, PlayEntityMetadata, entity_id, remap_varint);
            }
            RawPacket::PlayAttachEntity(body) => {
                let mut packet = body.deserialize()?;
                remap_id(&mut packet.attached_entity_id);
                remap_id(&mut packet.holding_entity_id);
                Ok(Some(Packet::PlayAttachEntity(packet)))
            }
            RawPacket::PlayEntityVelocity(body) => {
                remap_entity_id_field!(body, PlayEntityVelocity, entity_id, remap_varint);
            }
            RawPacket::PlayEntityEquipment(body) => {
                remap_entity_id_field!(body, PlayEntityEquipment, entity_id, remap_varint);
            }
            RawPacket::PlaySetPassengers(body) => {
                let mut packet = body.deserialize()?;
                remap_varint(&mut packet.entity_id);
                for child in &mut packet.passenger_entitiy_ids {
                    remap_varint(child);
                }
                Ok(Some(Packet::PlaySetPassengers(packet)))
            }
            RawPacket::PlayCollectItem(body) => {
                let mut packet = body.deserialize()?;
                remap_varint(&mut packet.collected_entity_id);
                remap_varint(&mut packet.collector_entity_id);
                Ok(Some(Packet::PlayCollectItem(packet)))
            }
            RawPacket::PlayEntityTeleport(body) => {
                remap_entity_id_field!(body, PlayEntityTeleport, entity_id, remap_varint);
            }
            RawPacket::PlayEntityProperties(body) => {
                remap_entity_id_field!(body, PlayEntityProperties, entity_id, remap_varint);
            }
            RawPacket::PlayEntityEffect(body) => {
                remap_entity_id_field!(body, PlayEntityEffect, entity_id, remap_varint);
            }
            _ => Ok(None)
        }
    }

    //noinspection DuplicatedCode
    async fn rewrite_entity_serverbound(self: &UpstreamConnection, raw_packet: &RawPacket<'_>) -> Result<Option<Packet>, PacketErr> {
        let (client_id, server_id) = match self.get_remapped_id_pair().await {
            Some(data) => data,
            None => {
                return Ok(None);
            }
        };

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
            RawPacket::PlayInteractEntity(body) => {
                remap_entity_id_field!(body, PlayInteractEntity, entity_id, remap_varint);
            }
            RawPacket::PlayEntityAction(body) => {
                remap_entity_id_field!(body, PlayEntityAction, entity_id, remap_varint);
            }
            RawPacket::PlaySpectate(body) => {
                let mut packet = body.deserialize()?;
                let players = self.proxy.players.lock().await;
                if let Some(other) = players.player_by_offline_id(&packet.target) {
                    packet.target = other.id;
                }
                Ok(Some(Packet::PlaySpectate(packet)))
            }
            _ => Ok(None)
        }
    }

    async fn get_remapped_id_pair(self: &UpstreamConnection) -> Option<(i32, i32)> {
        let entity_ids = self.entity_ids
            .read()
            .await;

        entity_ids
            .server
            .and_then(move |server_id| entity_ids.client.as_ref()
                .filter(move |client_id| **client_id != server_id)
                .map(move |client_id| (*client_id, server_id)))
    }
}