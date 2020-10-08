use super::bridge::{Bridge, TcpBridge, TcpReadBridge, TcpWriteBridge};
use super::config::TargetServerSpec;
use super::initial_handler::InitialUpstreamHandler;
use super::logger::{Level, Logger};
use super::session::{HasJoinedResponse, UserProperty};
use super::{Configuration, UnexpectedPacketErr};

use anyhow::{anyhow, Result};
use mcproto_rs::types::Chat;
use mcproto_rs::uuid::UUID4;
use mcproto_rs::v1_15_2::{HandshakeSpec, Packet578 as Packet, PacketDirection, PlayDisconnectSpec, PlayerInfoActionList, Id, PlayClientPluginMessageSpec};
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Mutex};
use tokio::task::JoinHandle;
use crate::proxy::bridge::RawPacket;
use futures::FutureExt;
use futures::future::Either;
use tokio::macros::support::Future;
use std::net::SocketAddr;

pub struct Proxy {
    inner: Arc<ProxyInner>,
}

struct ProxyInner {
    config: Configuration,
    players: RwLock<ProxyPlayers>,
    logger: Logger,
    private_key: rsa::RSAPrivateKey,
}

pub enum AddPlayerStatus {
    ConflictId(TcpBridge, UUID4),
    ConflictName(TcpBridge, String),
    Added(Player),
}

impl Proxy {
    pub fn new(config: Configuration) -> Result<Self> {
        let players = RwLock::new(ProxyPlayers::new());
        let logger = Logger::new(Level::Debug);
        let mut rng = rand::thread_rng();
        let private_key = RSAPrivateKey::new(&mut rng, 1024)
            .map_err(move |err| anyhow!("rsa gen error: {:?}", err))?;
        let inner = ProxyInner {
            config,
            players,
            logger,
            private_key,
        };

        Ok(Proxy {
            inner: Arc::new(inner),
        })
    }

    pub async fn listen_and_serve(&self) -> Result<()> {
        let inner = self.inner.as_ref();
        inner.logger.trace(format_args!(
            "entering listen_and_serve with config {:?}",
            self.config()
        ));

        let addrs = &inner.config.bind_addresses;
        let mut join_handles: Vec<JoinHandle<Result<()>>> = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let handle = tokio::spawn({
                let addr = addr.clone();
                let logger = inner.logger.clone();
                let inner_arc = self.inner.clone();
                async move {
                    let mut listener = TcpListener::bind(addr.clone()).await?;
                    logger.info(format_args!("listening on {:?}", addr));
                    loop {
                        let (stream, from) = listener.accept().await?;
                        logger.info(format_args!("connection from {:?}", from));
                        let connection = Bridge::initial(PacketDirection::ServerBound, stream, from)?;
                        InitialUpstreamHandler::new(
                            connection,
                            Self {
                                inner: inner_arc.clone(),
                            },
                        ).spawn_handler();
                    }
                }
            });

            join_handles.push(handle);
        }

        let mut errs: Vec<anyhow::Error> = match futures::future::try_join_all(join_handles).await {
            Ok(results) => {
                let mut errs = Vec::with_capacity(results.len());
                for result in results {
                    if let Err(err) = result {
                        errs.push(err.into());
                    }
                }

                errs
            }
            Err(err) => {
                vec!(err.into())
            }
        };

        if !errs.is_empty() {
            let logger = inner.logger;
            logger.error(format_args!("{} errors running rustcoord:", errs.len()));
            for err in &errs {
                logger.error(format_args!("err: {:?}", err));
            }

            Err(errs.remove(0))
        } else {
            inner.logger.warning(format_args!("finished {} listeners?", inner.config.bind_addresses.len()));
            Ok(())
        }
    }

    pub async fn players(&self) -> Vec<PlayerRef> {
        self.inner
            .players
            .read()
            .await
            .by_id
            .iter()
            .map(move |(_, value)| value.clone())
            .collect()
    }

    pub fn config(&self) -> &Configuration {
        &self.inner.config
    }

    pub fn rsa_pubkey_asn1(&self) -> Vec<u8> {
        use num_bigint_dig::{BigInt, Sign::Plus};
        let pub_key = self.inner.private_key.to_public_key();
        rsa_der::public_key_to_der(
            &BigInt::from_biguint(Plus, pub_key.n().clone()).to_signed_bytes_be(),
            &BigInt::from_biguint(Plus, pub_key.e().clone()).to_signed_bytes_be(),
        )
    }

    pub fn decrypt_token(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .private_key
            .decrypt(PaddingScheme::PKCS1v15, data)
            .map_err(move |err| anyhow!("rsa decrypt err {:?}", err))?)
    }

    pub fn logger(&self) -> &Logger {
        &self.inner.logger
    }

    pub async fn add_new_player(
        &self,
        upstream: TcpBridge,
        handshake: HandshakeSpec,
        join_response: HasJoinedResponse,
    ) -> AddPlayerStatus {
        self.inner.players.write().await.add_player(
            Self {
                inner: self.inner.clone(),
            },
            upstream,
            handshake,
            join_response,
        )
    }
}

pub struct ProxyPlayers {
    by_username: HashMap<String, PlayerRef>,
    by_id: HashMap<UUID4, PlayerRef>,
}

impl ProxyPlayers {
    pub fn new() -> Self {
        ProxyPlayers {
            by_username: HashMap::new(),
            by_id: HashMap::new(),
        }
    }

    fn add_player(
        &mut self,
        proxy: Proxy,
        upstream: TcpBridge,
        handshake: HandshakeSpec,
        join_response: HasJoinedResponse,
    ) -> AddPlayerStatus {
        let id = join_response.id;
        let username = join_response.name;
        let lower_name = username.to_lowercase();

        if self.by_id.contains_key(&id) {
            return AddPlayerStatus::ConflictId(upstream, id);
        }

        if self.by_username.contains_key(&lower_name) {
            return AddPlayerStatus::ConflictName(upstream, username);
        }

        let remote_addr = upstream.remote_addr().clone();
        let (u_reader, u_writer) = upstream.split();
        let upstream = Arc::new(PlayerBridgePair {
            reader: Mutex::new(u_reader),
            writer: Mutex::new(u_writer),
            remote_addr,
        });

        let properties = Arc::new(join_response.properties);
        let player_inner = Arc::new(RwLock::new(PlayerInner {
            proxy,
            handshake,
            username: username.clone(),
            id: id.clone(),
            properties: properties.clone(),
            upstream: Some(upstream),
            downstream: None,
            state: Mutex::new(PlayerInnerState::default()),
        }));

        let weak = PlayerRef {
            id: id.clone(),
            username: username.clone(),
            properties: properties.clone(),
            inner: player_inner.clone(),
        };

        let strong = Player {
            id: id.clone(),
            username: username.clone(),
            properties,
            inner: player_inner,
        };

        self.by_username.insert(lower_name, weak.clone());
        self.by_id.insert(id, weak.clone());
        AddPlayerStatus::Added(strong)
    }

    fn remove_player(&mut self, player: &Player) {
        self.by_username.remove(&player.username.to_lowercase());
        self.by_id.remove(&player.id);
    }
}

#[derive(Clone)]
pub struct PlayerRef {
    pub id: UUID4,
    pub username: String,
    pub properties: Arc<Vec<UserProperty>>,
    inner: Arc<RwLock<PlayerInner>>,
}

pub struct Player {
    id: UUID4,
    username: String,
    properties: Arc<Vec<UserProperty>>,
    inner: Arc<RwLock<PlayerInner>>,
}

pub struct PlayerInner {
    proxy: Proxy,
    id: UUID4,
    username: String,
    properties: Arc<Vec<UserProperty>>,
    upstream: Option<Arc<PlayerBridgePair>>,
    downstream: Option<Arc<PlayerBridgePair>>,
    handshake: HandshakeSpec,
    state: Mutex<PlayerInnerState>,
}

struct PlayerBridgePair {
    reader: Mutex<TcpReadBridge>,
    writer: Mutex<TcpWriteBridge>,
    remote_addr: SocketAddr,
}

impl Player {
    pub async fn connect_to_initial_downstream(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        let initial_servers: Vec<_> = inner
            .proxy
            .config()
            .servers
            .iter()
            .filter(move |s| s.connect_to)
            .cloned()
            .collect();
        if initial_servers.is_empty() {
            return inner
                .disconnect_upstream(Chat::from_text(
                    "no server available for you to connect to...",
                ))
                .await;
        }

        let server = initial_servers
            .get(rand::random::<usize>() % initial_servers.len())
            .expect("server exists");
        inner.connect_to_downstream(server).await
    }
}

impl Drop for Player {
    fn drop(&mut self) {
        let mut inner = futures::executor::block_on(self.inner.write());
        inner.upstream.take();
        futures::executor::block_on(inner.proxy.inner.players.write()).remove_player(self);
    }
}

impl PlayerInner {
    async fn disconnect_upstream(&mut self, message: Chat) -> Result<()> {
        self.upstream
            .as_mut()
            .expect("must be connected")
            .writer
            .lock()
            .await
            .write_packet(Packet::PlayDisconnect(PlayDisconnectSpec {
                reason: message,
            }))
            .await
    }

    async fn connect_to_downstream(&mut self, downstream: &TargetServerSpec) -> Result<()> {
        self.state.lock().await.current_server_id = Some(downstream.name.clone());
        let upstream = match &self.upstream {
            Some(upstream) => upstream.clone(),
            None => return Err(anyhow!("player is not connected")),
        };
        self.downstream.replace(downstream_connect(
            self.proxy.logger(),
            downstream.address.clone(),
            self.username.clone(),
            upstream.remote_addr.ip().to_string(),
            self.id,
            self.handshake.clone(),
        ).await?);
        let downstream = self.downstream.as_ref().expect("just created this").clone();

        let either = {
            tokio::pin! {
                let to_client = self.forward_forever(downstream.clone(), upstream.clone());
                let to_server = self.forward_forever(upstream, downstream);
            }

            futures::future::select(to_client, to_server).then(|either| async move {
                match either {
                    Either::Left((v, _)) => Either::Left(v),
                    Either::Right((v, _)) => Either::Right(v),
                }
            }).await
        };

        let client_err_handler = |err: Option<anyhow::Error>| {
            if let Some(err) = err {
                self.proxy.logger().warning(format_args!("{} disconnected due to error talking to client {:?}", self.username, err));
            } else {
                self.proxy.logger().info(format_args!("{} disconnected", self.username));
            }
        };

        let res = match either {
            Either::Left(to_client_result) => {
                match to_client_result {
                    ForwardingResult::WriteErr(err) => {
                        // failed to talk to client, or client disconnected
                        client_err_handler(Some(err));
                        None
                    }
                    ForwardingResult::Finished => None,
                    // failed to read from server
                    ForwardingResult::ReadErr(err) => {
                        self.server_disconnected_handler(err).await;
                        None
                    }
                    // jump to next server
                    ForwardingResult::ConnectToNextDownstream(next) => {
                        Some(next)
                    }
                    // failed to read packet
                    ForwardingResult::DeserializeErr(id, err) => {
                        self.bad_packet_handler(id, err).await;
                        None
                    }
                }
            }
            Either::Right(to_server_result) => {
                match to_server_result {
                    ForwardingResult::WriteErr(err) => {
                        // failed to talk to server
                        self.server_disconnected_handler(Some(err)).await;
                        None
                    }
                    ForwardingResult::Finished => None,
                    ForwardingResult::ReadErr(err) => {
                        // failed while reading client
                        client_err_handler(err);
                        None
                    }
                    ForwardingResult::ConnectToNextDownstream(next) => {
                        Some(next)
                    }
                    ForwardingResult::DeserializeErr(id, err) => {
                        self.bad_packet_handler(id, err).await;
                        None
                    }
                }
            }
        };

        if let Some(next_target) = res {
            self.proxy.logger().info(format_args!("would have connected {} to {} but not implemented", self.username, next_target));
        } else {
            self.proxy.logger().info(format_args!("connection {}/{} is terminated", self.username, self.id));
        }

        Ok(())
    }

    async fn server_disconnected_handler(&self, err: Option<anyhow::Error>) {
        let disconnect_result = {
            if let Some(downstream) = self.downstream.as_ref() {
                let mut to = downstream.writer.lock().await;
                if let Some(err) = &err {
                    to.write_packet(Packet::PlayDisconnect(PlayDisconnectSpec {
                        reason: Chat::from_text(format!("disconnected: server error {:?}", err).as_str()),
                    })).await
                } else {
                    to.write_packet(Packet::PlayDisconnect(PlayDisconnectSpec {
                        reason: Chat::from_text("disconnected from server!"),
                    })).await
                }
            } else {
                Err(anyhow!("player already left"))
            }
        };

        if let Err(disconnect_err) = disconnect_result {
            self.proxy.logger().warning(format_args!("{} failed to notify of error {:?} -- {:?}", self.username, err, disconnect_err))
        }
    }

    async fn bad_packet_handler(&self, packet_id: Id, err: anyhow::Error) {
        let write_result = if let Some(upstream) = self.upstream.as_ref() {
            upstream.writer.lock().await.write_packet(Packet::PlayDisconnect(PlayDisconnectSpec {
                reason: Chat::from_text(format!("invalid packet {:?} -- {:?}", packet_id, err).as_str()),
            })).await
        } else {
            Err(anyhow!("player already gone"))
        };

        if let Err(err) = write_result {
            self.proxy.logger().warning(format_args!("failed to disconnect {} for bad packet {:?}", self.username, err));
        }

        self.proxy.logger().warning(format_args!("bad packet on connection {} -- {:?} {:?}", self.username, packet_id, err));
    }

    async fn forward_forever(&self, source: Arc<PlayerBridgePair>, to: Arc<PlayerBridgePair>) -> ForwardingResult {
        loop {
            match source.reader.lock().await.read_packet().await {
                Ok(read) => {
                    if let Some(mut packet) = read {
                        match packet.deserialize() {
                            Ok(deserialized) => {
                                let (packets, fin): (Option<Vec<Packet>>, bool) = match self.handle_packet(deserialized).await {
                                    PacketHandleResult::ConnectToNextDownstream(downstream) => {
                                        return ForwardingResult::ConnectToNextDownstream(downstream);
                                    }
                                    PacketHandleResult::WriteNext(deserialized) => {
                                        (Some(vec![deserialized]), false)
                                    }
                                    PacketHandleResult::SkipPacket => (None, false),
                                    PacketHandleResult::FinalPacket(packet) => {
                                        (Some(vec![packet]), true)
                                    }
                                    PacketHandleResult::WriteThese(packets) => {
                                        (Some(packets), false)
                                    }
                                };

                                if let Some(packets) = packets {
                                    for deserialized in packets {
                                        if let Err(err) = to.writer.lock().await.write_packet(deserialized).await {
                                            return ForwardingResult::WriteErr(err);
                                        }
                                    }
                                }

                                if fin {
                                    return ForwardingResult::Finished;
                                }
                            }
                            Err(err) => {
                                return ForwardingResult::DeserializeErr(packet.id().clone(), err);
                            }
                        }
                    } else {
                        return ForwardingResult::ReadErr(None);
                    }
                }
                Err(err) => {
                    return ForwardingResult::ReadErr(Some(err));
                }
            }
        }
    }

    async fn handle_packet(&self, mut packet: Packet) -> PacketHandleResult {
        match packet {
            Packet::PlayPlayerInfo(mut body) => {
                self.handle_player_info(&mut body).await;
                PacketHandleResult::WriteNext(Packet::PlayPlayerInfo(body))
            }
            Packet::PlayDisconnect(_) => {
                PacketHandleResult::FinalPacket(packet)
            }
            Packet::PlayJoinGame(mut body) => {
                self.handle_join_game(body).await
            }
            Packet::PlayServerPluginMessage(body) => {
                match self.handle_plugin_message(body).await {
                    Err(err) => {
                        self.proxy.logger().warning(format_args!("failed to handle proxy plugin message for {} -- {:?}", self.username, err));
                        PacketHandleResult::SkipPacket
                    },
                    Ok(result) => result,
                }
            }
            other => PacketHandleResult::WriteNext(other)
        }
    }

    async fn handle_player_info(&self, info: &mut mcproto_rs::v1_15_2::PlayPlayerInfoSpec) {
        // this fixes broken skins
        let mut state = self.state.lock().await;

        match &mut info.actions {
            PlayerInfoActionList::Add(actions) => {
                for container in actions {
                    // we should find a player on this proxy with that skin
                    if let Some(player) = self.proxy.inner.players.read().await.by_id.get(&container.uuid) {
                        state.tablist_users.insert(player.id.clone());

                        let own_properties = &player.properties;
                        let mut own_property_names = HashSet::with_capacity(own_properties.len());
                        for property in own_properties.iter() {
                            own_property_names.insert(property.name.clone());
                        }

                        let prop_data = &mut container.action.properties.data;
                        let mut out_props = Vec::with_capacity(prop_data.len());

                        while !prop_data.is_empty() {
                            let prop = prop_data.remove(0);
                            if !own_property_names.contains(&prop.name) {
                                out_props.push(prop);
                            }
                        }

                        for property in own_properties.iter() {
                            out_props.push(mcproto_rs::v1_15_2::PlayerAddProperty {
                                name: property.name.clone(),
                                value: property.value.clone(),
                                signature: Some(property.signature.clone()),
                            })
                        }

                        *prop_data = out_props;
                    }
                }
            }
            PlayerInfoActionList::Remove(ids) => {
                for id in ids {
                    state.tablist_users.remove(id);
                }
            }
            _ => {}
        }
    }

    async fn handle_join_game(&self, mut body: mcproto_rs::v1_15_2::PlayJoinGameSpec) -> PacketHandleResult {
        let mut state = self.state.lock().await;
        state.server_entity_id = Some(body.entity_id);
        if state.client_entity_id.is_none() {
            state.client_entity_id = state.server_entity_id.clone();
            PacketHandleResult::WriteNext(Packet::PlayJoinGame(body))
        } else {
            // todo
            PacketHandleResult::SkipPacket
        }
    }

    async fn handle_plugin_message(&self, mut body: mcproto_rs::v1_15_2::PlayServerPluginMessageSpec) -> Result<PacketHandleResult> {
        let bytes = body.data.data.as_slice();
        if body.channel == "BungeeCord" {
            let (sub_channel, bytes) = read_java_utf8(bytes)?;
            match sub_channel.as_str() {
                "Connect" => {
                    let (target, _) = read_java_utf8(bytes)?;
                    return Ok(PacketHandleResult::ConnectToNextDownstream(target));
                }
                // todo others
                _ => {}
            }
        }

        Ok(PacketHandleResult::WriteNext(Packet::PlayServerPluginMessage(body)))
    }
}

fn read_java_utf8(data: &[u8]) -> Result<(String, &[u8])> {
    if data.len() < 2 {
        return Err(anyhow!("eof reading length!"));
    }
    let length = (((data[0] as u16) << 8) | (data[1] as u16)) as usize;
    let data = &data[2..];
    if data.len() < length {
        return Err(anyhow!("eof expecting {} bytes got {}", length, data.len()));
    }

    let (mut data, rest) = data.split_at(length);
    let mut out = String::with_capacity(length);
    while !data.is_empty() {
        let b0 = data[0];
        let group_size = if (b0 & 0b11110000) >> 4 == 0b1110 {
            3
        } else if (b0 & 0b11100000) >> 5 == 0b110 {
            2
        } else if (b0 >> 7) == 0 {
            1
        } else {
            return Err(anyhow!("unexpected byte pattern {}", b0));
        };

        if data.len() < group_size {
            return Err(anyhow!("eof trying to read a UTF-8 group with size {}", group_size));
        }

        let (char_data, rest) = data.split_at(group_size);
        data = rest;
        let c = if group_size == 1 {
            char_data[0] as u32
        } else if group_size == 2 {
            (((char_data[0] & 0x1F) as u32) << 6) | ((char_data[1] & 0x3F) as u32)
        } else if group_size == 3 {
            (((char_data[0] & 0x0F) as u32) << 12) | (((char_data[1] & 0x3F) as u32) << 6) | ((char_data[2] & 0x3F) as u32)
        } else {
            panic!("impossible")
        };

        if let Some(ch) = char::from_u32(c) {
            out.push(ch);
        } else {
            return Err(anyhow!("failed to interpret bytes to char {:?}", char_data));
        }
    }

    Ok((out, rest))
}

enum ForwardingResult {
    WriteErr(anyhow::Error),
    ReadErr(Option<anyhow::Error>),
    ConnectToNextDownstream(String),
    DeserializeErr(Id, anyhow::Error),
    Finished,
}

enum PacketHandleResult {
    WriteNext(Packet),
    SkipPacket,
    WriteThese(Vec<Packet>),
    ConnectToNextDownstream(String),
    FinalPacket(Packet),
}

async fn downstream_connect(
    logger: &Logger,
    target: String,
    username: String,
    ip: String,
    id: UUID4,
    handshake: HandshakeSpec,
) -> Result<Arc<PlayerBridgePair>> {
    use mcproto_rs::v1_15_2::{
        HandshakeNextState, LoginStartSpec,
        Packet578::{
            Handshake, LoginEncryptionRequest, LoginSetCompression, LoginStart, LoginSuccess,
        },
        PacketDirection::ClientBound,
        State::{Login, Play},
    };

    logger.debug(format_args!("connecting {}/{} (from {}) to {:?}", username, id, ip, target));
    let stream = TcpStream::connect(target).await?;
    let peer_addr = stream.peer_addr()?;
    logger.debug(format_args!("connected to {}", peer_addr));
    let mut bridge = Bridge::initial(ClientBound, stream, peer_addr)?;
    let handshake = Handshake(HandshakeSpec {
        version: 578.into(),
        server_address: [handshake.server_address, ip.clone(), id.to_string()].join("\x00"),
        server_port: handshake.server_port,
        next_state: HandshakeNextState::Login,
    });
    logger.debug(format_args!("handshake with downstream {:?}", handshake));
    bridge.write_packet(handshake).await?;
    bridge.set_state(Login);
    bridge.write_packet(LoginStart(LoginStartSpec { name: username.clone() })).await?;
    loop {
        let packet = bridge.must_read_packet().await?.deserialize()?;
        match packet {
            LoginSetCompression(spec) => {
                logger.debug(format_args!("downstream asked for compression with threshold {:?}", spec.threshold));
                bridge.set_compression_threshold(spec.threshold.into());
            }
            LoginSuccess(spec) => {
                logger.debug(format_args!("downstream said 'login success!' switching to play {:?}", spec));
                break;
            }
            LoginEncryptionRequest(_) => {
                logger.warning(format_args!("downstream {} asked for encryption, it's in online mode, disconnecting {}/{} (from {})", peer_addr, username, id, ip));
                return Err(anyhow!("server is in online mode"));
            }
            packet => {
                return Err(UnexpectedPacketErr { packet }.into());
            }
        }
    }
    bridge.set_state(Play);
    let remote_addr = bridge.remote_addr().clone();
    let (read_half, write_half) = bridge.split();
    Ok(Arc::new(PlayerBridgePair {
        remote_addr,
        reader: Mutex::new(read_half),
        writer: Mutex::new(write_half),
    }))
}

#[derive(Default)]
struct PlayerInnerState {
    tablist_users: HashSet<UUID4>,
    client_entity_id: Option<i32>,
    server_entity_id: Option<i32>,
    current_server_id: Option<String>,
}