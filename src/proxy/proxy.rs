use super::bridge::{Bridge, PacketNext, ReadBridge};
use super::config::TargetServerSpec;
use super::initial_handler::InitialUpstreamHandler;
use super::logger::{Level, Logger};
use super::session::{HasJoinedResponse, UserProperty};
use super::{Configuration, UnexpectedPacketErr};
use crate::{read_check_closed, read_parse};

use crate::proxy::bridge::WriteBridge;
use anyhow::{anyhow, Result};
use futures::{Stream, TryStreamExt};
use mcproto_rs::protocol::{Packet as PacketTrait, RawPacket};
use mcproto_rs::types::Chat;
use mcproto_rs::uuid::UUID4;
use mcproto_rs::v1_15_2::{
    HandshakeSpec, Id, Packet578 as Packet, PacketDirection, PlayDisconnectSpec,
};
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

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
    ConflictId(Bridge, UUID4),
    ConflictName(Bridge, String),
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
                        )
                        .spawn_handler();
                    }
                }
            });

            join_handles.push(handle);
        }

        futures::future::try_join_all(join_handles).await?;

        Ok(())
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
        upstream: Bridge,
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
        upstream: Bridge,
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

        let player_inner = Arc::new(RwLock::new(PlayerInner {
            proxy,
            handshake,
            username: username.clone(),
            id: id.clone(),
            properties: join_response.properties,
            upstream: Some(upstream),
        }));

        let weak = PlayerRef {
            id: id.clone(),
            username: username.clone(),
            inner: player_inner.clone(),
        };

        let strong = Player {
            id: id.clone(),
            username: username.clone(),
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
    inner: Arc<RwLock<PlayerInner>>,
}

pub struct Player {
    id: UUID4,
    username: String,
    inner: Arc<RwLock<PlayerInner>>,
}

pub struct PlayerInner {
    proxy: Proxy,
    id: UUID4,
    username: String,
    properties: Vec<UserProperty>,
    upstream: Option<Bridge>,
    handshake: HandshakeSpec,
}

pub struct DownstreamConnection {
    bridge: Bridge,
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
        inner
            .proxy
            .logger()
            .info(format_args!("player {} disconnected", inner.username));
    }
}

impl PlayerInner {
    async fn disconnect_upstream(&mut self, message: Chat) -> Result<()> {
        self.upstream
            .as_mut()
            .expect("must be connected")
            .write_packet(Packet::PlayDisconnect(PlayDisconnectSpec {
                reason: message,
            }))
            .await
    }

    async fn connect_to_downstream(&mut self, downstream: &TargetServerSpec) -> Result<()> {
        let upstream = self.upstream.take().expect("must be connected");
        let downstream = downstream_connect(
            downstream.address.clone(),
            self.username.clone(),
            upstream.remote_addr().ip().to_string(),
            self.id,
            self.handshake.clone(),
        )
        .await?;

        let (upstream_read, mut upstream_write) = upstream.into_split();
        let (downstream_read, mut downstream_write) = downstream.into_split();

        tokio::try_join!(
            forward_forever(downstream_read, upstream_write),
            forward_forever(upstream_read, downstream_write)
        )?;
        Ok(())
    }
}

async fn forward_forever(mut source: ReadBridge, mut to: WriteBridge) -> Result<()> {
    tokio::spawn(async move {
        while let PacketNext::Read(packet) = source.read_packet().await? {
            to.write_raw_packet(packet).await?;
        }

        Ok(())
    })
    .await
    .map_err(move |join_err| anyhow::anyhow!("join err: {:?}", join_err))?
}

async fn downstream_connect(
    target: String,
    username: String,
    ip: String,
    id: UUID4,
    handshake: HandshakeSpec,
) -> Result<Bridge> {
    use mcproto_rs::v1_15_2::{
        HandshakeNextState, LoginStartSpec,
        Packet578::{
            Handshake, LoginEncryptionRequest, LoginSetCompression, LoginStart, LoginSuccess,
        },
        PacketDirection::ClientBound,
        State::{Login, Play},
    };

    let stream = TcpStream::connect(target).await?;
    let peer_addr = stream.peer_addr()?;
    let mut bridge = Bridge::initial(ClientBound, stream, peer_addr)?;
    bridge
        .write_packet(Handshake(HandshakeSpec {
            version: 578.into(),
            server_address: [handshake.server_address, ip, id.to_string()].join("\x00"),
            server_port: handshake.server_port,
            next_state: HandshakeNextState::Login,
        }))
        .await?;
    bridge.set_state(Login);
    bridge
        .write_packet(LoginStart(LoginStartSpec { name: username }))
        .await?;
    loop {
        match read_parse!(bridge.read_packet()) {
            LoginSetCompression(spec) => {
                bridge.set_compression_threshold(spec.threshold.into());
            }
            LoginSuccess(_) => {
                break;
            }
            LoginEncryptionRequest(_) => {
                return Err(anyhow!("server is in online mode"));
            }
            packet => {
                return Err(UnexpectedPacketErr { packet }.into());
            }
        }
    }
    bridge.set_state(Play);
    Ok(bridge)
}
