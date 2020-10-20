use crate::proxy::upstream::{UpstreamInner, UpstreamConnection};
use std::sync::Arc;
use std::collections::HashMap;
use mcproto_rs::uuid::UUID4;
use tokio::sync::Mutex;
use crate::proxy::config::Configuration;
use anyhow::{Result, anyhow};
use crate::proxy::logger::Logger;
use tokio::net::TcpListener;
use mctokio::TcpConnection;
use crate::proxy::util::{StreamsInner, offline_id_for};
use mcproto_rs::v1_15_2::State;
use crate::proxy::initial::InitialUpstreamHandler;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey};
use mcproto_rs::types::Chat;

pub type Proxy = Arc<ProxyInner>;

pub struct ProxyInner {
    pub config: Configuration,
    pub players: Mutex<Players>,
    pub logger: Logger,
    pub private_key: rsa::RSAPrivateKey,
    pub favicon: Option<Vec<u8>>,
}

impl ProxyInner {
    pub async fn listen_and_serve(config: Configuration) -> Result<()> {
        let logger = Logger::new(config.log_level.clone());
        logger.debug(format_args!("generating RSA keypair..."));
        let mut rng = rand::thread_rng();
        let private_key = RSAPrivateKey::new(&mut rng, 1024)
            .map_err(move |err| anyhow!("rsa gen error: {:?}", err))?;

        let favicon = config.load_favicon().await?;
        if favicon.is_some() {
            logger.info(format_args!(
                "loaded favicon from {}",
                config.favicon_location.as_ref().expect("is present")));
        }
        logger.debug(format_args!("constructing proxy"));
        let out = Self {
            config,
            logger,
            private_key,
            favicon,
            players: Mutex::new(Players::new()),
        };

        let proxy = Arc::new(out);

        logger.debug(format_args!("binding on all {} addresses", proxy.config.bind_addresses.len()));

        futures::future::try_join_all(
            proxy.config.bind_addresses.iter()
                .cloned() // avoids borrow of proxy forever
                .map(|addr| {
                    let proxy = proxy.clone();
                    async move {
                        tokio::spawn(async move {
                            proxy.listen_addr(addr).await
                        }).await?
                    }
                })).await?;

        Ok(())
    }

    async fn listen_addr(self: Proxy, addr: String) -> Result<()> {
        let mut listener = TcpListener::bind(addr.clone()).await?;
        self.logger.info(format_args!("bound on {}", addr));
        loop {
            let (client, remote) = listener.accept().await?;
            let (read, write) = TcpConnection::from_client_connection(client).into_split();
            let streams = StreamsInner::create(self.clone(), format!("conn from {}", remote), read, write, State::Handshaking);
            let conn = InitialUpstreamHandler {
                proxy: self.clone(),
                handshake: None,
                streams,
                remote
            };
            conn.spawn_handle()
        }
    }

    pub(crate) async fn has_disconnected(&self, id: &UUID4) {
        let mut players = self.players.lock().await;
        if let Some(player) = players.by_id.remove(id) {
            let offline_id = offline_id_for(player.username.as_str());
            players.by_offline_id.remove(&offline_id);
            let lower_name = player.username.to_lowercase();
            players.by_username.remove(&lower_name);
        }
    }

    pub async fn player_list(&self) -> Vec<UpstreamConnection> {
        self.players.lock().await.players()
    }

    pub(crate) async fn has_joined(&self, player: UpstreamInner) -> Result<UpstreamConnection> {
        self.players.lock().await.try_add_player(player).await
    }

    pub fn rsa_pubkey_asn1(&self) -> Vec<u8> {
        use num_bigint_dig::{BigInt, Sign::Plus};
        let pub_key = self.private_key.to_public_key();
        rsa_der::public_key_to_der(
            &BigInt::from_biguint(Plus, pub_key.n().clone()).to_signed_bytes_be(),
            &BigInt::from_biguint(Plus, pub_key.e().clone()).to_signed_bytes_be(),
        )
    }

    pub fn decrypt_token(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .private_key
            .decrypt(PaddingScheme::PKCS1v15, data)
            .map_err(move |err| anyhow!("rsa decrypt err {:?}", err))?)
    }
}

pub struct Players {
    by_id: HashMap<UUID4, UpstreamConnection>,
    by_offline_id: HashMap<UUID4, UpstreamConnection>,
    by_username: HashMap<String, UpstreamConnection>,
}

impl Players {
    fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_offline_id: HashMap::new(),
            by_username: HashMap::new(),
        }
    }

    async fn try_add_player(&mut self, player: UpstreamInner) -> Result<UpstreamConnection> {
        let name_key = player.username.to_lowercase();
        if self.by_id.contains_key(&player.id) || self.by_username.contains_key(&name_key) {
            player.kick(Chat::from_traditional("&cYou are already connected to this server!", true)).await?;
            return Err(anyhow!("player already on server!"));
        }

        let shared = Arc::new(player);
        self.by_id.insert(shared.id.clone(), shared.clone());
        self.by_username.insert(name_key, shared.clone());
        self.by_offline_id.insert(offline_id_for(shared.username.as_str()), shared.clone());
        shared.mark_connected();
        Ok(shared)
    }

    pub fn player_by_id(&self, id: &UUID4) -> Option<UpstreamConnection> {
        self.by_id.get(&id).cloned()
    }

    pub fn player_by_offline_id(&self, id: &UUID4) -> Option<UpstreamConnection> {
        self.by_offline_id.get(&id).cloned()
    }

    pub fn player_by_name(&self, name: &String) -> Option<UpstreamConnection> {
        let lower_name = name.to_lowercase();
        self.by_username.get(&lower_name).cloned()
    }

    pub fn players(&self) -> Vec<UpstreamConnection> {
        self.by_id.values().cloned().collect()
    }
}