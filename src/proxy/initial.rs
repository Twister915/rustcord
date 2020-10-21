use mcproto_rs::{v1_15_2 as proto, types::{Chat, VarInt}, protocol::State};
use proto::Packet578 as Packet;

use crate::proxy::util::Streams;
use crate::proxy::proxy::Proxy;
use crate::proxy::auth;

use std::net::SocketAddr;
use anyhow::{Result, anyhow};
use rand::Rng;
use crate::proxy::auth::HasJoinedResponse;
use mcproto_rs::uuid::UUID4;
use crate::proxy::upstream::UpstreamInner;

pub struct InitialUpstreamHandler {
    pub proxy: Proxy,
    pub streams: Streams,
    pub remote: SocketAddr,
    pub handshake: Option<proto::HandshakeSpec>,
}

impl InitialUpstreamHandler {
    pub fn spawn_handle(self) {
        tokio::spawn(async move {
            let logger = self.proxy.logger.clone();
            if let Err(err) = self.handle().await {
                logger.error(format_args!("error in initial handler :: {:?}", err));
            }
        });
    }

    async fn handle(mut self) -> Result<()> {
        self.proxy.logger.debug(format_args!("initial connection from {}", self.remote));
        use Packet::Handshake;
        let handshake = match self.streams.must_read_next_packet().await? {
            Handshake(body) => body,
            other => {
                return Err(anyhow!("unexpected packet {:?}", other));
            }
        };
        let next_state = handshake.next_state.clone();
        self.handshake = Some(handshake);
        use proto::HandshakeNextState::*;
        match next_state {
            Login => self.handle_login().await,
            Status => self.handle_status().await,
        }
    }

    async fn handle_status(self) -> Result<()> {
        self.streams.set_state(State::Status).await?;
        self.proxy.logger.debug(format_args!("serving status to {}", self.remote));

        use Packet::{StatusRequest, StatusResponse, StatusPing, StatusPong};
        use proto::{StatusResponseSpec, StatusPongSpec};
        use mcproto_rs::status::*;

        match self.streams.must_read_next_packet().await? {
            StatusRequest(_) => {}
            other => {
                return Err(anyhow!("unexpected packet {:?}", other));
            }
        }

        // create status
        let response = {
            let players = self.proxy.player_list().await;
            let config = &self.proxy.config;
            StatusSpec {
                players: StatusPlayersSpec {
                    max: config.max_players as i32,
                    online: players.len() as i32,
                    sample: players.iter()
                        .map(move |player| StatusPlayerSampleSpec {
                            id: player.id.clone(),
                            name: player.username.clone(),
                        })
                        .take(5)
                        .collect(),
                },
                description: Chat::from_traditional(
                    config.motd
                        .clone()
                        .unwrap_or("A Rust Minecraft Proxy".to_owned())
                        .as_str(),true),
                favicon: self.proxy.favicon.as_ref().map(move |data| StatusFaviconSpec {
                    content_type: "image/png".to_owned(),
                    data: data.clone(),
                }),
                version: StatusVersionSpec {
                    name: "mcprox-rs 1.15.2".to_owned(),
                    protocol: 578,
                }
            }
        };

        self.streams.write_packet(StatusResponse(StatusResponseSpec { response })).await?;
        if let Some(packet) = self.streams.read_next_packet().await? {
            match packet {
                StatusPing(body) => {
                    self.streams.write_packet(StatusPong(StatusPongSpec{ payload: body.payload })).await?;
                },
                other => {
                    return Err(anyhow!("unexpected packet {:?}", other));
                }
            }
        }

        self.proxy.logger.debug(format_args!("status complete for {}, shutting down serve", self.remote));
        Ok(())
    }

    async fn handle_login(mut self) -> Result<()> {
        use Packet::{LoginStart, LoginEncryptionRequest, LoginEncryptionResponse, LoginSetCompression, LoginSuccess, LoginDisconnect};
        use proto::{LoginEncryptionRequestSpec, LoginSetCompressionSpec, LoginSuccessSpec, LoginDisconnectSpec};
        use State::{Login, Play};

        self.streams.set_state(Login).await?;
        self.proxy.logger.debug(format_args!("serving login to {}", self.remote));

        let login_start = match self.streams.must_read_next_packet().await? {
            LoginStart(body) => body,
            other => {
                return Err(anyhow!("unexpected packet {:?}", other));
            }
        };

        self.proxy.logger.info(format_args!("start login for {} from {}", login_start.name, self.remote));

        let join_response = if self.proxy.config.encryption {
            let correct_verify_token = random_verify_token();
            let public_key_bytes = self.proxy.rsa_pubkey_asn1();
            let server_id: String = [' '; 20].iter().collect();

            self.streams.write_packet(LoginEncryptionRequest(LoginEncryptionRequestSpec{
                verify_token: correct_verify_token.clone().into(),
                public_key: public_key_bytes.clone().into(),
                server_id: server_id.clone(),
            })).await?;

            let response = match self.streams.read_next_packet().await? {
                Some(next) => {
                    match next {
                        LoginEncryptionResponse(body) => body,
                        other => {
                            return Err(anyhow!("unexpected packet {:?}", other));
                        }
                    }
                }
                None => {
                    // client aborted because of bad session
                    self.proxy.logger.info(format_args!("client {} aborted login", login_start.name));
                    return Ok(());
                }
            };

            let verify_token_from_client = self.proxy.decrypt_token(
                response.verify_token.as_slice())?;

            if verify_token_from_client != correct_verify_token {
                self.streams.write_packet(LoginDisconnect(LoginDisconnectSpec{
                    message: Chat::from_traditional("&cEncryption Failure!", true)
                })).await?;
                return Err(anyhow!("got unexpected verify token {:?} != {:?}",
                    correct_verify_token, verify_token_from_client));
            }

            let shared_secret = self.proxy.decrypt_token(
                response.shared_secret.as_slice())?;

            self.proxy.logger.info(format_args!("setup session with mojang for {} from {}", login_start.name, self.remote));
            let ip = self.remote.ip().to_string();
            let http_client = reqwest::Client::default();
            let has_joined = auth::HasJoinedRequest {
                username: login_start.name.clone(),
                ip,
                hash: auth::ServerHashComponents {
                    shared_secret: shared_secret.clone(),
                    server_id,
                    public_key: public_key_bytes,
                }
            }.send(&http_client).await?;
            self.streams.enable_encryption(shared_secret.as_slice(), shared_secret.as_slice()).await?;
            has_joined
        } else {
            self.proxy.logger.info(format_args!("login offline mode for {} from {}", login_start.name, self.remote));
            HasJoinedResponse {
                name: login_start.name.clone(),
                id: UUID4::random(),
                properties: vec![],
            }
        };

        if let Some(threshold) = self.proxy.config.compression_threshold.as_ref() {
            let threshold = (*threshold) as i32;
            self.proxy.logger.debug(format_args!("enable compression for {} from {} with threshold={}", login_start.name, self.remote, threshold));
            self.streams.write_packet(LoginSetCompression(LoginSetCompressionSpec{
                threshold: VarInt(threshold),
            })).await?;
            self.streams.set_compression_threshold(Some(threshold)).await?;
        }

        self.streams.write_packet(LoginSuccess(LoginSuccessSpec{
            username: join_response.name.clone(),
            uuid_string: join_response.id.hex(),
        })).await?;

        self.proxy.logger.info(format_args!(
            "{} (now {}) from {} has logged in with ID {}",
            login_start.name, join_response.name, self.remote, join_response.id));

        self.streams.set_state(Play).await?;

        let proxy = self.proxy;
        let upstream_inner = UpstreamInner::create(
            self.streams,
            proxy.clone(),
            join_response.name,
            join_response.id,
            self.remote,
            join_response.properties,
            self.handshake.take().expect("present by this phase"),
        );

        let upstream = proxy.has_joined(upstream_inner).await?;
        if let Err(err) = tokio::spawn({
            let upstream = upstream.clone();
            async move {
                upstream.serve().await;
            }
        }).await {
            upstream.proxy.logger.error(format_args!(
                "failure while handling upstream conn from {} for {} :: {:?}",
                upstream.remote_addr.ip(),
                upstream.username,
                err));

            upstream.take_streams_disconnect().await;
        }
        Ok(())
    }
}

fn random_verify_token() -> Vec<u8> {
    const SIZE: usize = 4;
    let mut out = vec![0u8; SIZE];
    let mut rng = rand::thread_rng();
    for x in out.iter_mut() {
        *x = rng.gen();
    }

    out
}