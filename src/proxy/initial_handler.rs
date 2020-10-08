use super::{session, Proxy};

use crate::proxy::proxy::{AddPlayerStatus, Player};
use crate::proxy::session::HasJoinedResponse;
use crate::proxy::UnexpectedPacketErr;
use anyhow::Result;
use mcproto_rs::types::VarInt;
use mcproto_rs::uuid::UUID4;
use mcproto_rs::v1_15_2::Packet578::PlayDisconnect;
use mcproto_rs::v1_15_2::{HandshakeSpec, LoginStartSpec, Packet578 as Packet, PlayDisconnectSpec};
use rand::Rng;
use tokio::task::JoinHandle;
use crate::proxy::bridge::TcpBridge;

pub struct InitialUpstreamHandler {
    proxy: Proxy,
    connection: Option<TcpBridge>,
    handshake: Option<HandshakeSpec>,
    login_start: Option<LoginStartSpec>,
    join_response: Option<HasJoinedResponse>,
}

impl InitialUpstreamHandler {
    pub fn new(connection: TcpBridge, proxy: Proxy) -> Self {
        Self {
            proxy,
            connection: Some(connection),
            handshake: None,
            login_start: None,
            join_response: None,
        }
    }

    pub fn spawn_handler(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let result = self.do_initial_handle().await;
            match result {
                Ok(Some(player)) => match player.connect_to_initial_downstream().await {
                    Ok(()) => {}
                    Err(err) => self.proxy.logger().warning(format_args!(
                        "error with connected player {} :: {}",
                        self.get_name(),
                        err
                    )),
                },
                Err(err) => {
                    self.proxy.logger().warning(format_args!(
                        "for {} failed to handle connection :: {:?}",
                        self.get_name(),
                        err
                    ));
                }
                _ => {}
            }
        })
    }

    async fn do_initial_handle(&mut self) -> Result<Option<Player>> {
        use Packet::Handshake;
        let packet = self.connection.as_mut()
            .expect("need connection")
            .must_read_packet()
            .await?
            .deserialize()?;
        match packet
        {
            Handshake(spec) => {
                self.proxy.logger().debug(format_args!("upstream connection got handshake {:?}", spec));
                let next_state = spec.next_state.clone();
                self.handshake = Some(spec);

                use mcproto_rs::v1_15_2::HandshakeNextState::*;
                match next_state {
                    Login => self.handle_login().await,
                    Status => {
                        self.handle_status().await?;
                        Ok(None)
                    }
                }
            }
            packet => {
                return Err(UnexpectedPacketErr { packet }.into());
            }
        }
    }

    async fn handle_status(&mut self) -> Result<()> {
        use mcproto_rs::status::*;
        use mcproto_rs::types::Chat;
        use mcproto_rs::v1_15_2::{
            State::Status, StatusPingSpec, StatusPongSpec, StatusResponseSpec,
        };
        use Packet::{StatusPing, StatusPong, StatusRequest, StatusResponse};

        let mut connection = self
            .connection
            .take()
            .expect("connection should always be present");

        connection.set_state(Status);

        // get status request
        match connection.must_read_packet().await?.deserialize()? {
            StatusRequest(_) => (),
            packet => {
                return Err(UnexpectedPacketErr { packet }.into());
            }
        };

        self.proxy.logger().info(format_args!("handling status, got request"));

        // prepare status response
        let response = {
            let players = self.proxy.players().await;
            let config = self.proxy.config();
            StatusSpec {
                players: StatusPlayersSpec {
                    online: players.len() as i32,
                    max: config.max_players as i32,
                    sample: players
                        .iter()
                        .map(move |player| StatusPlayerSampleSpec {
                            id: player.id.clone(),
                            name: player.username.clone(),
                        })
                        .take(5)
                        .collect(),
                },
                description: Chat::from_text(
                    config
                        .motd
                        .clone()
                        .unwrap_or("A Rust Minecraft Proxy".to_owned())
                        .as_str(),
                ),
                favicon: None,
                version: StatusVersionSpec {
                    name: "mcprox-rs 1.15.2".to_owned(),
                    protocol: 578,
                },
            }
        };

        connection
            .write_packet(StatusResponse(StatusResponseSpec { response }))
            .await?;

        let StatusPingSpec { payload } = {
            match connection.read_packet().await? {
                Some(mut packet) => match packet.deserialize()? {
                    StatusPing(ping) => ping,
                    packet => {
                        return Err(UnexpectedPacketErr { packet }.into());
                    }
                },
                None => {
                    return Ok(());
                }
            }
        };

        connection
            .write_packet(StatusPong(StatusPongSpec { payload }))
            .await
    }

    async fn handle_login(&mut self) -> Result<Option<Player>> {
        use mcproto_rs::types::Chat;
        use mcproto_rs::v1_15_2::{
            LoginDisconnectSpec, LoginEncryptionRequestSpec, LoginSetCompressionSpec,
            LoginSuccessSpec,
            State::{Login, Play},
        };
        use Packet::{
            LoginDisconnect, LoginEncryptionRequest, LoginEncryptionResponse, LoginSetCompression,
            LoginStart, LoginSuccess,
        };

        let mut connection = self
            .connection
            .take()
            .expect("connection should always be present");

        connection.set_state(Login);
        let login_start = match connection.must_read_packet().await?.deserialize()? {
            LoginStart(spec) => spec,
            packet => {
                return Err(UnexpectedPacketErr { packet }.into());
            }
        };
        self.login_start = Some(login_start.clone());

        let join_response = if self.proxy.config().encryption {
            let correct_verify_token = random_verify_token();
            let public_key_bytes = self.proxy.rsa_pubkey_asn1();
            let server_id: String = [' '; 20].iter().collect();
            connection
                .write_packet(LoginEncryptionRequest(LoginEncryptionRequestSpec {
                    public_key: public_key_bytes.clone().into(),
                    server_id: server_id.clone(),
                    verify_token: correct_verify_token.clone().into(),
                }))
                .await?;

            let response = match connection.must_read_packet().await?.deserialize()? {
                LoginEncryptionResponse(spec) => spec,
                packet => {
                    return Err(UnexpectedPacketErr { packet }.into());
                }
            };
            let verify_token_from_client = self
                .proxy
                .decrypt_token(response.verify_token.data.as_slice())?;
            if verify_token_from_client != correct_verify_token {
                connection
                    .write_packet(LoginDisconnect(LoginDisconnectSpec {
                        message: Chat::from_text("error: bad verify token"),
                    }))
                    .await?;

                return Ok(None);
            }
            let shared_secret = self
                .proxy
                .decrypt_token(response.shared_secret.data.as_slice())?;
            let ip = connection.remote_addr().ip().to_string();
            let http_client = reqwest::Client::default();

            let has_joined = session::HasJoinedRequest {
                username: login_start.name,
                ip,
                hash: session::ServerHashComponents {
                    shared_secret: shared_secret.clone(),
                    server_id,
                    public_key: public_key_bytes,
                },
            }
            .send(&http_client)
            .await?;

            connection.enable_encryption(shared_secret.as_slice(), shared_secret.as_slice())?;
            has_joined
        } else {
            HasJoinedResponse {
                name: login_start.name,
                id: UUID4::random(),
                properties: vec![],
            }
        };

        self.join_response = Some(join_response.clone());

        let logger = self.proxy.logger();
        logger.info(format_args!(
            "{}/{} joined",
            join_response.name,
            join_response.id.hex()
        ));

        if let Some(threshold) = self.proxy.config().compression_threshold.as_ref() {
            let threshold = *threshold;
            connection.write_packet(LoginSetCompression(LoginSetCompressionSpec {
                    threshold: VarInt(threshold as i32),
                }))
                .await?;
            connection.set_compression_threshold(threshold);
        }

        connection.write_packet(LoginSuccess(LoginSuccessSpec {
                username: join_response.name.clone(),
                uuid_string: join_response.id.hex(),
            }))
            .await?;

        connection.set_state(Play);

        let add_result = self
            .proxy
            .add_new_player(
                connection,
                self.handshake.take().expect("has handshake"),
                self.join_response.take().expect("has join response"),
            )
            .await;

        match add_result {
            AddPlayerStatus::ConflictId(mut connection, id) => {
                logger.warning(format_args!("conflict on player id {}", id));

                connection
                    .write_packet(PlayDisconnect(PlayDisconnectSpec {
                        reason: Chat::from_text("you have already joined this server!"),
                    }))
                    .await?;
                Ok(None)
            }
            AddPlayerStatus::ConflictName(mut connection, name) => {
                logger.warning(format_args!("conflict on player name {}", name));

                connection
                    .write_packet(PlayDisconnect(PlayDisconnectSpec {
                        reason: Chat::from_text("your username is already in use!"),
                    }))
                    .await?;

                Ok(None)
            }
            AddPlayerStatus::Added(player) => Ok(Some(player)),
        }
    }

    fn get_name(&self) -> String {
        if let Some(join_response) = self.join_response.as_ref() {
            join_response.name.clone()
        } else if let Some(login_start) = self.login_start.as_ref() {
            login_start.name.clone()
        } else if let Some(connection) = self.connection.as_ref() {
            connection.remote_addr().to_string()
        } else {
            "unknown player".to_owned()
        }
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
