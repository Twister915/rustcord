use crate::proxy::upstream::UpstreamConnection;
use crate::proxy::util::{Streams, StreamsInner};
use std::sync::Arc;
use mctokio::TcpConnection;
use mcproto_rs::v1_15_2 as proto;
use proto::Packet578 as Packet;
use proto::PlayJoinGameSpec;
use mcproto_rs::types::Chat;
use anyhow::{anyhow, Result};

pub type DownstreamConnection = Arc<DownstreamInner>;

pub struct DownstreamInner {
    pub target_addr: String,
    pub upstream: UpstreamConnection,
    pub streams: Streams,
    pub join_game: PlayJoinGameSpec,
}

#[derive(Debug)]
pub enum DownstreamConnectErr {
    Kicked(Chat),
    OnlineMode,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for DownstreamConnectErr {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

impl From<std::io::Error> for DownstreamConnectErr {
    fn from(err: std::io::Error) -> Self {
        Self::Other(err.into())
    }
}

impl DownstreamInner {
    pub(crate) async fn connect(upstream: UpstreamConnection, to: String)
                                -> Result<DownstreamConnection, DownstreamConnectErr>
    {
        let connection = TcpConnection::connect_to_server(to.clone()).await?;
        let (read, write) = connection.into_split();
        let streams = StreamsInner::create(
            upstream.proxy.clone(),
            format!("downstream to {:?} for {}", to, upstream.username),
            read,
            write,
            proto::State::Handshaking);

        use Packet::{Handshake, LoginStart, LoginSuccess, LoginSetCompression, LoginEncryptionRequest, LoginDisconnect, PlayJoinGame};
        use proto::{HandshakeSpec, HandshakeNextState, LoginStartSpec};

        streams.write_packet(Handshake(HandshakeSpec {
            next_state: HandshakeNextState::Login,
            version: upstream.handshake.version.clone(),
            server_address: [
                upstream.handshake.server_address.clone(),
                upstream.remote_addr.ip().to_string(),
                upstream.id.to_string(),
            ].join("\x00"),
            server_port: upstream.handshake.server_port.clone(),
        })).await?;

        streams.set_state(proto::State::Login).await?;
        streams.write_packet(LoginStart(LoginStartSpec {
            name: upstream.username.clone(),
        })).await?;

        loop {
            let packet = streams.must_read_next_packet().await?;
            match packet {
                LoginSetCompression(spec) => {
                    streams.set_compression_threshold(Some(spec.threshold.0)).await?;
                }
                LoginSuccess(_) => {
                    streams.set_state(proto::State::Play).await?;
                    break;
                }
                LoginEncryptionRequest(_) => {
                    return Err(DownstreamConnectErr::OnlineMode);
                }
                LoginDisconnect(spec) => {
                    return Err(DownstreamConnectErr::Kicked(spec.message));
                }
                other => {
                    return Err(anyhow!("unexpected packet {:?}", other).into());
                }
            }
        }

        let join_game = match streams.must_read_next_packet().await? {
            PlayJoinGame(body) => body,
            other => {
                return Err(anyhow!("unexpected packet {:?}", other).into());
            }
        };

        // register plugin channels
        let out = Arc::new(Self {
            target_addr: to,
            upstream,
            streams,
            join_game,
        });

        out.register_plugin_channels(out
            .upstream
            .plugin_channels
            .lock()
            .await
            .iter()
            .cloned()
            .collect())
            .await?;

        Ok(out)
    }

    pub(crate) async fn register_plugin_channels(self: &DownstreamConnection, channels: Vec<String>) -> Result<()> {
        let new: String = channels.iter()
            .map(move |v| v.as_str())
            .collect::<Vec<_>>()
            .join("\x00");

        use proto::PlayClientPluginMessageSpec;
        let packet = Packet::PlayClientPluginMessage(PlayClientPluginMessageSpec {
            channel: "minecraft:register".to_owned(),
            data: new.into_bytes().into(),
        });

        for chan in channels {
            self.upstream.proxy.logger.info(format_args!(
                "player {} register plugin channel {}",
                self.upstream.username,
                chan
            ))
        }

        self.streams.write_packet(packet).await
    }
}