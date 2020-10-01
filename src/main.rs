use anyhow::Result;
use crate::proxy::logger::Level;

mod proxy;

#[tokio::main]
async fn main() -> Result<()> {
    let config = proxy::Configuration{
        bind_addresses: vec!("0.0.0.0:25565".to_owned()),
        max_players: 100,
        motd: Some("A Rust Minecraft Proxy".to_owned()),
        servers: vec!(
            proxy::TargetServerSpec{
                name: "lobby".to_owned(),
                address: "127.0.0.1:21000".to_owned(),
                connect_to: true,
                use_motd: false,
            },
        ),
        ping_backends: false,
        encryption: true,
        compression_threshold: Some(256),
        log_level: Level::Trace,
    };

    let mut prox = proxy::Proxy::new(config)?;
    prox.listen_and_serve().await
}
