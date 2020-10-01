#[derive(Clone, Debug)]
pub struct Configuration {
    pub servers: Vec<TargetServerSpec>,
    pub motd: Option<String>,
    pub max_players: u32,
    pub ping_backends: bool,
    pub bind_addresses: Vec<String>,
    pub encryption: bool,
    pub compression_threshold: Option<usize>,
    pub log_level: super::logger::Level,
}

#[derive(Clone, Debug)]
pub struct TargetServerSpec {
    pub address: String,
    pub name: String,
    pub use_motd: bool,
    pub connect_to: bool
}