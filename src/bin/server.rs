use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser)]
#[command(about = "Yaler server — HTTPS/WebSocket tunnel endpoint")]
struct Args {
    /// Path to TOML config file
    #[arg(short, long, default_value = "server.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 requires an explicit crypto provider when multiple providers
    // are present in the dependency tree (ring + aws-lc-rs both get pulled in).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("yaler=info")),
        )
        .init();

    let args = Args::parse();
    let raw = std::fs::read_to_string(&args.config)
        .unwrap_or_else(|_| toml::to_string(&yaler::config::ServerConfig::default()).unwrap());
    let cfg: yaler::config::ServerConfig = toml::from_str(&raw)?;

    yaler::server::run(cfg).await
}
