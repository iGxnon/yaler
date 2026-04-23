use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(about = "Yaler client — mixed HTTP/SOCKS5 local proxy with Chrome TLS fingerprint")]
struct Args {
    #[arg(short, long, default_value = "client.toml")]
    config: String,
    /// Enable debug logging (overridden by RUST_LOG)
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if args.verbose {
            EnvFilter::new("yaler=debug")
        } else {
            EnvFilter::new("yaler=info")
        }
    });
    fmt().with_env_filter(filter).init();

    let raw = std::fs::read_to_string(&args.config)
        .unwrap_or_else(|_| toml::to_string(&yaler::config::ClientConfig::default()).unwrap());
    let cfg: yaler::config::ClientConfig = toml::from_str(&raw)?;

    yaler::client::run(cfg).await
}
