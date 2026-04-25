use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use stalin::{Config, proxy::ProxyServer};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[arg(short, long, env = "STALIN_CONFIG", default_value = "stalin.yml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let config = Config::from_path(&args.config)
        .with_context(|| format!("failed to load config {}", args.config.display()))?;
    ProxyServer::new(config).serve().await
}
