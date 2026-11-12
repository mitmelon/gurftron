//! Manomite Loader: one binary, many local models, one HTTP API.

mod api;
mod config;
mod engines;
mod errors;
mod metrics;
mod registry;
#[cfg(feature = "onnx")]
mod tokenizer;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

const HELP: &str = "manomite-loader 0.1.0

USAGE:
    manomite-loader [--server server.toml] [--models models.toml]

ENV:
    MANOMITE_HOST, MANOMITE_PORT   override server.host / server.port
    RUST_LOG                       override server.log_level
";

struct Args {
    server: PathBuf,
    models: PathBuf,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        server: "server.toml".into(),
        models: "models.toml".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--server" => args.server = it.next().context("--server needs a path")?.into(),
            "--models" => args.models = it.next().context("--models needs a path")?.into(),
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument '{other}'\n\n{HELP}"),
        }
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let cfg = config::load(&args.server, &args.models)?;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(cfg.server.log_level.clone()));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(false)
        .init();

    #[cfg(feature = "gguf")]
    llama_cpp_2::send_logs_to_tracing(llama_cpp_2::LogOptions::default());

    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .with_context(|| format!("bad host/port: {}:{}", cfg.server.host, cfg.server.port))?;
    if !addr.ip().is_loopback() {
        tracing::warn!(%addr, "listening beyond localhost: there is no authentication in v0.1");
    }

    let model_count = cfg.models.len();
    let registry = registry::Registry::new(cfg);

    // Free the GGUF model after it has been idle for a while.
    let sweeper = registry.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            sweeper.sweep_idle();
        }
    });

    let app = api::router(registry);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("could not bind {addr}"))?;
    tracing::info!(%addr, models = model_count, "manomite-loader ready, no model loaded yet");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;
    Ok(())
}
