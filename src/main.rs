use rustenrich::{
    clock::SystemClock, config::Config, enrichment::Enrichment, http::HttpState, server,
    storage::Storage,
};
use std::{process::ExitCode, sync::Arc};
use tracing_subscriber::{EnvFilter, prelude::*};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            println!(
                "{}",
                serde_json::json!({"level":"ERROR","event":"service_exit_error","message":message})
            );
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let config = Arc::new(Config::from_env().map_err(|error| error.to_string())?);
    // Dependency events stay disabled at every level; their diagnostics can contain URLs.
    let filter = EnvFilter::try_new(format!("off,rustenrich={}", config.log_level))
        .map_err(|_| "Startup failed: invalid logging configuration.")?;
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stdout),
        )
        .try_init()
        .map_err(|_| "Startup failed: logging initialization failed.")?;
    tracing::info!("configuration_validated");
    let clock = Arc::new(SystemClock);
    let storage = Storage::open(&config, clock.clone())
        .await
        .map_err(|_| "Startup failed: persistent storage unavailable, locked, or incompatible.")?;
    tracing::info!("storage_initialized");
    let service = Enrichment::new(config.clone(), storage, clock)
        .map_err(|_| "Startup failed: provider client initialization failed.")?;
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .map_err(|_| "Startup failed: listener unavailable.")?;
    tracing::info!("service_started");
    server::serve(listener, HttpState::new(service), shutdown_signal())
        .await
        .map_err(|_| "Service failed: listener unavailable.".to_owned())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            }
            Err(_) => {
                if tokio::signal::ctrl_c().await.is_err() {
                    tracing::error!("shutdown_signal_unavailable");
                }
            }
        }
    }
    #[cfg(not(unix))]
    if tokio::signal::ctrl_c().await.is_err() {
        tracing::error!("shutdown_signal_unavailable");
    }
}
