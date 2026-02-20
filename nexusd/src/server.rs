// SPDX-License-Identifier: GPL-2.0-only
use crate::api::{self, AppState};
use nexus_lib::config::Config;
use tokio::net::TcpListener;
use tracing::info;
use std::sync::Arc;

pub async fn run(config: &Config, state: Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let app = api::router(state);

    let listener = TcpListener::bind(&config.api.listen).await?;
    info!(listen = %config.api.listen, "HTTP API ready");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("nexusd stopped");
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
        _ = sigint.recv() => info!("received SIGINT, shutting down"),
    }
}
