mod metadata;
mod vsock;

use anyhow::{Context, Result};
use metadata::ImageMetadata;
use tracing::{info, error};
use tokio::signal;

const IMAGE_METADATA_PATH: &str = "/etc/nexus/image.yaml";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    info!("Nexus guest-agent starting");

    // Load image metadata
    let metadata = ImageMetadata::load(IMAGE_METADATA_PATH)
        .context("failed to load image metadata")?;

    info!("loaded image metadata: {:?}", metadata);

    // Start vsock server
    let vsock_task = tokio::spawn(vsock::run_vsock_server(metadata));

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = signal_term() => {
            info!("received SIGTERM, shutting down");
        }
        result = vsock_task => {
            match result {
                Ok(Ok(())) => info!("vsock server exited cleanly"),
                Ok(Err(e)) => error!("vsock server error: {}", e),
                Err(e) => error!("vsock server task panicked: {}", e),
            }
        }
    }

    info!("Nexus guest-agent exiting");
    Ok(())
}

#[cfg(unix)]
async fn signal_term() -> Result<()> {
    signal::unix::signal(signal::unix::SignalKind::terminate())?
        .recv()
        .await;
    Ok(())
}
