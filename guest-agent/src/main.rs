mod env;
mod metadata;
mod vsock;
mod mcp;

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

    // Start vsock control server (port 100)
    let control_task = tokio::spawn(vsock::run_vsock_server(metadata));

    // Start MCP server (port 200)
    let mcp_task = tokio::spawn(mcp::run_mcp_server());

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = signal_term() => {
            info!("received SIGTERM, shutting down");
        }
        result = control_task => {
            match result {
                Ok(Ok(())) => info!("control server exited cleanly"),
                Ok(Err(e)) => error!("control server error: {}", e),
                Err(e) => error!("control server task panicked: {}", e),
            }
        }
        result = mcp_task => {
            match result {
                Ok(Ok(())) => info!("MCP server exited cleanly"),
                Ok(Err(e)) => error!("MCP server error: {}", e),
                Err(e) => error!("MCP server task panicked: {}", e),
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
