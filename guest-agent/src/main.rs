use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Nexus guest-agent starting");

    // Placeholder — vsock listener and image metadata will be added in Task 2
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    info!("Nexus guest-agent exiting");
    Ok(())
}
