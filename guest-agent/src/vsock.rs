use crate::metadata::ImageMetadata;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{info, warn, error};

const CONTROL_PORT: u32 = 100;

/// Message sent from guest to host on connection
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GuestMessage {
    #[serde(rename = "handshake")]
    Handshake {
        vm_id: Option<String>, // base32 ID, will be set by host, guest sends None
        metadata: ImageMetadata,
    },
    #[serde(rename = "pong")]
    Pong { timestamp: i64 },
}

/// Message sent from host to guest
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HostMessage {
    #[serde(rename = "ping")]
    Ping { timestamp: i64 },
}

/// Start vsock listener on port 100 and handle connections
pub async fn run_vsock_server(metadata: ImageMetadata) -> Result<()> {
    let addr = VsockAddr::new(VMADDR_CID_ANY, CONTROL_PORT);
    let listener = VsockListener::bind(addr)
        .with_context(|| format!("failed to bind vsock listener on port {}", CONTROL_PORT))?;

    info!("vsock listener started on port {}", CONTROL_PORT);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!("accepted connection from {:?}", peer);
                tokio::spawn(handle_connection(stream, metadata.clone()));
            }
            Err(e) => {
                error!("failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_connection(mut stream: VsockStream, metadata: ImageMetadata) {
    if let Err(e) = handle_connection_inner(&mut stream, metadata).await {
        error!("connection error: {}", e);
    }
}

async fn handle_connection_inner(stream: &mut VsockStream, metadata: ImageMetadata) -> Result<()> {
    // Send handshake message
    let handshake = GuestMessage::Handshake {
        vm_id: None, // Guest doesn't know its VM ID; host will track it
        metadata,
    };
    let msg_json = serde_json::to_vec(&handshake)
        .context("failed to serialize handshake")?;

    stream.write_all(&msg_json).await
        .context("failed to send handshake")?;
    stream.write_all(b"\n").await
        .context("failed to send handshake newline")?;
    stream.flush().await
        .context("failed to flush handshake")?;

    info!("sent handshake message");

    // Read loop for keep-alive pings
    let mut buffer = Vec::new();
    let mut read_buf = [0u8; 4096];

    loop {
        let n = stream.read(&mut read_buf).await
            .context("failed to read from stream")?;

        if n == 0 {
            info!("connection closed by host");
            break;
        }

        buffer.extend_from_slice(&read_buf[..n]);

        // Process complete messages (newline-delimited JSON)
        while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
            let line = buffer.drain(..=pos).collect::<Vec<_>>();
            let line_str = String::from_utf8_lossy(&line[..line.len()-1]);

            match serde_json::from_str::<HostMessage>(&line_str) {
                Ok(HostMessage::Ping { timestamp }) => {
                    info!("received ping at {}", timestamp);
                    let pong = GuestMessage::Pong { timestamp };
                    let pong_json = serde_json::to_vec(&pong)?;
                    stream.write_all(&pong_json).await?;
                    stream.write_all(b"\n").await?;
                    stream.flush().await?;
                }
                Err(e) => {
                    warn!("failed to parse host message: {}", e);
                }
            }
        }
    }

    Ok(())
}
