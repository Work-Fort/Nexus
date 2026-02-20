use crate::store::traits::StateStore;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{info, warn, error};

const CONTROL_PORT: u32 = 100;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Image metadata received from guest-agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMetadata {
    pub image_id: String,      // base32 ID (13 chars, a-z, 2-7)
    pub image_name: String,
    pub build_id: String,       // base32 ID (13 chars, a-z, 2-7)
    pub built_at: i64,
}

/// Message from guest to host
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum GuestMessage {
    #[serde(rename = "handshake")]
    Handshake {
        vm_id: Option<String>, // base32 ID, guest sends None
        metadata: ImageMetadata,
    },
    #[serde(rename = "pong")]
    Pong { timestamp: i64 },
}

/// Message from host to guest
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum HostMessage {
    #[serde(rename = "ping")]
    Ping { timestamp: i64 },
}

/// Manages vsock connections to guest agents
pub struct VsockManager {
    store: Arc<dyn StateStore + Send + Sync>,
    connections: Arc<Mutex<HashMap<crate::id::Id, VsockConnection>>>,
}

struct VsockConnection {
    stream: UnixStream,
    metadata: Option<ImageMetadata>,
}

impl VsockManager {
    pub fn new(store: Arc<dyn StateStore + Send + Sync>) -> Self {
        Self {
            store,
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Connect to guest-agent via vsock and wait for handshake
    pub async fn connect_and_handshake(&self, vm_id: crate::id::Id, uds_path: PathBuf) -> Result<ImageMetadata> {
        let vsock_path = uds_path.join("firecracker.vsock");

        // Connect to Firecracker vsock UDS
        let stream = timeout(DEFAULT_CONNECT_TIMEOUT, UnixStream::connect(&vsock_path))
            .await
            .context("timeout connecting to vsock UDS")?
            .with_context(|| format!("failed to connect to vsock UDS at {}", vsock_path.display()))?;

        // Send CONNECT command to Firecracker
        let mut stream = self.firecracker_vsock_connect(stream, CONTROL_PORT).await?;

        // Read handshake message (newline-delimited JSON)
        let handshake = timeout(DEFAULT_CONNECT_TIMEOUT, self.read_handshake(&mut stream))
            .await
            .context("timeout waiting for guest handshake")?
            .context("failed to read handshake")?;

        info!("received handshake from VM {}: {:?}", vm_id, handshake);

        // Store connection
        let connection = VsockConnection {
            stream,
            metadata: Some(handshake.clone()),
        };
        self.connections.lock().await.insert(vm_id, connection);

        // Update VM state to ready
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            store.update_vm_state(vm_id, "ready", Some("guest-agent connected"))
        })
        .await
        .context("task panicked")?
        .context("failed to update VM state to ready")?;

        let store = self.store.clone();
        let timestamp = chrono::Utc::now().timestamp();
        tokio::task::spawn_blocking(move || {
            store.set_vm_agent_connected_at(vm_id, timestamp)
        })
        .await
        .context("task panicked")?
        .context("failed to set agent_connected_at timestamp")?;

        Ok(handshake)
    }

    /// Send CONNECT command via Firecracker vsock UDS protocol
    async fn firecracker_vsock_connect(&self, mut stream: UnixStream, port: u32) -> Result<UnixStream> {
        let connect_cmd = format!("CONNECT {}\n", port);
        stream.write_all(connect_cmd.as_bytes()).await
            .context("failed to send CONNECT command")?;
        stream.flush().await
            .context("failed to flush CONNECT command")?;

        info!("sent CONNECT {} to Firecracker vsock", port);

        // Firecracker doesn't send a response to CONNECT; connection is ready immediately
        Ok(stream)
    }

    /// Read handshake message from guest
    async fn read_handshake(&self, stream: &mut UnixStream) -> Result<ImageMetadata> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        reader.read_line(&mut line).await
            .context("failed to read handshake line")?;

        let msg: GuestMessage = serde_json::from_str(&line)
            .context("failed to parse handshake JSON")?;

        match msg {
            GuestMessage::Handshake { metadata, .. } => Ok(metadata),
            _ => anyhow::bail!("expected handshake message, got {:?}", msg),
        }
    }

    /// Start background task to monitor running VMs and detect unreachable agents
    pub fn start_monitor_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if let Err(e) = self.check_unreachable_vms().await {
                    error!("error checking unreachable VMs: {}", e);
                }
            }
        });
    }

    async fn check_unreachable_vms(&self) -> Result<()> {
        let store = self.store.clone();
        let running_vms = tokio::task::spawn_blocking(move || {
            store.list_vms_by_state("running")
        })
        .await
        .context("task panicked")?
        .context("failed to list running VMs")?;

        let now = chrono::Utc::now().timestamp();

        // Get timeout from settings table (default 20 seconds)
        let store = self.store.clone();
        let timeout_secs = tokio::task::spawn_blocking(move || {
            store.get_setting("agent_ready_timeout")
        })
        .await
        .context("task panicked")?
        .unwrap_or_else(|_| Some("20".to_string()))
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(20);

        for vm in running_vms {
            let elapsed = now - vm.started_at.unwrap_or(now);
            if elapsed > timeout_secs {
                warn!("VM {} unreachable: agent did not connect within {} seconds", vm.id, timeout_secs);
                let store = self.store.clone();
                let vm_id = vm.id;
                tokio::task::spawn_blocking(move || {
                    store.update_vm_state(vm_id, "unreachable", Some("agent connection timeout"))
                })
                .await
                .context("task panicked")?
                .context("failed to update VM state to unreachable")?;
            }
        }

        Ok(())
    }

    /// Close connection for a VM (called on VM stop/crash)
    pub async fn close_connection(&self, vm_id: crate::id::Id) {
        self.connections.lock().await.remove(&vm_id);
    }
}
