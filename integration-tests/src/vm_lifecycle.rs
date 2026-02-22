use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const DAEMON_URL: &str = "http://localhost:3030";
const ALPINE_VERSION: &str = "3.23.3";
const GUEST_AGENT_TIMEOUT: Duration = Duration::from_secs(20);
const VM_BOOT_EXPECTED: Duration = Duration::from_millis(150);

#[derive(Debug, Deserialize)]
struct VmResponse {
    id: String,
    state: String,
    pid: Option<u32>,
}

// Guest agent protocol structures (matching vsock_manager.rs)
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum GuestMessage {
    #[serde(rename = "handshake")]
    Handshake {
        vm_id: Option<String>,
        metadata: ImageMetadata,
    },
}

#[derive(Debug, Deserialize)]
struct ImageMetadata {
    image_id: String,
    image_name: String,
    build_id: String,
    built_at: i64,
}

/// Create minimal Alpine VM
pub async fn create_vm(client: &Client) -> Result<String> {
    println!("🔧 Creating minimal Alpine VM...");

    let response = client
        .post(format!("{}/v1/vms/create", DAEMON_URL))
        .json(&json!({
            "name": "integration-test-vm",
            "kernel": {
                "provider": "github",
                "version": "5.10.223"
            },
            "rootfs": {
                "provider": "alpine",
                "version": ALPINE_VERSION,
                "arch": "x86_64"
            },
            "memory_mib": 128,
            "vcpus": 1
        }))
        .send()
        .await
        .context("Failed to create VM")?;

    if !response.status().is_success() {
        bail!("VM creation failed: {}", response.status());
    }

    let vm: VmResponse = response.json().await?;
    println!("  ✓ VM created: {}", vm.id);
    Ok(vm.id)
}

/// Start VM and return PID
pub async fn start_vm(client: &Client, vm_id: &str) -> Result<u32> {
    println!("🚀 Starting VM {}...", vm_id);

    let response = client
        .post(format!("{}/v1/vms/{}/start", DAEMON_URL, vm_id))
        .send()
        .await
        .context("Failed to start VM")?;

    if !response.status().is_success() {
        bail!("VM start failed: {}", response.status());
    }

    // Wait for VM to boot (expected 120-150ms)
    thread::sleep(VM_BOOT_EXPECTED + Duration::from_millis(100));

    // Get VM state to retrieve PID
    let response = client
        .get(format!("{}/v1/vms/{}", DAEMON_URL, vm_id))
        .send()
        .await
        .context("Failed to get VM state")?;

    let vm: VmResponse = response.json().await?;

    let pid = vm.pid.context("VM started but PID is null")?;
    println!("  ✓ VM started with PID: {}", pid);
    Ok(pid)
}

/// Verify Firecracker process is alive and owns expected resources
pub async fn verify_process(pid: u32, vm_id: &str) -> Result<()> {
    println!("🔍 Verifying Firecracker process...");

    // Check 1: PID exists in process table
    let proc_path = PathBuf::from(format!("/proc/{}", pid));
    if !proc_path.exists() {
        bail!("PID {} not found in process table", pid);
    }
    println!("  ✓ PID {} is alive", pid);

    // Check 2: Process is Firecracker (check /proc/PID/exe)
    let exe_path = proc_path.join("exe");
    let exe_target = fs::read_link(&exe_path)
        .context("Failed to read process executable")?;

    // More flexible check: accept if path contains "firecracker" or is in expected directory
    let exe_str = exe_target.to_string_lossy();
    if !exe_str.contains("firecracker") && !exe_str.contains("/assets/firecracker/") {
        bail!("PID {} is not Firecracker: {}", pid, exe_target.display());
    }
    println!("  ✓ Process is Firecracker");

    // Check 3: lsof shows PID owns UDS socket
    let workspace_path = get_vm_workspace_path(vm_id)?;
    let socket_path = workspace_path.join("firecracker.vsock");
    verify_socket_ownership(pid, &socket_path)?;

    // Check 4: UDS responds correctly
    verify_socket_connection(&socket_path).await?;

    Ok(())
}

/// Verify VM reaches "ready" state and vsock communication works
pub async fn verify_vm_ready(client: &Client, vm_id: &str) -> Result<()> {
    println!("🔗 Verifying VM ready state and vsock communication...");

    let start = std::time::Instant::now();

    loop {
        let response = client
            .get(format!("{}/v1/vms/{}", DAEMON_URL, vm_id))
            .send()
            .await?;

        let vm: VmResponse = response.json().await?;

        if vm.state == "ready" {
            println!("  ✓ VM reached ready state");
            break;
        }

        if start.elapsed() > GUEST_AGENT_TIMEOUT {
            bail!("VM did not reach ready state within {} seconds", GUEST_AGENT_TIMEOUT.as_secs());
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Independent vsock verification
    let workspace_path = get_vm_workspace_path(vm_id)?;
    verify_vsock_connection(vm_id, &workspace_path).await?;

    Ok(())
}

/// Verify vsock connection to guest agent
async fn verify_vsock_connection(vm_id: &str, workspace_path: &PathBuf) -> Result<()> {
    println!("🔌 Verifying vsock connection to guest agent...");

    let vsock_path = workspace_path.join("firecracker.vsock");

    let stream = tokio::time::timeout(
        GUEST_AGENT_TIMEOUT,
        UnixStream::connect(&vsock_path)
    )
    .await
    .context("timeout connecting to vsock UDS")?
    .context("failed to connect to vsock UDS")?;

    // Send CONNECT command to vsock CID 100 (guest agent)
    let mut stream = stream;
    stream.write_all(b"CONNECT 100\n").await
        .context("Failed to send CONNECT command")?;
    stream.flush().await?;

    // Read handshake using BufReader (newline-delimited JSON, NOT EOF-delimited)
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();

    tokio::time::timeout(
        GUEST_AGENT_TIMEOUT,
        reader.read_line(&mut line)
    )
    .await
    .context("timeout reading handshake")?
    .context("failed to read handshake line")?;

    // Parse handshake message
    let msg: GuestMessage = serde_json::from_str(&line)
        .context("failed to parse handshake JSON")?;

    match msg {
        GuestMessage::Handshake { metadata, .. } => {
            println!("  ✓ vsock connection verified");
            println!("  ✓ Guest agent responding (image: {})", metadata.image_name);
            Ok(())
        }
    }
}

/// Stop VM and verify cleanup
pub async fn stop_vm(client: &Client, vm_id: &str, expected_pid: u32) -> Result<()> {
    println!("🛑 Stopping VM {}...", vm_id);

    let response = client
        .post(format!("{}/v1/vms/{}/stop", DAEMON_URL, vm_id))
        .send()
        .await
        .context("Failed to stop VM")?;

    if !response.status().is_success() {
        bail!("VM stop failed: {}", response.status());
    }

    // Wait for graceful shutdown
    thread::sleep(Duration::from_secs(2));

    // Verify PID no longer exists
    let proc_path = PathBuf::from(format!("/proc/{}", expected_pid));
    if proc_path.exists() {
        bail!("PID {} still exists after VM stop", expected_pid);
    }
    println!("  ✓ Previous PID {} no longer in process table", expected_pid);

    // Verify PID is null in database
    let response = client
        .get(format!("{}/v1/vms/{}", DAEMON_URL, vm_id))
        .send()
        .await?;

    let vm: VmResponse = response.json().await?;
    if vm.pid.is_some() {
        bail!("VM PID should be null after stop, found: {:?}", vm.pid);
    }
    println!("  ✓ PID null in database");

    Ok(())
}

/// Restart VM and verify new process
pub async fn restart_vm(client: &Client, vm_id: &str, old_pid: u32) -> Result<u32> {
    println!("🔄 Restarting VM {}...", vm_id);

    let new_pid = start_vm(client, vm_id).await?;

    if new_pid == old_pid {
        bail!("New PID {} matches old PID (expected different)", new_pid);
    }
    println!("  ✓ New PID {} (different from old PID {})", new_pid, old_pid);

    // Verify new PID matches database
    let response = client
        .get(format!("{}/v1/vms/{}", DAEMON_URL, vm_id))
        .send()
        .await?;

    let vm: VmResponse = response.json().await?;
    if vm.pid != Some(new_pid) {
        bail!("Database PID {:?} doesn't match new PID {}", vm.pid, new_pid);
    }
    println!("  ✓ New PID matches database");

    Ok(new_pid)
}

// Helper functions

fn get_vm_workspace_path(vm_id: &str) -> Result<PathBuf> {
    let drives_dir = dirs::data_dir()
        .context("Cannot determine XDG_DATA_HOME")?
        .join("nexus")
        .join("drives");

    Ok(drives_dir.join(vm_id))
}

fn verify_socket_ownership(pid: u32, socket_path: &PathBuf) -> Result<()> {
    use std::process::Command;

    let output = Command::new("lsof")
        .arg("-U")
        .arg("-a")
        .arg("-p")
        .arg(pid.to_string())
        .output()
        .context("Failed to execute lsof")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let socket_str = socket_path.to_string_lossy();

    if !stdout.contains(socket_str.as_ref()) {
        bail!("lsof does not show PID {} owns socket {}", pid, socket_str);
    }

    println!("  ✓ lsof confirms PID owns UDS socket");
    Ok(())
}

async fn verify_socket_connection(socket_path: &PathBuf) -> Result<()> {
    tokio::net::UnixStream::connect(socket_path)
        .await
        .context("Failed to connect to UDS socket")?;

    println!("  ✓ UDS socket connection verified");
    Ok(())
}
