use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

const DAEMON_URL: &str = "http://localhost:9600";
const VM2_NAME: &str = "integration-test-vm-2";
const DRIVE2_NAME: &str = "integration-test-drive-2";

#[derive(Debug, Deserialize)]
struct McpResult {
    result: Option<McpResultBody>,
    error: Option<McpError>,
}

#[derive(Debug, Deserialize)]
struct McpResultBody {
    content: Vec<McpContent>,
    meta: Option<McpMeta>,
}

#[derive(Debug, Deserialize)]
struct McpContent {
    text: String,
}

#[derive(Debug, Deserialize)]
struct McpMeta {
    #[serde(rename = "exitCode")]
    exit_code: i32,
}

#[derive(Debug, Deserialize)]
struct McpError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct VmResponse {
    id: String,
    state: String,
}

struct RunCommandResult {
    stdout: String,
    exit_code: i32,
}

/// Run a command inside a VM via the MCP JSON-RPC endpoint.
async fn run_vm_command(
    client: &Client,
    vm_name: &str,
    command: &str,
    args: &[&str],
) -> Result<RunCommandResult> {
    let args_json: Vec<serde_json::Value> = args.iter().map(|a| json!(a)).collect();

    let response = client
        .post(format!("{}/mcp", DAEMON_URL))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {
                    "vm": vm_name,
                    "command": command,
                    "args": args_json
                }
            }
        }))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("Failed to send MCP request")?;

    let result: McpResult = response.json().await
        .context("Failed to parse MCP response")?;

    if let Some(err) = result.error {
        bail!("MCP error: {}", err.message);
    }

    let body = result.result.context("Missing result in MCP response")?;
    let stdout = body.content.first()
        .map(|c| c.text.clone())
        .unwrap_or_default();
    let exit_code = body.meta
        .map(|m| m.exit_code)
        .unwrap_or(-1);

    Ok(RunCommandResult { stdout, exit_code })
}

/// Test ICMP connectivity from a VM to an external host.
pub async fn test_external_icmp(client: &Client, vm_name: &str) -> Result<()> {
    println!("🌐 Testing external ICMP connectivity...");

    let result = run_vm_command(client, vm_name, "/bin/ping", &["-c", "2", "-W", "5", "8.8.8.8"]).await?;

    if result.exit_code != 0 {
        bail!("ping failed (exit {}): {}", result.exit_code, result.stdout);
    }

    if !result.stdout.contains("0% packet loss") {
        bail!("Expected 0% packet loss: {}", result.stdout);
    }

    println!("  ✓ ICMP ping to 8.8.8.8 succeeded");
    Ok(())
}

/// Test TCP/HTTP connectivity from a VM to an external host.
pub async fn test_external_tcp(client: &Client, vm_name: &str) -> Result<()> {
    println!("🌐 Testing external TCP connectivity...");

    let result = run_vm_command(
        client, vm_name, "/usr/bin/wget",
        &["-q", "-O", "/dev/null", "--timeout=10", "http://google.com"],
    ).await?;

    if result.exit_code != 0 {
        bail!("wget failed (exit {}): {}", result.exit_code, result.stdout);
    }

    println!("  ✓ HTTP fetch from google.com succeeded");
    Ok(())
}

/// Verify that tap devices have bridge port isolation enabled.
pub fn test_bridge_port_isolation_flag(vm_name: &str) -> Result<()> {
    println!("🔒 Verifying bridge port isolation flags...");

    // Get VM's tap device from the API response config_json
    // Simpler: just check all tap devices on nexbr0
    let output = Command::new("bridge")
        .args(["-d", "link", "show", "master", "nexbr0"])
        .output()
        .context("Failed to run bridge command")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.is_empty() {
        bail!("No devices found on nexbr0 bridge");
    }

    // Every tap device on the bridge should have isolated on
    let mut tap_count = 0;
    for line in stdout.lines() {
        if line.contains("tap") && line.contains("master nexbr0") {
            tap_count += 1;
        }
        if line.contains("isolated off") {
            bail!(
                "Found tap device with isolation disabled for VM {}: {}",
                vm_name,
                line.trim()
            );
        }
    }

    if tap_count == 0 {
        bail!("No tap devices found on nexbr0");
    }

    // Verify isolated on is present
    if !stdout.contains("isolated on") {
        bail!("Bridge port isolation not set on tap devices");
    }

    println!("  ✓ All {} tap device(s) have isolation enabled", tap_count);
    Ok(())
}

/// Create a second VM for isolation testing.
/// Returns (vm_id, drive_id) for cleanup.
pub async fn create_second_vm(client: &Client, master_image_id: &str) -> Result<(String, String)> {
    println!("🔧 Creating second VM for isolation test...");

    // Create drive
    let response = client
        .post(format!("{}/v1/drives", DAEMON_URL))
        .json(&json!({
            "base": master_image_id,
            "name": DRIVE2_NAME
        }))
        .send()
        .await
        .context("Failed to create second drive")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Second drive creation failed: {}", body);
    }

    let drive: serde_json::Value = response.json().await?;
    let drive_id = drive["id"].as_str().context("missing drive id")?.to_string();

    // Create VM
    let response = client
        .post(format!("{}/v1/vms", DAEMON_URL))
        .json(&json!({ "name": VM2_NAME }))
        .send()
        .await
        .context("Failed to create second VM")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Second VM creation failed: {}", body);
    }

    let vm: VmResponse = response.json().await?;

    // Attach drive
    let response = client
        .post(format!("{}/v1/drives/{}/attach", DAEMON_URL, drive_id))
        .json(&json!({
            "vm_id": vm.id,
            "is_root_device": true
        }))
        .send()
        .await
        .context("Failed to attach second drive")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Second drive attach failed: {}", body);
    }

    // Start VM
    let response = client
        .post(format!("{}/v1/vms/{}/start", DAEMON_URL, vm.id))
        .send()
        .await
        .context("Failed to start second VM")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Second VM start failed: {}", body);
    }

    // Wait for ready
    let start = std::time::Instant::now();
    loop {
        let response = client
            .get(format!("{}/v1/vms/{}", DAEMON_URL, vm.id))
            .send()
            .await?;
        let state: VmResponse = response.json().await?;

        if state.state == "ready" {
            break;
        }
        if start.elapsed() > Duration::from_secs(20) {
            bail!("Second VM did not reach ready state within 20s");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!("  ✓ Second VM created and ready: {}", vm.id);
    Ok((vm.id, drive_id))
}

/// Test that two VMs cannot communicate with each other (bridge port isolation).
pub async fn test_vm_isolation(client: &Client, vm1_name: &str, vm2_name: &str) -> Result<()> {
    println!("🔒 Testing VM-to-VM isolation...");

    // Get VM2's IP from its boot args (config_json contains the IP)
    let response = client
        .get(format!("{}/v1/vms/{}", DAEMON_URL, vm2_name))
        .send()
        .await?;

    let vm2: serde_json::Value = response.json().await?;
    let config_json: String = vm2["config_json"].as_str()
        .context("missing config_json")?.to_string();
    let config: serde_json::Value = serde_json::from_str(&config_json)?;
    let boot_args = config["boot-source"]["boot_args"].as_str()
        .context("missing boot_args")?;

    // Extract IP from boot args: "... ip=172.16.0.X::172.16.0.1:..."
    let ip = boot_args.split("ip=").nth(1)
        .and_then(|s| s.split("::").next())
        .context("Failed to extract VM2 IP from boot args")?;

    println!("  → VM2 IP: {}", ip);

    // Ping VM2 from VM1 — should fail
    let result = run_vm_command(client, vm1_name, "/bin/ping", &["-c", "2", "-W", "3", ip]).await?;

    if result.exit_code == 0 {
        bail!("VM isolation FAILED: VM1 can reach VM2 at {}", ip);
    }

    if !result.stdout.contains("100% packet loss") {
        bail!("Expected 100% packet loss, got: {}", result.stdout);
    }

    // Also test reverse direction
    let response = client
        .get(format!("{}/v1/vms/{}", DAEMON_URL, vm1_name))
        .send()
        .await?;
    let vm1: serde_json::Value = response.json().await?;
    let config1_json: String = vm1["config_json"].as_str()
        .context("missing config_json")?.to_string();
    let config1: serde_json::Value = serde_json::from_str(&config1_json)?;
    let boot_args1 = config1["boot-source"]["boot_args"].as_str()
        .context("missing boot_args")?;
    let ip1 = boot_args1.split("ip=").nth(1)
        .and_then(|s| s.split("::").next())
        .context("Failed to extract VM1 IP from boot args")?;

    let result = run_vm_command(client, vm2_name, "/bin/ping", &["-c", "2", "-W", "3", ip1]).await?;

    if result.exit_code == 0 {
        bail!("VM isolation FAILED (reverse): VM2 can reach VM1 at {}", ip1);
    }

    println!("  ✓ VM1 cannot reach VM2 (100% packet loss)");
    println!("  ✓ VM2 cannot reach VM1 (100% packet loss)");
    Ok(())
}

/// Stop the second VM.
pub async fn stop_second_vm(client: &Client, vm_id: &str) -> Result<()> {
    let response = client
        .post(format!("{}/v1/vms/{}/stop", DAEMON_URL, vm_id))
        .send()
        .await
        .context("Failed to stop second VM")?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Second VM stop failed: {}", body);
    }

    println!("  ✓ Second VM stopped");
    Ok(())
}

/// Test the cleanup-network admin endpoint.
pub async fn test_cleanup_network(client: &Client) -> Result<()> {
    println!("🧹 Testing network cleanup endpoint...");

    let response = client
        .post(format!("{}/v1/admin/cleanup-network", DAEMON_URL))
        .send()
        .await
        .context("Failed to call cleanup-network")?;

    if !response.status().is_success() {
        bail!("Cleanup network failed: {}", response.status());
    }

    let report: serde_json::Value = response.json().await?;

    let taps = report["taps_deleted"].as_u64().unwrap_or(0);
    let bridge = report["bridge_deleted"].as_bool().unwrap_or(false);
    let nftables = report["nftables_flushed"].as_bool().unwrap_or(false);

    println!("  ✓ Cleanup report: {} taps deleted, bridge={}, nftables={}", taps, bridge, nftables);

    if !bridge {
        bail!("Bridge was not deleted by cleanup");
    }
    if !nftables {
        bail!("nftables were not flushed by cleanup");
    }

    Ok(())
}
