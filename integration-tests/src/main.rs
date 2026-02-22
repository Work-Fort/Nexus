use anyhow::{Context, Result};
use integration_tests::{prerequisites, smoke_test, vm_lifecycle};
use std::process::Command;
use std::thread;
use std::time::Duration;

const SUCCESS_EXIT: i32 = 0;
const FAILURE_EXIT: i32 = 1;
// DNF_EXIT defined in prerequisites module

#[tokio::main]
async fn main() {
    let result = run_integration_tests().await;

    match result {
        Ok(_) => {
            println!("\n✅ All integration tests passed!");
            std::process::exit(SUCCESS_EXIT);
        }
        Err(e) => {
            eprintln!("\n❌ Integration test failed: {:#}", e);
            std::process::exit(FAILURE_EXIT);
        }
    }
}

async fn run_integration_tests() -> Result<()> {
    println!("🧪 Nexus Integration Test Suite");
    println!("================================\n");

    // Step 1: Check prerequisites
    prerequisites::check_all()?;
    println!();

    // Step 2: Clean environment
    clean_environment()?;
    println!();

    // Step 3: Start daemon (direct execution, not systemd)
    let mut daemon_handle = start_daemon()?;
    println!();

    // Step 4: Verify clean state
    smoke_test::verify_clean_state()?;
    println!();

    // Step 5: Execute real downloads
    smoke_test::execute_downloads().await?;
    println!();

    // Step 6: Verify downloads present
    smoke_test::verify_downloads_present()?;
    println!();

    // Step 7: Create minimal VM
    let client = reqwest::Client::new();
    let vm_id = vm_lifecycle::create_vm(&client).await?;
    println!();

    // Step 8: Start VM and verify (comprehensive checks)
    let pid1 = vm_lifecycle::start_vm(&client, &vm_id).await?;
    vm_lifecycle::verify_process(pid1, &vm_id).await?;
    vm_lifecycle::verify_vm_ready(&client, &vm_id).await?;
    println!();

    // Step 9: Stop VM and verify cleanup
    vm_lifecycle::stop_vm(&client, &vm_id, pid1).await?;
    println!();

    // Step 10: Restart VM and verify new process
    let pid2 = vm_lifecycle::restart_vm(&client, &vm_id, pid1).await?;
    vm_lifecycle::verify_process(pid2, &vm_id).await?;
    vm_lifecycle::verify_vm_ready(&client, &vm_id).await?;
    println!();

    // Step 11: Final cleanup
    vm_lifecycle::stop_vm(&client, &vm_id, pid2).await?;

    // Step 12: Stop daemon
    println!("🛑 Stopping daemon...");
    daemon_handle.kill().context("Failed to stop daemon")?;
    daemon_handle.wait().context("Failed to wait for daemon")?;
    println!("  ✓ Daemon stopped");

    Ok(())
}

fn clean_environment() -> Result<()> {
    println!("🧹 Cleaning Nexus environment...");

    let output = Command::new("mise")
        .arg("run")
        .arg("clean")
        .current_dir(std::env::var("HOME")? + "/Work/WorkFort/nexus")
        .output()
        .context("Failed to run mise clean")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("mise clean failed: {}", stderr);
    }

    println!("  ✓ Environment cleaned");
    Ok(())
}

fn start_daemon() -> Result<std::process::Child> {
    println!("🚀 Starting nexusd daemon (direct execution)...");

    // Find nexusd binary (prefer CARGO_BIN_EXE if set, otherwise use mise)
    let nexusd_bin = if let Ok(bin) = std::env::var("CARGO_BIN_EXE_nexusd") {
        bin
    } else {
        // Use mise to find binary
        let home = std::env::var("HOME")?;
        format!("{}/Work/WorkFort/nexus/target/debug/nexusd", home)
    };

    // Start daemon in background (direct execution, not systemd)
    let daemon_handle = Command::new(&nexusd_bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to start nexusd daemon")?;

    // Wait for daemon to be ready (poll health endpoint or wait fixed time)
    println!("  → Waiting for daemon to be ready...");
    thread::sleep(Duration::from_secs(3));

    // TODO: Could add health endpoint polling here for more robust startup verification

    println!("  ✓ Daemon started and ready (PID: {})", daemon_handle.id());
    Ok(daemon_handle)
}
