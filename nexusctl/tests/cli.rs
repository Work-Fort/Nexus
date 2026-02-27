// SPDX-License-Identifier: GPL-2.0-only
use nexus_lib::test_support::TestDaemon;
use std::process::Command;

#[tokio::test]
async fn status_when_daemon_running() {
    let daemon = TestDaemon::start().await;

    // Run nexusctl status
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", &daemon.addr, "status"])
        .output()
        .expect("failed to run nexusctl");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "nexusctl status failed: {stdout}");
    assert!(stdout.contains("ok"), "expected 'ok' in output: {stdout}");
    assert!(stdout.contains(&daemon.addr), "expected address in output: {stdout}");
    assert!(stdout.contains("Database:"), "expected database path in output: {stdout}");
    assert!(stdout.contains("Tables:"), "expected table count in output: {stdout}");

    // TestDaemon sends SIGTERM and waits on drop
}

#[tokio::test]
async fn status_when_daemon_not_running() {
    // Use a port where nothing is listening
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", "127.0.0.1:19998", "status"])
        .output()
        .expect("failed to run nexusctl");

    assert!(!output.status.success(), "expected non-zero exit code");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot connect to Nexus daemon"),
        "expected connection error in stderr: {stderr}"
    );
    assert!(
        stderr.contains("19998"),
        "expected port in error message: {stderr}"
    );
    assert!(
        stderr.contains("systemctl --user start nexus.service"),
        "expected actionable hint in stderr: {stderr}"
    );
}

#[tokio::test]
async fn vm_create_list_inspect_delete() {
    let daemon = TestDaemon::start().await;

    // Create a VM
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", &daemon.addr, "vm", "create", "cli-test-vm"])
        .output()
        .expect("failed to run nexusctl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "create failed: {stdout}");
    assert!(stdout.contains("Created VM"), "expected create message: {stdout}");

    // List VMs
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", &daemon.addr, "vm", "list"])
        .output()
        .expect("failed to run nexusctl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "list failed: {stdout}");
    assert!(stdout.contains("cli-test-vm"), "expected VM in list: {stdout}");
    assert!(stdout.contains("NAME"), "expected table header: {stdout}");

    // Inspect VM
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", &daemon.addr, "vm", "inspect", "cli-test-vm"])
        .output()
        .expect("failed to run nexusctl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "inspect failed: {stdout}");
    assert!(stdout.contains("cli-test-vm"), "expected VM name: {stdout}");
    assert!(stdout.contains("State:"), "expected state field: {stdout}");
    assert!(stdout.contains("CID:"), "expected CID field: {stdout}");

    // Delete VM
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", &daemon.addr, "vm", "delete", "cli-test-vm", "--yes"])
        .output()
        .expect("failed to run nexusctl");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "delete failed: {stdout}");
    assert!(stdout.contains("Deleted VM"), "expected delete message: {stdout}");

    // Verify deleted
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", &daemon.addr, "vm", "inspect", "cli-test-vm"])
        .output()
        .expect("failed to run nexusctl");
    assert!(!output.status.success(), "expected inspect to fail after delete");
}

#[tokio::test]
async fn admin_cleanup_network() {
    let daemon = TestDaemon::start().await;

    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", &daemon.addr, "admin", "cleanup-network"])
        .output()
        .expect("failed to run nexusctl");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "admin cleanup-network failed: {stdout}");
    // With no VMs running, cleanup should report zeros
    assert!(stdout.contains("Taps deleted:"), "expected taps line: {stdout}");
    assert!(stdout.contains("Bridge deleted:"), "expected bridge line: {stdout}");
    assert!(stdout.contains("nftables flushed:"), "expected nftables line: {stdout}");
}

#[test]
fn version_prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["version"])
        .output()
        .expect("failed to run nexusctl");

    assert!(output.status.success(), "nexusctl version failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("nexusctl 0.1.0"),
        "expected version string in output: {stdout}"
    );
}
