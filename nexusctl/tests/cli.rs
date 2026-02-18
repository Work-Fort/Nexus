use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::process::{Child, Command};
use std::time::Duration;

/// Address used for nexusctl integration tests.
/// Different from nexusd's integration test (port 9600) to avoid conflicts
/// when running `cargo test --workspace`.
const TEST_ADDR: &str = "127.0.0.1:9601";

fn target_dir() -> std::path::PathBuf {
    // The test binary is at target/debug/deps/cli-<hash>
    // Cross-package binaries are at target/debug/nexusd
    let mut path = std::env::current_exe().expect("cannot get test binary path");
    path.pop(); // remove cli-<hash>
    path.pop(); // remove deps
    path
}

fn start_daemon() -> Child {
    // nexusd is a cross-package binary, so env!("CARGO_BIN_EXE_nexusd") won't work.
    // Locate it relative to the test binary in target/debug/.
    let binary = target_dir().join("nexusd");
    let config_yaml = format!("api:\n  listen: \"{TEST_ADDR}\"");
    let config_path = std::env::temp_dir().join("nexusctl-test-config.yaml");
    std::fs::write(&config_path, config_yaml).expect("failed to write test config");

    Command::new(binary)
        .env("RUST_LOG", "info")
        .arg("--config")
        .arg(&config_path)
        .spawn()
        .expect("failed to start nexusd")
}

fn stop_daemon(child: &Child) {
    signal::kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM)
        .expect("failed to send SIGTERM");
}

#[tokio::test]
async fn status_when_daemon_running() {
    let mut child = start_daemon();

    // Wait for daemon to be ready
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client
            .get(format!("http://{TEST_ADDR}/v1/health"))
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
    }
    assert!(ready, "daemon did not become ready within 5 seconds");

    // Run nexusctl status — use env!("CARGO_BIN_EXE_nexusctl") since it's the same package
    let output = Command::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(["--daemon", TEST_ADDR, "status"])
        .output()
        .expect("failed to run nexusctl");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "nexusctl status failed: {stdout}");
    assert!(stdout.contains("ok"), "expected 'ok' in output: {stdout}");
    assert!(
        stdout.contains(TEST_ADDR),
        "expected address in output: {stdout}"
    );

    // Clean up
    stop_daemon(&child);
    child.wait().expect("failed to wait on daemon");
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
