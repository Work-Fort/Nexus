use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::process::{Child, Command};
use std::time::Duration;

fn start_daemon() -> Child {
    let binary = env!("CARGO_BIN_EXE_nexusd");
    Command::new(binary)
        .env("RUST_LOG", "info")
        .spawn()
        .expect("failed to start nexusd")
}

fn stop_daemon(child: &Child) {
    signal::kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM)
        .expect("failed to send SIGTERM");
}

#[tokio::test]
async fn daemon_starts_serves_health_and_stops() {
    let mut child = start_daemon();

    // Wait for the daemon to be ready
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client
            .get("http://127.0.0.1:9600/v1/health")
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
    }
    assert!(ready, "daemon did not become ready within 5 seconds");

    // Verify health endpoint
    let resp = client
        .get("http://127.0.0.1:9600/v1/health")
        .send()
        .await
        .expect("health request failed");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    // Graceful shutdown
    stop_daemon(&child);
    let status = child.wait().expect("failed to wait on daemon");
    assert!(
        status.success(),
        "daemon exited with non-zero status: {}",
        status
    );
}
