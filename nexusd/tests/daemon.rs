use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::process::{Child, Command};
use std::time::Duration;

fn start_daemon(db_path: &std::path::Path) -> Child {
    let binary = env!("CARGO_BIN_EXE_nexusd");
    Command::new(binary)
        .env("RUST_LOG", "info")
        .arg("--db")
        .arg(db_path)
        .spawn()
        .expect("failed to start nexusd")
}

fn stop_daemon(child: &Child) {
    signal::kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM)
        .expect("failed to send SIGTERM");
}

#[tokio::test]
async fn daemon_starts_serves_health_and_stops() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("test.db");

    let mut child = start_daemon(&db_path);

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

    // Verify health endpoint includes database info
    let resp = client
        .get("http://127.0.0.1:9600/v1/health")
        .send()
        .await
        .expect("health request failed");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["database"]["path"].is_string(), "expected database path in response");
    assert_eq!(body["database"]["table_count"], 2);
    assert!(body["database"]["size_bytes"].is_number(), "expected database size in response");

    // Verify database file was created
    assert!(db_path.exists(), "database file should be created");

    // Graceful shutdown
    stop_daemon(&child);
    let status = child.wait().expect("failed to wait on daemon");
    assert!(
        status.success(),
        "daemon exited with non-zero status: {}",
        status
    );
}
