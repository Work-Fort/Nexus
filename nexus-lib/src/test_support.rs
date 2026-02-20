// SPDX-License-Identifier: GPL-2.0-only
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

/// A running nexusd instance for integration tests.
/// Stops the daemon on drop.
pub struct TestDaemon {
    child: Child,
    pub addr: String,
    pub port: u16,
    pub db_path: PathBuf,
    _tmp_dir: tempfile::TempDir,
    _config_dir: tempfile::TempDir,
}

impl TestDaemon {
    /// Start a daemon on a random available port with a temp database.
    /// Polls until the health endpoint responds or timeout (5s).
    pub async fn start() -> Self {
        Self::start_with_binary(Self::find_nexusd_binary()).await
    }

    /// Start with an explicit binary path (for cross-package tests).
    pub async fn start_with_binary(binary: PathBuf) -> Self {
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");

        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = tmp_dir.path().join("test.db");

        let config_dir = tempfile::tempdir().expect("failed to create config dir");
        let config_path = config_dir.path().join("nexus.yaml");
        let config_yaml = format!(
            "api:\n  listen: \"{addr}\"\nstorage:\n  workspaces: \"{}\"",
            tmp_dir.path().join("workspaces").display()
        );
        std::fs::write(&config_path, config_yaml)
            .expect("failed to write test config");

        let child = Command::new(&binary)
            .env("RUST_LOG", "info")
            .arg("--config")
            .arg(&config_path)
            .arg("--db")
            .arg(&db_path)
            .spawn()
            .unwrap_or_else(|e| panic!("failed to start {}: {e}", binary.display()));

        let daemon = TestDaemon {
            child,
            addr: addr.clone(),
            port,
            db_path,
            _tmp_dir: tmp_dir,
            _config_dir: config_dir,
        };

        daemon.wait_ready().await;
        daemon
    }

    pub fn health_url(&self) -> String {
        format!("http://{}/v1/health", self.addr)
    }

    async fn wait_ready(&self) {
        let client = reqwest::Client::new();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if client.get(self.health_url()).send().await.is_ok() {
                return;
            }
        }
        panic!("daemon did not become ready within 5 seconds on {}", self.addr);
    }

    /// Find the nexusd binary relative to the test binary location.
    fn find_nexusd_binary() -> PathBuf {
        let mut path = std::env::current_exe().expect("cannot get test binary path");
        path.pop(); // remove test-<hash>
        path.pop(); // remove deps
        path.join("nexusd")
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = signal::kill(
            Pid::from_raw(self.child.id() as i32),
            Signal::SIGTERM,
        );
        let _ = self.child.wait();
    }
}

/// Find a free TCP port by binding to port 0 and reading the assigned port.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .expect("failed to bind to port 0");
    listener.local_addr().unwrap().port()
}
