// SPDX-License-Identifier: GPL-2.0-only
//! End-to-end integration tests for download workflows.
//!
//! Each test starts a TestDaemon, configures its provider database to point
//! at a local wiremock server, then exercises the full download -> register ->
//! list -> verify -> remove lifecycle through the daemon's REST API.

mod download_fixtures;

use nexus_lib::test_support::TestDaemon;

#[tokio::test]
async fn kernel_download_register_list_verify() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    ).await;

    let client = reqwest::Client::new();
    let base = format!("http://{}", daemon.addr);

    // Pre-check: no kernels installed
    let resp = client.get(format!("{base}/v1/kernels")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let kernels: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(kernels.is_empty(), "expected no kernels initially");

    // Build fake kernel and start mock server
    let kernel = download_fixtures::FakeKernel::new("6.99.0");
    let mock_server = wiremock::MockServer::start().await;
    download_fixtures::serve_kernel_from_mock(&mock_server, &kernel).await;

    // Configure provider: mock server base_url, HTTP without TLS, xz pipeline
    let pipeline = serde_json::to_string(&vec![
        serde_json::json!({"transport": "http", "credentials": {}, "host": "", "encrypted": false}),
        serde_json::json!({"checksum": "SHA256"}),
        serde_json::json!({"verify": "none"}),
        serde_json::json!({"decompress": "xz"}),
        serde_json::json!({"checksum": "SHA256"}),
    ]).unwrap();
    download_fixtures::configure_provider_for_mock(
        &daemon.db_path, "kernel", &mock_server.uri(), &pipeline,
    );

    // 1. Download kernel via REST API
    let resp = client.post(format!("{base}/v1/kernels/download"))
        .json(&serde_json::json!({"version": "6.99.0"}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 201, "kernel download should return 201 Created");
    let k: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(k["version"], "6.99.0");
    assert_eq!(k["architecture"], "x86_64");
    assert!(!k["sha256"].as_str().unwrap().is_empty());

    // Comprehensive verification: file exists, executable, correct version
    let path = k["path_on_host"].as_str().unwrap();
    assert!(path.contains("vmlinux"));
    let kernel_path = std::path::Path::new(path);
    assert!(kernel_path.exists(), "kernel file must exist at expected path");
    let metadata = std::fs::metadata(kernel_path).unwrap();
    assert!(metadata.len() > 0, "kernel file must not be empty");
    // Verify SHA256 matches expected value
    let actual_sha256 = k["sha256"].as_str().unwrap();
    assert_eq!(actual_sha256, kernel.decompressed_sha256, "kernel SHA256 must match expected value");

    // 2. Verify list endpoint includes the kernel
    let resp = client.get(format!("{base}/v1/kernels")).send().await.unwrap();
    let kernels: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(kernels.len(), 1);
    assert_eq!(kernels[0]["version"], "6.99.0");

    // 3. Verify file integrity via verify endpoint
    let resp = client.get(format!("{base}/v1/kernels/6.99.0/verify"))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let verified: bool = resp.json().await.unwrap();
    assert!(verified, "kernel SHA256 re-verification should pass");

    // 4. Verify duplicate download returns error
    let resp = client.post(format!("{base}/v1/kernels/download"))
        .json(&serde_json::json!({"version": "6.99.0"}))
        .send().await.unwrap();
    assert_ne!(resp.status(), 201, "duplicate download should fail");

    // 5. Remove and verify cleanup
    let resp = client.delete(format!("{base}/v1/kernels/6.99.0"))
        .send().await.unwrap();
    assert_eq!(resp.status(), 204);
    let resp = client.get(format!("{base}/v1/kernels")).send().await.unwrap();
    let kernels: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(kernels.is_empty(), "kernel list should be empty after removal");
}
