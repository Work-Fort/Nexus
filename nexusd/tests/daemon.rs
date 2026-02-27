// SPDX-License-Identifier: GPL-2.0-only
use nexus_lib::test_support::TestDaemon;

#[tokio::test]
async fn kernel_list_returns_empty_initially() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/v1/kernels", daemon.addr))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn rootfs_list_returns_empty_initially() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/v1/rootfs-images", daemon.addr))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn firecracker_list_returns_empty_initially() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/v1/firecracker", daemon.addr))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn daemon_starts_serves_health_and_stops() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;

    // Verify health endpoint includes database info
    let client = reqwest::Client::new();
    let resp = client
        .get(daemon.health_url())
        .send()
        .await
        .expect("health request failed");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["database"]["path"].is_string(), "expected database path in response");
    assert_eq!(body["database"]["table_count"], 22);
    assert!(body["database"]["size_bytes"].is_number(), "expected database size in response");

    // Verify database file was created
    assert!(daemon.db_path.exists(), "database file should be created");

    // TestDaemon sends SIGTERM and waits on drop
}

#[tokio::test]
async fn vm_crud_lifecycle() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;

    let client = reqwest::Client::new();
    let base = format!("http://{}", daemon.addr);

    // Create a VM
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&serde_json::json!({"name": "int-test-vm"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let vm: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(vm["name"], "int-test-vm");
    assert_eq!(vm["state"], "created");
    assert_eq!(vm["cid"], 3);

    // List VMs
    let resp = client.get(format!("{base}/v1/vms")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let vms: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(vms.len(), 1);

    // Get VM by name
    let resp = client
        .get(format!("{base}/v1/vms/int-test-vm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let detail: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(detail["name"], "int-test-vm");

    // Get VM not found
    let resp = client
        .get(format!("{base}/v1/vms/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Delete VM
    let resp = client
        .delete(format!("{base}/v1/vms/int-test-vm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify deleted
    let resp = client
        .get(format!("{base}/v1/vms/int-test-vm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // List should be empty
    let resp = client.get(format!("{base}/v1/vms")).send().await.unwrap();
    let vms: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(vms.len(), 0);
}

#[tokio::test]
async fn template_crud_lifecycle() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;

    let client = reqwest::Client::new();
    let base = format!("http://{}", daemon.addr);

    // Create template
    let resp = client
        .post(format!("{base}/v1/templates"))
        .json(&serde_json::json!({
            "name": "test-template",
            "source_type": "rootfs",
            "source_identifier": "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let tpl: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(tpl["name"], "test-template");
    assert_eq!(tpl["version"], 1);

    // List templates
    let resp = client.get(format!("{base}/v1/templates")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let templates: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(templates.len(), 1);

    // Get template by name
    let resp = client
        .get(format!("{base}/v1/templates/test-template"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let detail: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(detail["name"], "test-template");

    // Get template not found
    let resp = client
        .get(format!("{base}/v1/templates/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Delete template
    let resp = client
        .delete(format!("{base}/v1/templates/test-template"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify deleted
    let resp = client
        .get(format!("{base}/v1/templates/test-template"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // List should be empty
    let resp = client.get(format!("{base}/v1/templates")).send().await.unwrap();
    let templates: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(templates.len(), 0);
}

#[tokio::test]
async fn create_vm_rejects_base32_name() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;

    let client = reqwest::Client::new();
    let base = format!("http://{}", daemon.addr);

    // Try to create VM with a 13-char base32-parsable name
    let resp = client
        .post(format!("{base}/v1/vms"))
        .json(&serde_json::json!({
            "name": "aaaaaaaaaaaaa",  // Valid base32, 13 chars
            "role": "work",
            "vcpu_count": 1,
            "mem_size_mib": 128
        }))
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request
    assert_eq!(resp.status(), 400);
    let error: serde_json::Value = resp.json().await.unwrap();
    let error_msg = error["error"].as_str().unwrap();
    assert!(
        error_msg.contains("cannot be a valid base32 ID"),
        "Expected error message about base32 ID, got: {}", error_msg
    );
}

#[tokio::test]
async fn vm_tags_crud() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;
    let client = reqwest::Client::new();

    // Create a VM
    let resp = client.post(format!("http://{}/v1/vms", daemon.addr))
        .json(&serde_json::json!({"name": "tag-vm", "role": "work"}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 201);

    // Add tag
    let resp = client.post(format!("http://{}/v1/vms/tag-vm/tags", daemon.addr))
        .json(&serde_json::json!({"tag": "sharkfin_user:test-lead"}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // List tags
    let resp = client.get(format!("http://{}/v1/vms/tag-vm/tags", daemon.addr))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body, serde_json::json!(["sharkfin_user:test-lead"]));

    // Delete tag
    let resp = client.delete(format!("http://{}/v1/vms/tag-vm/tags/sharkfin_user:test-lead", daemon.addr))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn exec_async_returns_404_for_missing_vm() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;
    let client = reqwest::Client::new();

    let resp = client.post(format!("http://{}/v1/vms/nonexistent/exec-async", daemon.addr))
        .json(&serde_json::json!({"command": "/bin/true"}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn sharkfin_webhook_returns_404_for_unknown_user() {
    let daemon = TestDaemon::start_with_binary(
        env!("CARGO_BIN_EXE_nexusd").into(),
    )
    .await;
    let client = reqwest::Client::new();

    let resp = client.post(format!("http://{}/v1/webhooks/sharkfin", daemon.addr))
        .json(&serde_json::json!({
            "event": "message.new",
            "recipient": "unknown-user",
            "channel": "nexus",
            "from": "tpm",
            "message_id": 123,
            "sent_at": "2026-02-27T21:15:16Z"
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), 404);
}
