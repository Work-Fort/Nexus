use nexus_lib::test_support::TestDaemon;

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
    assert_eq!(body["database"]["table_count"], 5);
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
