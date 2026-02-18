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
    assert_eq!(body["database"]["table_count"], 2);
    assert!(body["database"]["size_bytes"].is_number(), "expected database size in response");

    // Verify database file was created
    assert!(daemon.db_path.exists(), "database file should be created");

    // TestDaemon sends SIGTERM and waits on drop
}
