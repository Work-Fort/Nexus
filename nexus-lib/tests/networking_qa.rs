#![cfg(feature = "test-support")]

use nexus_lib::test_support::TestDaemon;
use serde_json::json;

#[tokio::test]
#[ignore = "Requires full VM environment with drive attached - verify in integration tests or manual QA"]
async fn vm_has_internet_connectivity_via_mcp() {
    let daemon = TestDaemon::start().await;
    let client = reqwest::Client::new();

    // Create VM
    let vm_resp = client
        .post(format!("http://{}/v1/vms", daemon.addr))
        .json(&json!({
            "name": "internet-test",
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "role": "work"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(vm_resp.status(), 201);
    let vm: serde_json::Value = vm_resp.json().await.unwrap();
    let vm_id = vm["id"].as_str().unwrap();

    // Start VM
    let start_resp = client
        .post(format!("http://{}/v1/vms/{}/start", daemon.addr, vm_id))
        .send()
        .await
        .unwrap();
    assert_eq!(start_resp.status(), 200);

    // Wait for VM to reach ready state
    let mut ready = false;
    for _ in 0..60 {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let status_resp = client
            .get(format!("http://{}/v1/vms/{}", daemon.addr, vm_id))
            .send()
            .await
            .unwrap();
        let vm_data: serde_json::Value = status_resp.json().await.unwrap();
        if vm_data["status"].as_str() == Some("ready") {
            ready = true;
            break;
        }
    }
    assert!(ready, "VM did not reach ready state within 60 seconds");

    // Test 1: Ping Google DNS (8.8.8.8) via MCP run_command tool
    let ping_req = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "vm": vm_id,
                "command": "ping",
                "args": ["-c", "3", "8.8.8.8"]
            }
        }
    });

    let ping_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&ping_req)
        .send()
        .await
        .unwrap();
    assert_eq!(ping_resp.status(), 200);

    let ping_result: serde_json::Value = ping_resp.json().await.unwrap();
    assert_eq!(ping_result["result"]["meta"]["exitCode"], 0, "ping command failed");
    let output = ping_result["result"]["content"][0]["text"].as_str().unwrap();
    assert!(output.contains("8.8.8.8"), "ping output missing");

    // Test 2: HTTPS request via curl
    let curl_req = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "vm": vm_id,
                "command": "curl",
                "args": ["-s", "-o", "/dev/null", "-w", "%{http_code}", "https://www.google.com"]
            }
        }
    });

    let curl_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&curl_req)
        .send()
        .await
        .unwrap();
    assert_eq!(curl_resp.status(), 200);

    let curl_result: serde_json::Value = curl_resp.json().await.unwrap();
    assert_eq!(curl_result["result"]["meta"]["exitCode"], 0, "curl command failed");
    let http_code = curl_result["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .trim();
    assert_eq!(http_code, "200", "HTTPS request did not return 200 OK");

    // Test 3: DNS resolution (using getent)
    let dns_req = json!({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "vm": vm_id,
                "command": "getent",
                "args": ["hosts", "google.com"]
            }
        }
    });

    let dns_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&dns_req)
        .send()
        .await
        .unwrap();
    assert_eq!(dns_resp.status(), 200);

    let dns_result: serde_json::Value = dns_resp.json().await.unwrap();
    assert_eq!(dns_result["result"]["meta"]["exitCode"], 0, "DNS resolution failed");
    let output = dns_result["result"]["content"][0]["text"].as_str().unwrap();
    assert!(output.contains("google.com"), "getent hosts output missing");
}

#[tokio::test]
#[ignore = "Requires full VM environment with drive attached - verify in integration tests or manual QA"]
async fn vm_network_isolation() {
    let daemon = TestDaemon::start().await;
    let client = reqwest::Client::new();

    // Create two VMs
    let vm1_resp = client
        .post(format!("http://{}/v1/vms", daemon.addr))
        .json(&json!({
            "name": "vm1",
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "role": "work"
        }))
        .send()
        .await
        .unwrap();
    let vm1: serde_json::Value = vm1_resp.json().await.unwrap();
    let vm1_id = vm1["id"].as_str().unwrap();

    let vm2_resp = client
        .post(format!("http://{}/v1/vms", daemon.addr))
        .json(&json!({
            "name": "vm2",
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "role": "work"
        }))
        .send()
        .await
        .unwrap();
    let vm2: serde_json::Value = vm2_resp.json().await.unwrap();
    let vm2_id = vm2["id"].as_str().unwrap();

    // Start both VMs
    client
        .post(format!("http://{}/v1/vms/{}/start", daemon.addr, vm1_id))
        .send()
        .await
        .unwrap();
    client
        .post(format!("http://{}/v1/vms/{}/start", daemon.addr, vm2_id))
        .send()
        .await
        .unwrap();

    // Wait for both to be ready
    for vm_id in [vm1_id, vm2_id] {
        for _ in 0..60 {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            let status_resp = client
                .get(format!("http://{}/v1/vms/{}", daemon.addr, vm_id))
                .send()
                .await
                .unwrap();
            let vm_data: serde_json::Value = status_resp.json().await.unwrap();
            if vm_data["status"].as_str() == Some("ready") {
                break;
            }
        }
    }

    // Get VM2's IP address
    let vm2_details = client
        .get(format!("http://{}/v1/vms/{}", daemon.addr, vm2_id))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let vm2_ip = vm2_details["network"]["ip_address"]
        .as_str()
        .expect("VM2 should have IP address");

    // Try to ping VM2 from VM1 - should fail due to isolation
    let ping_req = json!({
        "jsonrpc": "2.0",
        "id": 200,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "vm": vm1_id,
                "command": "ping",
                "args": ["-c", "2", "-W", "1", vm2_ip]
            }
        }
    });

    let ping_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&ping_req)
        .send()
        .await
        .unwrap();

    let ping_result: serde_json::Value = ping_resp.json().await.unwrap();

    // Ping should fail (non-zero exit code) due to nftables isolation rules
    assert_ne!(
        ping_result["result"]["meta"]["exitCode"].as_i64().unwrap(), 0,
        "VM-to-VM ping should fail due to isolation"
    );
}
