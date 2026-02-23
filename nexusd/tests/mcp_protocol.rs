use nexus_lib::test_support::TestDaemon;
use serde_json::json;

#[tokio::test]
async fn mcp_initialize_handshake() {
    let daemon = TestDaemon::start().await;
    let client = reqwest::Client::new();

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}
        }
    });

    let resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let response: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["protocolVersion"], "2025-03-26");
    assert!(response["result"]["serverInfo"]["name"].as_str().unwrap().contains("nexusd"));
}

#[tokio::test]
async fn mcp_tools_list() {
    let daemon = TestDaemon::start().await;
    let client = reqwest::Client::new();

    let request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });

    let resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let response: serde_json::Value = resp.json().await.unwrap();
    let tools = response["result"]["tools"].as_array().unwrap();

    assert!(tools.iter().any(|t| t["name"] == "file_read"));
    assert!(tools.iter().any(|t| t["name"] == "file_write"));
    assert!(tools.iter().any(|t| t["name"] == "file_delete"));
    assert!(tools.iter().any(|t| t["name"] == "run_command"));

    // Verify schema includes vm parameter
    let file_read = tools.iter().find(|t| t["name"] == "file_read").unwrap();
    assert!(file_read["inputSchema"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "vm"));
}

#[tokio::test]
#[ignore = "Requires full VM environment with drive attached - verify in integration tests or manual QA"]
async fn mcp_file_operations_via_tools() {
    let daemon = TestDaemon::start().await;
    let client = reqwest::Client::new();

    // Create and start VM
    let vm_resp = client
        .post(format!("http://{}/v1/vms", daemon.addr))
        .json(&json!({
            "name": "mcp-test",
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "role": "work"
        }))
        .send()
        .await
        .unwrap();
    let vm: serde_json::Value = vm_resp.json().await.unwrap();
    let vm_id = vm["id"].as_str().unwrap();

    client
        .post(format!("http://{}/v1/vms/{}/start", daemon.addr, vm_id))
        .send()
        .await
        .unwrap();

    // Wait for ready
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

    // Write file via tools/call
    let write_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "file_write",
            "arguments": {
                "vm": vm_id,
                "path": "/tmp/mcp_test.txt",
                "content": "hello from MCP"
            }
        }
    });

    let write_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&write_req)
        .send()
        .await
        .unwrap();

    assert_eq!(write_resp.status(), 200);
    let write_result: serde_json::Value = write_resp.json().await.unwrap();
    assert_eq!(write_result["jsonrpc"], "2.0");
    assert!(write_result["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Wrote"));

    // Read file via tools/call
    let read_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "file_read",
            "arguments": {
                "vm": vm_id,
                "path": "/tmp/mcp_test.txt"
            }
        }
    });

    let read_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&read_req)
        .send()
        .await
        .unwrap();

    let read_result: serde_json::Value = read_resp.json().await.unwrap();
    assert_eq!(read_result["result"]["content"][0]["text"], "hello from MCP");

    // Delete file via tools/call
    let delete_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "file_delete",
            "arguments": {
                "vm": vm_id,
                "path": "/tmp/mcp_test.txt"
            }
        }
    });

    let delete_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&delete_req)
        .send()
        .await
        .unwrap();

    assert_eq!(delete_resp.status(), 200);
}

#[tokio::test]
#[ignore = "Requires full VM environment with drive attached - verify in integration tests or manual QA"]
async fn mcp_run_command_via_tool() {
    let daemon = TestDaemon::start().await;
    let client = reqwest::Client::new();

    // Create and start VM
    let vm_resp = client
        .post(format!("http://{}/v1/vms", daemon.addr))
        .json(&json!({
            "name": "cmd-test",
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "role": "work"
        }))
        .send()
        .await
        .unwrap();
    let vm: serde_json::Value = vm_resp.json().await.unwrap();
    let vm_id = vm["id"].as_str().unwrap();

    client
        .post(format!("http://{}/v1/vms/{}/start", daemon.addr, vm_id))
        .send()
        .await
        .unwrap();

    // Wait for ready
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

    // Run command via tools/call
    let cmd_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "vm": vm_id,
                "command": "echo",
                "args": ["hello world"]
            }
        }
    });

    let cmd_resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&cmd_req)
        .send()
        .await
        .unwrap();

    let cmd_result: serde_json::Value = cmd_resp.json().await.unwrap();
    assert!(cmd_result["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("hello world"));
    assert_eq!(cmd_result["result"]["meta"]["exitCode"], 0);
}

#[tokio::test]
async fn mcp_error_handling() {
    let daemon = TestDaemon::start().await;
    let client = reqwest::Client::new();

    // Unknown method
    let unknown_method = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "unknown/method"
    });

    let resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&unknown_method)
        .send()
        .await
        .unwrap();

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["error"]["code"], -32601); // Method not found

    // Missing vm parameter
    let missing_vm = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "file_read",
            "arguments": {
                "path": "/tmp/test"
            }
        }
    });

    let resp = client
        .post(format!("http://{}/mcp", daemon.addr))
        .json(&missing_vm)
        .send()
        .await
        .unwrap();

    let result: serde_json::Value = resp.json().await.unwrap();
    assert!(result["error"].is_object());
}
