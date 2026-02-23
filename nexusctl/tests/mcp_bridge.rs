use assert_cmd::Command;
use nexus_lib::test_support::TestDaemon;
use serde_json::json;
use std::io::Write;
use std::process::{Command as StdCommand, Stdio};

#[tokio::test]
async fn mcp_bridge_initialize() {
    let daemon = TestDaemon::start().await;

    // Spawn mcp-bridge process
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(&["--daemon", &daemon.addr.to_string(), "mcp-bridge"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());

    // Send initialize request via stdin
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    });

    writeln!(stdin, "{}", request.to_string()).unwrap();
    stdin.flush().unwrap();

    // Read response from stdout
    use std::io::BufRead;
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();

    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["protocolVersion"], "2025-03-26");

    child.kill().unwrap();
}

#[tokio::test]
async fn mcp_bridge_tools_list() {
    let daemon = TestDaemon::start().await;

    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_nexusctl"))
        .args(&["--daemon", &daemon.addr.to_string(), "mcp-bridge"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());

    // Send tools/list request
    let request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });

    writeln!(stdin, "{}", request.to_string()).unwrap();
    stdin.flush().unwrap();

    // Read response
    use std::io::BufRead;
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();

    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    let tools = response["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "file_read"));

    child.kill().unwrap();
}
