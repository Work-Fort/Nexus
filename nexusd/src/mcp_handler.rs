use anyhow::{anyhow, Result};
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::{json, Value};
use std::sync::Arc;

// JSON-RPC error codes
const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;

// Custom error type to distinguish invalid params from internal errors
#[derive(Debug)]
enum McpError {
    InvalidParams(String),
    Internal(String),
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::InvalidParams(msg) => write!(f, "{}", msg),
            McpError::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for McpError {}

impl From<anyhow::Error> for McpError {
    fn from(err: anyhow::Error) -> Self {
        let msg = err.to_string();
        if msg.starts_with("missing ") || msg.contains("parameter") {
            McpError::InvalidParams(msg)
        } else {
            McpError::Internal(msg)
        }
    }
}

pub async fn handle_mcp_request(
    State(state): State<Arc<crate::api::AppState>>,
    body: String,
) -> Result<String, (StatusCode, String)> {
    // Parse JSON-RPC request
    let request: Value = match serde_json::from_str(&body) {
        Ok(req) => req,
        Err(_) => {
            let error = error_response(None, PARSE_ERROR, "Parse error".to_string());
            return Ok(serde_json::to_string(&error).unwrap());
        }
    };

    let id = request.get("id").cloned();
    let method = match request.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            let error = error_response(id, INVALID_REQUEST, "Missing method".to_string());
            return Ok(serde_json::to_string(&error).unwrap());
        }
    };

    let params = request.get("params").cloned().unwrap_or(json!({}));

    // Dispatch to method handler
    let result = match method {
        "initialize" => handle_initialize(params).await.map_err(McpError::from),
        "tools/list" => handle_tools_list(params).await.map_err(McpError::from),
        "tools/call" => handle_tools_call(params, state).await.map_err(McpError::from),
        _ => {
            let error = error_response(
                id,
                METHOD_NOT_FOUND,
                format!("Method not found: {}", method),
            );
            return Ok(serde_json::to_string(&error).unwrap());
        }
    };

    // Return response with appropriate error code
    let response = match result {
        Ok(value) => success_response(id, value),
        Err(McpError::InvalidParams(msg)) => error_response(id, INVALID_PARAMS, msg),
        Err(McpError::Internal(msg)) => error_response(id, INTERNAL_ERROR, msg),
    };

    serde_json::to_string(&response)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn handle_initialize(params: Value) -> Result<Value> {
    let _client_version = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("2025-03-26");

    Ok(json!({
        "protocolVersion": "2025-03-26",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "nexusd",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}

async fn handle_tools_list(_params: Value) -> Result<Value> {
    Ok(json!({
        "tools": [
            {
                "name": "file_read",
                "version": "1.0.0",
                "description": "Read a file from a VM",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {
                            "type": "string",
                            "description": "VM name or ID"
                        },
                        "path": {
                            "type": "string",
                            "description": "Absolute path to file in VM"
                        }
                    },
                    "required": ["vm", "path"]
                }
            },
            {
                "name": "file_write",
                "version": "1.0.0",
                "description": "Write content to a file in a VM",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {
                            "type": "string",
                            "description": "VM name or ID"
                        },
                        "path": {
                            "type": "string",
                            "description": "Absolute path to file in VM"
                        },
                        "content": {
                            "type": "string",
                            "description": "Content to write"
                        }
                    },
                    "required": ["vm", "path", "content"]
                }
            },
            {
                "name": "file_delete",
                "version": "1.0.0",
                "description": "Delete a file from a VM",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {
                            "type": "string",
                            "description": "VM name or ID"
                        },
                        "path": {
                            "type": "string",
                            "description": "Absolute path to file in VM"
                        }
                    },
                    "required": ["vm", "path"]
                }
            },
            {
                "name": "run_command",
                "version": "1.0.0",
                "description": "Execute a command in a VM and return output",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {
                            "type": "string",
                            "description": "VM name or ID"
                        },
                        "command": {
                            "type": "string",
                            "description": "Command to execute"
                        },
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Command arguments"
                        }
                    },
                    "required": ["vm", "command"]
                }
            }
        ]
    }))
}

async fn handle_tools_call(params: Value, state: Arc<crate::api::AppState>) -> Result<Value> {
    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| anyhow!("missing name parameter"))?;

    let arguments = params
        .get("arguments")
        .and_then(|a| a.as_object())
        .ok_or_else(|| anyhow!("missing arguments parameter"))?;

    // Extract VM parameter (required for all tools)
    let vm_id = arguments
        .get("vm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing vm parameter"))?;

    // Get VM from database
    let store = state.store.clone();
    let vm_id_clone = vm_id.to_string();
    let vm = tokio::task::spawn_blocking(move || store.get_vm(&vm_id_clone))
        .await
        .map_err(|e| anyhow!("task panicked: {}", e))?
        .map_err(|e| anyhow!("database error: {}", e))?
        .ok_or_else(|| anyhow!("VM {} not found", vm_id))?;

    // Check VM is ready
    if vm.state.to_string() != "ready" {
        return Err(anyhow!(
            "VM {} is in state '{}', expected 'ready'",
            vm.name,
            vm.state
        ));
    }

    // Get MCP connection to guest-agent
    let runtime_dir = nexus_lib::vm_service::vm_runtime_dir(&vm.id);
    let mcp_stream = state
        .vsock_manager
        .get_mcp_connection(vm.id, runtime_dir)
        .await
        .map_err(|e| anyhow!("MCP connection failed: {}", e))?;

    let mcp_client = nexus_lib::mcp_client::McpClient::new(mcp_stream);

    // Dispatch to tool handler
    match tool_name {
        "file_read" => {
            let path = arguments
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| anyhow!("missing path parameter"))?;

            let content = mcp_client
                .file_read(path)
                .await
                .map_err(|e| anyhow!("file_read error: {}", e))?;

            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": content
                    }
                ]
            }))
        }
        "file_write" => {
            let path = arguments
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| anyhow!("missing path parameter"))?;
            let content = arguments
                .get("content")
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow!("missing content parameter"))?;

            let written = mcp_client
                .file_write(path, content)
                .await
                .map_err(|e| anyhow!("file_write error: {}", e))?;

            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!("Wrote {} bytes to {}", written, path)
                    }
                ]
            }))
        }
        "file_delete" => {
            let path = arguments
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| anyhow!("missing path parameter"))?;

            mcp_client
                .file_delete(path)
                .await
                .map_err(|e| anyhow!("file_delete error: {}", e))?;

            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!("Deleted {}", path)
                    }
                ]
            }))
        }
        "run_command" => {
            let command = arguments
                .get("command")
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow!("missing command parameter"))?;
            let args: Vec<String> = arguments
                .get("args")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();

            let mut output = String::new();
            let exit_code = mcp_client
                .run_command(command, &args, |chunk| {
                    output.push_str(&chunk);
                })
                .await
                .map_err(|e| anyhow!("run_command error: {}", e))?;

            // Return exit code in meta, not isError (MCP compliance)
            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": output
                    }
                ],
                "meta": {
                    "exitCode": exit_code
                }
            }))
        }
        _ => Err(anyhow!("Unknown tool: {}", tool_name)),
    }
}

fn error_response(id: Option<Value>, code: i32, message: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn success_response(id: Option<Value>, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}
