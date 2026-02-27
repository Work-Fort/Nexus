use anyhow::Result;
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
        "tools/call" => handle_tools_call(params, state).await,
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
                        },
                        "encoding": {
                            "type": "string",
                            "description": "Encoding for response: 'text' (default) or 'base64' for binary files"
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
                        },
                        "encoding": {
                            "type": "string",
                            "description": "Content encoding: 'text' (default) or 'base64' for binary data"
                        },
                        "mode": {
                            "type": "string",
                            "description": "File permissions in octal (e.g., '0755')"
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
            },
            // --- VM Lifecycle Tools ---
            {
                "name": "vm_list",
                "version": "1.0.0",
                "description": "List all VMs with optional filtering by role or state",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string", "description": "Filter by VM role: 'work', 'portal', or 'service'"},
                        "state": {"type": "string", "description": "Filter by VM state (e.g., 'created', 'running', 'ready')"}
                    },
                    "required": []
                }
            },
            {
                "name": "vm_create",
                "version": "1.0.0",
                "description": "Create a new VM record",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "VM name (must be unique)"},
                        "role": {"type": "string", "description": "VM role: 'work' (default), 'portal', or 'service'"},
                        "vcpu_count": {"type": "integer", "description": "Number of vCPUs (default: 1)"},
                        "mem_size_mib": {"type": "integer", "description": "Memory in MiB (default: 128)"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "vm_inspect",
                "version": "1.0.0",
                "description": "Get detailed information about a VM including network config",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"}
                    },
                    "required": ["vm"]
                }
            },
            {
                "name": "vm_delete",
                "version": "1.0.0",
                "description": "Delete a VM record (must not be running)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"}
                    },
                    "required": ["vm"]
                }
            },
            {
                "name": "vm_start",
                "version": "1.0.0",
                "description": "Start a VM (resolves rootfs, allocates network, spawns Firecracker, provisions guest)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"}
                    },
                    "required": ["vm"]
                }
            },
            {
                "name": "vm_stop",
                "version": "1.0.0",
                "description": "Stop a running VM (sends SIGTERM to Firecracker, cleans up network)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"}
                    },
                    "required": ["vm"]
                }
            },
            {
                "name": "vm_logs",
                "version": "1.0.0",
                "description": "Get console log output from a VM",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"},
                        "tail": {"type": "integer", "description": "Number of lines from end (default: 100)"}
                    },
                    "required": ["vm"]
                }
            },
            {
                "name": "vm_history",
                "version": "1.0.0",
                "description": "Get state transition history for a VM",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"}
                    },
                    "required": ["vm"]
                }
            },
            // --- VM Provisioning Tools ---
            {
                "name": "vm_add_provision_file",
                "version": "1.0.0",
                "description": "Add a provision file configuration for a VM (injected on next start)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"},
                        "guest_path": {"type": "string", "description": "Absolute path inside the guest VM"},
                        "source_type": {"type": "string", "description": "Source type: 'inline' or 'file'"},
                        "source": {"type": "string", "description": "File content (inline) or host file path (file)"},
                        "encoding": {"type": "string", "description": "Encoding: 'text' (default) or 'base64'"}
                    },
                    "required": ["vm", "guest_path", "source_type", "source"]
                }
            },
            {
                "name": "vm_provision_files",
                "version": "1.0.0",
                "description": "List all provision files configured for a VM",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"}
                    },
                    "required": ["vm"]
                }
            },
            {
                "name": "vm_remove_provision_file",
                "version": "1.0.0",
                "description": "Remove a provision file configuration from a VM",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vm": {"type": "string", "description": "VM name or ID"},
                        "guest_path": {"type": "string", "description": "Guest path of the provision file to remove"}
                    },
                    "required": ["vm", "guest_path"]
                }
            },
            // --- Image Tools ---
            {
                "name": "image_list",
                "version": "1.0.0",
                "description": "List all master images",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "image_import",
                "version": "1.0.0",
                "description": "Import a directory as a master image (btrfs subvolume)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Image name"},
                        "source_path": {"type": "string", "description": "Path to directory to import"}
                    },
                    "required": ["name", "source_path"]
                }
            },
            {
                "name": "image_inspect",
                "version": "1.0.0",
                "description": "Get detailed information about a master image",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "image": {"type": "string", "description": "Image name or ID"}
                    },
                    "required": ["image"]
                }
            },
            {
                "name": "image_delete",
                "version": "1.0.0",
                "description": "Delete a master image (fails if drives reference it)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "image": {"type": "string", "description": "Image name or ID"}
                    },
                    "required": ["image"]
                }
            }
        ]
    }))
}

async fn handle_tools_call(
    params: Value,
    state: Arc<crate::api::AppState>,
) -> Result<Value, McpError> {
    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing name parameter".to_string()))?;

    let arguments = params
        .get("arguments")
        .and_then(|a| a.as_object())
        .ok_or_else(|| McpError::InvalidParams("missing arguments parameter".to_string()))?;

    // Two-tier dispatch: guest tools require VM + vsock, management tools operate on AppState
    match tool_name {
        // Guest tools (require vm parameter + vsock connection)
        "file_read" | "file_write" | "file_delete" | "run_command" => {
            handle_guest_tool(tool_name, arguments, &state).await
        }
        // Management tools (host-side operations)
        _ => handle_management_tool(tool_name, arguments, &state).await,
    }
}

async fn handle_guest_tool(
    tool_name: &str,
    arguments: &serde_json::Map<String, Value>,
    state: &Arc<crate::api::AppState>,
) -> Result<Value, McpError> {
    // Extract VM parameter (required for guest tools)
    let vm_id = arguments
        .get("vm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams("missing vm parameter".to_string()))?;

    // Get VM from database (direct call, consistent with REST handlers)
    let vm = state
        .store
        .get_vm(vm_id)
        .map_err(|e| McpError::Internal(format!("database error: {}", e)))?
        .ok_or_else(|| McpError::InvalidParams(format!("VM {} not found", vm_id)))?;

    // Check VM is ready
    if vm.state.to_string() != "ready" {
        return Err(McpError::InvalidParams(format!(
            "VM {} is in state '{}', expected 'ready'",
            vm.name, vm.state
        )));
    }

    // Get MCP connection to guest-agent
    let runtime_dir = nexus_lib::vm_service::vm_runtime_dir(&vm.id);
    let mcp_stream = state
        .vsock_manager
        .get_mcp_connection(vm.id, runtime_dir)
        .await
        .map_err(|e| McpError::Internal(format!("MCP connection failed: {}", e)))?;

    let mcp_client = nexus_lib::mcp_client::McpClient::new(mcp_stream);

    // Dispatch to guest tool handler
    match tool_name {
        "file_read" => {
            let path = arguments
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| {
                    McpError::InvalidParams("missing path parameter".to_string())
                })?;
            let encoding = arguments.get("encoding").and_then(|e| e.as_str());

            if let Some(enc) = encoding {
                let result = mcp_client
                    .file_read_encoded(path, enc)
                    .await
                    .map_err(|e| McpError::Internal(format!("file_read error: {}", e)))?;

                Ok(json!({
                    "content": [
                        {
                            "type": "text",
                            "text": result.to_string()
                        }
                    ]
                }))
            } else {
                let content = mcp_client
                    .file_read(path)
                    .await
                    .map_err(|e| McpError::Internal(format!("file_read error: {}", e)))?;

                Ok(json!({
                    "content": [
                        {
                            "type": "text",
                            "text": content
                        }
                    ]
                }))
            }
        }
        "file_write" => {
            let path = arguments
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or_else(|| {
                    McpError::InvalidParams("missing path parameter".to_string())
                })?;
            let content = arguments
                .get("content")
                .and_then(|c| c.as_str())
                .ok_or_else(|| {
                    McpError::InvalidParams("missing content parameter".to_string())
                })?;
            let encoding = arguments.get("encoding").and_then(|e| e.as_str());
            let mode = arguments.get("mode").and_then(|m| m.as_str());

            let written = if encoding.is_some() || mode.is_some() {
                mcp_client
                    .file_write_encoded(path, content, encoding.unwrap_or("text"), mode)
                    .await
                    .map_err(|e| McpError::Internal(format!("file_write error: {}", e)))?
            } else {
                mcp_client
                    .file_write(path, content)
                    .await
                    .map_err(|e| McpError::Internal(format!("file_write error: {}", e)))?
            };

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
                .ok_or_else(|| {
                    McpError::InvalidParams("missing path parameter".to_string())
                })?;

            mcp_client
                .file_delete(path)
                .await
                .map_err(|e| McpError::Internal(format!("file_delete error: {}", e)))?;

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
                .ok_or_else(|| {
                    McpError::InvalidParams("missing command parameter".to_string())
                })?;
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
                .map_err(|e| McpError::Internal(format!("run_command error: {}", e)))?;

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
        _ => Err(McpError::Internal(format!(
            "Unknown guest tool: {}",
            tool_name
        ))),
    }
}

async fn handle_management_tool(
    tool_name: &str,
    arguments: &serde_json::Map<String, Value>,
    state: &Arc<crate::api::AppState>,
) -> Result<Value, McpError> {
    match tool_name {
        // --- VM Lifecycle Tools ---
        "vm_list" => {
            let role = optional_str(arguments, "role");
            let vm_state = optional_str(arguments, "state");
            let vms = state.store.list_vms(role, vm_state).map_err(store_err)?;
            Ok(mcp_text_response(&vms))
        }

        "vm_create" => {
            let name = require_str(arguments, "name")?;
            let role_str = optional_str(arguments, "role").unwrap_or("work");
            let vcpu = arguments
                .get("vcpu_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u32;
            let mem = arguments
                .get("mem_size_mib")
                .and_then(|v| v.as_u64())
                .unwrap_or(128) as u32;

            let params = nexus_lib::vm::CreateVmParams {
                name: name.to_string(),
                role: serde_json::from_value(serde_json::json!(role_str))
                    .unwrap_or(nexus_lib::vm::VmRole::Work),
                vcpu_count: vcpu,
                mem_size_mib: mem,
            };
            let vm = state.store.create_vm(&params).map_err(store_err)?;
            Ok(mcp_text_response(&vm))
        }

        "vm_inspect" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            let network = state.store.get_vm_network(vm.id.as_i64()).ok().flatten();
            let mut vm_json = serde_json::to_value(&vm).unwrap();
            vm_json["network"] = network
                .as_ref()
                .map(|n| {
                    json!({
                        "ip_address": n.ip_address,
                        "bridge_name": n.bridge_name,
                    })
                })
                .unwrap_or(Value::Null);
            Ok(json!({
                "content": [{"type": "text", "text": serde_json::to_string_pretty(&vm_json).unwrap()}]
            }))
        }

        "vm_delete" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            // Clean up tap device (best-effort)
            if let Err(e) = state.network_service.destroy_tap(vm.id.as_i64()) {
                tracing::warn!(
                    "Failed to destroy tap device for VM {}: {}",
                    vm.name,
                    e
                );
            }
            let deleted = state.store.delete_vm(vm.id).map_err(store_err)?;
            if deleted {
                Ok(mcp_message_response(&format!("VM '{}' deleted", vm_id)))
            } else {
                Err(McpError::InvalidParams(format!(
                    "VM '{}' not found",
                    vm_id
                )))
            }
        }

        "vm_start" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = crate::api::start_vm(state.as_ref(), vm_id)
                .await
                .map_err(|e| match e {
                    crate::api::StartVmError::NotFound(msg) => McpError::InvalidParams(msg),
                    crate::api::StartVmError::BadRequest(msg) => McpError::InvalidParams(msg),
                    crate::api::StartVmError::Conflict(msg) => McpError::InvalidParams(msg),
                    crate::api::StartVmError::Internal(msg) => McpError::Internal(msg),
                })?;
            Ok(mcp_text_response(&vm))
        }

        "vm_stop" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = crate::api::stop_vm(state.as_ref(), vm_id)
                .await
                .map_err(|e| match e {
                    crate::api::StopVmError::NotFound(msg) => McpError::InvalidParams(msg),
                    crate::api::StopVmError::Conflict(msg) => McpError::InvalidParams(msg),
                    crate::api::StopVmError::Internal(msg) => McpError::Internal(msg),
                })?;
            Ok(mcp_text_response(&vm))
        }

        "vm_logs" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            let log_path = vm.console_log_path.as_ref().ok_or_else(|| {
                McpError::InvalidParams(format!("no console log for VM '{}'", vm.name))
            })?;
            let tail: usize = arguments
                .get("tail")
                .and_then(|t| t.as_u64())
                .unwrap_or(100) as usize;
            let content = std::fs::read_to_string(log_path)
                .map_err(|e| McpError::Internal(format!("cannot read console log: {}", e)))?;
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(tail);
            let output = lines[start..].join("\n");
            Ok(mcp_message_response(&output))
        }

        "vm_history" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            let history = state.store.get_state_history(vm.id).map_err(store_err)?;
            Ok(mcp_text_response(&history))
        }

        // --- VM Provisioning Tools ---
        "vm_add_provision_file" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            let params = nexus_lib::vm::AddProvisionFileParams {
                guest_path: require_str(arguments, "guest_path")?.to_string(),
                source_type: require_str(arguments, "source_type")?.to_string(),
                source: require_str(arguments, "source")?.to_string(),
                encoding: optional_str(arguments, "encoding")
                    .unwrap_or("text")
                    .to_string(),
                mode: None,
            };
            let pf = state
                .store
                .add_provision_file(vm.id, &params)
                .map_err(store_err)?;
            Ok(mcp_text_response(&pf))
        }

        "vm_provision_files" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            let files = state
                .store
                .list_provision_files(vm.id)
                .map_err(store_err)?;
            Ok(mcp_text_response(&files))
        }

        "vm_remove_provision_file" => {
            let vm_id = require_str(arguments, "vm")?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            let guest_path = require_str(arguments, "guest_path")?;
            let deleted = state
                .store
                .remove_provision_file(vm.id, guest_path)
                .map_err(store_err)?;
            if deleted {
                Ok(mcp_message_response(&format!(
                    "Removed provision file for '{}'",
                    guest_path
                )))
            } else {
                Err(McpError::InvalidParams(format!(
                    "no provision file for guest path '{}'",
                    guest_path
                )))
            }
        }

        // --- Image Tools ---
        "image_list" => {
            let svc = nexus_lib::drive_service::DriveService::new(
                state.store.as_ref(),
                state.backend.as_ref(),
                state.drives_root.clone(),
            );
            let images = svc
                .list_images()
                .map_err(|e| McpError::Internal(e.to_string()))?;
            Ok(mcp_text_response(&images))
        }

        "image_import" => {
            let params = nexus_lib::drive::ImportImageParams {
                name: require_str(arguments, "name")?.to_string(),
                source_path: require_str(arguments, "source_path")?.to_string(),
            };
            let svc = nexus_lib::drive_service::DriveService::new(
                state.store.as_ref(),
                state.backend.as_ref(),
                state.drives_root.clone(),
            );
            let img = svc.import_image(&params).map_err(|e| match &e {
                nexus_lib::drive_service::DriveServiceError::Store(
                    nexus_lib::store::traits::StoreError::InvalidInput(_),
                ) => McpError::InvalidParams(e.to_string()),
                nexus_lib::drive_service::DriveServiceError::Store(
                    nexus_lib::store::traits::StoreError::Conflict(_),
                ) => McpError::InvalidParams(e.to_string()),
                _ => McpError::Internal(e.to_string()),
            })?;
            Ok(mcp_text_response(&img))
        }

        "image_inspect" => {
            let name_or_id = require_str(arguments, "image")?;
            let svc = nexus_lib::drive_service::DriveService::new(
                state.store.as_ref(),
                state.backend.as_ref(),
                state.drives_root.clone(),
            );
            let img = svc
                .get_image(name_or_id)
                .map_err(|e| McpError::Internal(e.to_string()))?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("image '{}' not found", name_or_id))
                })?;
            Ok(mcp_text_response(&img))
        }

        "image_delete" => {
            let name_or_id = require_str(arguments, "image")?;
            let img = state
                .store
                .get_image(name_or_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("image '{}' not found", name_or_id))
                })?;
            // Delete subvolume from filesystem
            let path = std::path::PathBuf::from(&img.subvolume_path);
            if path.exists() {
                state.backend.delete_subvolume(&path).map_err(|e| {
                    McpError::Internal(format!("failed to delete subvolume: {}", e))
                })?;
            }
            let deleted = state.store.delete_image(img.id).map_err(store_err)?;
            if deleted {
                Ok(mcp_message_response(&format!(
                    "Image '{}' deleted",
                    name_or_id
                )))
            } else {
                Err(McpError::InvalidParams(format!(
                    "image '{}' not found",
                    name_or_id
                )))
            }
        }

        // Drive tools -- Task 5
        // Kernel tools -- Task 6
        // Rootfs tools -- Task 7
        // Firecracker tools -- Task 8
        // Template tools -- Task 9
        // Build tools -- Task 10
        // Settings tools -- Task 11
        // Admin tools -- Task 12
        _ => Err(McpError::InvalidParams(format!(
            "Unknown tool: {}",
            tool_name
        ))),
    }
}

/// Format a serializable value as an MCP tool response.
fn mcp_text_response<T: serde::Serialize>(value: &T) -> Value {
    let text = serde_json::to_string_pretty(value)
        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
    json!({
        "content": [{"type": "text", "text": text}]
    })
}

/// Format a plain text message as an MCP tool response.
fn mcp_message_response(msg: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": msg}]
    })
}

/// Extract a required string parameter from MCP arguments.
fn require_str<'a>(
    args: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, McpError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::InvalidParams(format!("missing required parameter: {}", key)))
}

/// Extract an optional string parameter from MCP arguments.
fn optional_str<'a>(args: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

/// Map a StoreError to an McpError.
fn store_err(e: nexus_lib::store::traits::StoreError) -> McpError {
    match &e {
        nexus_lib::store::traits::StoreError::InvalidInput(_) => {
            McpError::InvalidParams(e.to_string())
        }
        nexus_lib::store::traits::StoreError::Conflict(_) => {
            McpError::InvalidParams(e.to_string())
        }
        _ => McpError::Internal(e.to_string()),
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
