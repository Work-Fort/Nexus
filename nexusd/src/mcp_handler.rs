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
    // Tool definitions split into groups to avoid json! macro recursion limit.
    let guest_tools = json!([
        {
            "name": "file_read",
            "version": "1.0.0",
            "description": "Read a file from a VM",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vm": {"type": "string", "description": "VM name or ID"},
                    "path": {"type": "string", "description": "Absolute path to file in VM"},
                    "encoding": {"type": "string", "description": "Encoding for response: 'text' (default) or 'base64' for binary files"}
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
                    "vm": {"type": "string", "description": "VM name or ID"},
                    "path": {"type": "string", "description": "Absolute path to file in VM"},
                    "content": {"type": "string", "description": "Content to write"},
                    "encoding": {"type": "string", "description": "Content encoding: 'text' (default) or 'base64' for binary data"},
                    "mode": {"type": "string", "description": "File permissions in octal (e.g., '0755')"}
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
                    "vm": {"type": "string", "description": "VM name or ID"},
                    "path": {"type": "string", "description": "Absolute path to file in VM"}
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
                    "vm": {"type": "string", "description": "VM name or ID"},
                    "command": {"type": "string", "description": "Command to execute"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Command arguments"}
                },
                "required": ["vm", "command"]
            }
        }
    ]);

    let vm_tools = json!([
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
        }
    ]);

    let storage_tools = json!([
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
        },
        {
            "name": "drive_list",
            "version": "1.0.0",
            "description": "List all drives, optionally filtered by base image",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "base": {"type": "string", "description": "Filter by master image name"}
                },
                "required": []
            }
        },
        {
            "name": "drive_create",
            "version": "1.0.0",
            "description": "Create a drive by snapshotting a master image",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "base": {"type": "string", "description": "Master image name to snapshot from"},
                    "name": {"type": "string", "description": "Drive name (optional, auto-generated if omitted)"},
                    "size": {"type": "integer", "description": "Drive size in bytes (optional, defaults to image size)"}
                },
                "required": ["base"]
            }
        },
        {
            "name": "drive_inspect",
            "version": "1.0.0",
            "description": "Get detailed information about a drive",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "drive": {"type": "string", "description": "Drive name or ID"}
                },
                "required": ["drive"]
            }
        },
        {
            "name": "drive_delete",
            "version": "1.0.0",
            "description": "Delete a drive (must not be attached to a VM)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "drive": {"type": "string", "description": "Drive name or ID"}
                },
                "required": ["drive"]
            }
        },
        {
            "name": "drive_attach",
            "version": "1.0.0",
            "description": "Attach a drive to a VM",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "drive": {"type": "string", "description": "Drive name or ID"},
                    "vm": {"type": "string", "description": "VM name or ID"},
                    "is_root_device": {"type": "boolean", "description": "Whether this is the root device (default: false)"}
                },
                "required": ["drive", "vm"]
            }
        },
        {
            "name": "drive_detach",
            "version": "1.0.0",
            "description": "Detach a drive from its VM",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "drive": {"type": "string", "description": "Drive name or ID"}
                },
                "required": ["drive"]
            }
        }
    ]);

    let asset_tools = json!([
        {
            "name": "kernel_list",
            "version": "1.0.0",
            "description": "List all downloaded kernels",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "kernel_download",
            "version": "1.0.0",
            "description": "Download a Linux kernel version from the configured provider",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "version": {"type": "string", "description": "Kernel version to download (e.g., '6.1.102')"}
                },
                "required": ["version"]
            }
        },
        {
            "name": "kernel_remove",
            "version": "1.0.0",
            "description": "Remove a downloaded kernel",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "version": {"type": "string", "description": "Kernel version or ID to remove"}
                },
                "required": ["version"]
            }
        },
        {
            "name": "kernel_verify",
            "version": "1.0.0",
            "description": "Verify a downloaded kernel's integrity",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "version": {"type": "string", "description": "Kernel version or ID to verify"}
                },
                "required": ["version"]
            }
        },
        {
            "name": "rootfs_list",
            "version": "1.0.0",
            "description": "List all downloaded rootfs images",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "rootfs_download",
            "version": "1.0.0",
            "description": "Download a rootfs image from the configured provider",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "distro": {"type": "string", "description": "Distribution name (e.g., 'alpine')"},
                    "version": {"type": "string", "description": "Distribution version (e.g., '3.20')"}
                },
                "required": ["distro", "version"]
            }
        },
        {
            "name": "rootfs_remove",
            "version": "1.0.0",
            "description": "Remove a downloaded rootfs image",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "distro": {"type": "string", "description": "Distribution name"},
                    "version": {"type": "string", "description": "Distribution version"}
                },
                "required": ["distro", "version"]
            }
        },
        {
            "name": "firecracker_list",
            "version": "1.0.0",
            "description": "List all downloaded Firecracker versions",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "firecracker_download",
            "version": "1.0.0",
            "description": "Download a Firecracker binary from the configured provider",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "version": {"type": "string", "description": "Firecracker version to download (e.g., '1.10.1')"}
                },
                "required": ["version"]
            }
        },
        {
            "name": "firecracker_remove",
            "version": "1.0.0",
            "description": "Remove a downloaded Firecracker version",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "version": {"type": "string", "description": "Firecracker version or ID to remove"}
                },
                "required": ["version"]
            }
        }
    ]);

    let config_tools = json!([
        {
            "name": "template_list",
            "version": "1.0.0",
            "description": "List all build templates",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "template_create",
            "version": "1.0.0",
            "description": "Create a new build template",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Template name (must be unique)"},
                    "source_type": {"type": "string", "description": "Source type (e.g., 'dockerfile', 'script')"},
                    "source_identifier": {"type": "string", "description": "Source path or identifier"},
                    "overlays": {"type": "object", "description": "Optional key-value overlay map"}
                },
                "required": ["name", "source_type", "source_identifier"]
            }
        },
        {
            "name": "template_inspect",
            "version": "1.0.0",
            "description": "Get detailed information about a template",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template": {"type": "string", "description": "Template name or ID"}
                },
                "required": ["template"]
            }
        },
        {
            "name": "template_delete",
            "version": "1.0.0",
            "description": "Delete a template and its associated builds",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template": {"type": "string", "description": "Template name or ID"}
                },
                "required": ["template"]
            }
        },
        {
            "name": "template_build",
            "version": "1.0.0",
            "description": "Trigger a build from a template (runs in background, returns build record immediately)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template": {"type": "string", "description": "Template name or ID"}
                },
                "required": ["template"]
            }
        },
        {
            "name": "build_list",
            "version": "1.0.0",
            "description": "List all builds, optionally filtered by template",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template": {"type": "string", "description": "Filter by template name"}
                },
                "required": []
            }
        },
        {
            "name": "build_inspect",
            "version": "1.0.0",
            "description": "Get detailed information about a build",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "Build ID (base32-encoded)"}
                },
                "required": ["id"]
            }
        },
        {
            "name": "settings_list",
            "version": "1.0.0",
            "description": "List all settings with their current values",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "settings_get",
            "version": "1.0.0",
            "description": "Get the current value of a setting",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Setting key name"}
                },
                "required": ["key"]
            }
        },
        {
            "name": "settings_update",
            "version": "1.0.0",
            "description": "Update a setting value (validated against schema)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Setting key name"},
                    "value": {"type": "string", "description": "New value for the setting"}
                },
                "required": ["key", "value"]
            }
        },
        {
            "name": "health",
            "version": "1.0.0",
            "description": "Check daemon health status including database info",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "cleanup_network",
            "version": "1.0.0",
            "description": "Clean up orphaned network resources (tap devices, IP allocations)",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }
    ]);

    // Concatenate all tool groups into a single array
    let mut tools = Vec::new();
    for group in [&guest_tools, &vm_tools, &storage_tools, &asset_tools, &config_tools] {
        if let Some(arr) = group.as_array() {
            tools.extend(arr.iter().cloned());
        }
    }

    Ok(json!({ "tools": tools }))
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

        // --- Drive Tools ---
        "drive_list" => {
            let base = optional_str(arguments, "base");
            let svc = nexus_lib::drive_service::DriveService::new(
                state.store.as_ref(),
                state.backend.as_ref(),
                state.drives_root.clone(),
            );
            let drives = svc
                .list_drives(base)
                .map_err(|e| McpError::Internal(e.to_string()))?;
            Ok(mcp_text_response(&drives))
        }

        "drive_create" => {
            let base = require_str(arguments, "base")?;
            let name = optional_str(arguments, "name");
            let size = arguments.get("size").and_then(|v| v.as_u64());
            let svc = nexus_lib::drive_service::DriveService::new(
                state.store.as_ref(),
                state.backend.as_ref(),
                state.drives_root.clone(),
            );
            let drive = svc.create_drive(base, name, size).map_err(|e| match &e {
                nexus_lib::drive_service::DriveServiceError::NotFound(_) => {
                    McpError::InvalidParams(e.to_string())
                }
                nexus_lib::drive_service::DriveServiceError::Store(
                    nexus_lib::store::traits::StoreError::InvalidInput(_),
                ) => McpError::InvalidParams(e.to_string()),
                _ => McpError::Internal(e.to_string()),
            })?;
            Ok(mcp_text_response(&drive))
        }

        "drive_inspect" => {
            let name_or_id = require_str(arguments, "drive")?;
            let svc = nexus_lib::drive_service::DriveService::new(
                state.store.as_ref(),
                state.backend.as_ref(),
                state.drives_root.clone(),
            );
            let drive = svc
                .get_drive(name_or_id)
                .map_err(|e| McpError::Internal(e.to_string()))?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("drive '{}' not found", name_or_id))
                })?;
            Ok(mcp_text_response(&drive))
        }

        "drive_delete" => {
            let name_or_id = require_str(arguments, "drive")?;
            let drive = state
                .store
                .get_drive(name_or_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("drive '{}' not found", name_or_id))
                })?;
            let path = std::path::PathBuf::from(&drive.subvolume_path);
            if path.exists() {
                state.backend.delete_subvolume(&path).map_err(|e| {
                    McpError::Internal(format!("failed to delete subvolume: {}", e))
                })?;
            }
            let deleted = state.store.delete_drive(drive.id).map_err(store_err)?;
            if deleted {
                Ok(mcp_message_response(&format!(
                    "Drive '{}' deleted",
                    name_or_id
                )))
            } else {
                Err(McpError::InvalidParams(format!(
                    "drive '{}' not found",
                    name_or_id
                )))
            }
        }

        "drive_attach" => {
            let drive_id = require_str(arguments, "drive")?;
            let vm_id = require_str(arguments, "vm")?;
            let is_root = arguments
                .get("is_root_device")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let drive = state
                .store
                .get_drive(drive_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("drive '{}' not found", drive_id))
                })?;
            let vm = state
                .store
                .get_vm(vm_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("VM '{}' not found", vm_id))
                })?;
            let attached = state
                .store
                .attach_drive(drive.id, vm.id, is_root)
                .map_err(store_err)?;
            Ok(mcp_text_response(&attached))
        }

        "drive_detach" => {
            let name_or_id = require_str(arguments, "drive")?;
            let drive = state
                .store
                .get_drive(name_or_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("drive '{}' not found", name_or_id))
                })?;
            let detached = state.store.detach_drive(drive.id).map_err(store_err)?;
            Ok(mcp_text_response(&detached))
        }

        // --- Kernel Tools ---
        "kernel_list" => {
            let kernels = state.store.list_kernels().map_err(store_err)?;
            Ok(mcp_text_response(&kernels))
        }

        "kernel_download" => {
            let version = require_str(arguments, "version")?;
            let provider_config = state
                .store
                .get_default_provider("kernel")
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::Internal("no default kernel provider configured".to_string())
                })?;
            let svc = nexus_lib::kernel_service::KernelService::from_provider_config(
                state.store.as_ref(),
                &state.executor,
                state.assets_dir.clone(),
                &provider_config,
            );
            let kernel = svc
                .download(version, &provider_config)
                .await
                .map_err(|e| McpError::Internal(e.to_string()))?;
            Ok(mcp_text_response(&kernel))
        }

        "kernel_remove" => {
            let version = require_str(arguments, "version")?;
            let svc = nexus_lib::kernel_service::KernelService::new(
                state.store.as_ref(),
                &state.executor,
                state.assets_dir.clone(),
            );
            let removed = svc
                .remove(version)
                .map_err(|e| McpError::Internal(e.to_string()))?;
            if removed {
                Ok(mcp_message_response(&format!(
                    "Kernel '{}' removed",
                    version
                )))
            } else {
                Err(McpError::InvalidParams(format!(
                    "kernel '{}' not found",
                    version
                )))
            }
        }

        "kernel_verify" => {
            let version = require_str(arguments, "version")?;
            let svc = nexus_lib::kernel_service::KernelService::new(
                state.store.as_ref(),
                &state.executor,
                state.assets_dir.clone(),
            );
            let result = svc
                .verify(version)
                .map_err(|e| McpError::InvalidParams(e.to_string()))?;
            Ok(mcp_text_response(&result))
        }

        // --- Rootfs Tools ---
        "rootfs_list" => {
            let images = state.store.list_rootfs_images().map_err(store_err)?;
            Ok(mcp_text_response(&images))
        }

        "rootfs_download" => {
            let distro = require_str(arguments, "distro")?;
            let version = require_str(arguments, "version")?;
            let provider_config = state
                .store
                .get_default_provider("rootfs")
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::Internal("no default rootfs provider configured".to_string())
                })?;
            let svc = nexus_lib::rootfs_service::RootfsService::from_provider_config(
                state.store.as_ref(),
                &state.executor,
                state.assets_dir.clone(),
                &provider_config,
            );
            let rootfs = svc
                .download(distro, version, &provider_config)
                .await
                .map_err(|e| McpError::Internal(e.to_string()))?;
            Ok(mcp_text_response(&rootfs))
        }

        "rootfs_remove" => {
            let distro = require_str(arguments, "distro")?;
            let version = require_str(arguments, "version")?;
            let svc = nexus_lib::rootfs_service::RootfsService::new(
                state.store.as_ref(),
                &state.executor,
                state.assets_dir.clone(),
            );
            let removed = svc
                .remove(distro, version)
                .map_err(|e| McpError::Internal(e.to_string()))?;
            if removed {
                Ok(mcp_message_response(&format!(
                    "Rootfs '{}-{}' removed",
                    distro, version
                )))
            } else {
                Err(McpError::InvalidParams(format!(
                    "rootfs '{}-{}' not found",
                    distro, version
                )))
            }
        }

        // --- Firecracker Tools ---
        "firecracker_list" => {
            let versions = state.store.list_firecracker_versions().map_err(store_err)?;
            Ok(mcp_text_response(&versions))
        }

        "firecracker_download" => {
            let version = require_str(arguments, "version")?;
            let provider_config = state
                .store
                .get_default_provider("firecracker")
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::Internal(
                        "no default firecracker provider configured".to_string(),
                    )
                })?;
            let svc = nexus_lib::firecracker_service::FirecrackerService::from_provider(
                state.store.as_ref(),
                &state.executor,
                state.assets_dir.clone(),
                &provider_config,
            );
            let fc = svc
                .download(version, &provider_config)
                .await
                .map_err(|e| McpError::Internal(e.to_string()))?;
            Ok(mcp_text_response(&fc))
        }

        "firecracker_remove" => {
            let version = require_str(arguments, "version")?;
            let svc = nexus_lib::firecracker_service::FirecrackerService::new(
                state.store.as_ref(),
                &state.executor,
                state.assets_dir.clone(),
            );
            let removed = svc
                .remove(version)
                .map_err(|e| McpError::Internal(e.to_string()))?;
            if removed {
                Ok(mcp_message_response(&format!(
                    "Firecracker '{}' removed",
                    version
                )))
            } else {
                Err(McpError::InvalidParams(format!(
                    "firecracker '{}' not found",
                    version
                )))
            }
        }

        // --- Template Tools ---
        "template_list" => {
            let templates = state.store.list_templates().map_err(store_err)?;
            Ok(mcp_text_response(&templates))
        }

        "template_create" => {
            let name = require_str(arguments, "name")?;
            let source_type = require_str(arguments, "source_type")?;
            let source_id = require_str(arguments, "source_identifier")?;
            let overlays = arguments.get("overlays").and_then(|v| {
                serde_json::from_value::<std::collections::HashMap<String, String>>(v.clone()).ok()
            });
            let params = nexus_lib::template::CreateTemplateParams {
                name: name.to_string(),
                source_type: source_type.to_string(),
                source_identifier: source_id.to_string(),
                overlays,
            };
            let tpl = state.store.create_template(&params).map_err(store_err)?;
            Ok(mcp_text_response(&tpl))
        }

        "template_inspect" => {
            let name_or_id = require_str(arguments, "template")?;
            let tpl = state
                .store
                .get_template(name_or_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("template '{}' not found", name_or_id))
                })?;
            Ok(mcp_text_response(&tpl))
        }

        "template_delete" => {
            let name_or_id = require_str(arguments, "template")?;
            let tpl = state
                .store
                .get_template(name_or_id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("template '{}' not found", name_or_id))
                })?;
            let deleted = state.store.delete_template(tpl.id).map_err(store_err)?;
            if deleted {
                Ok(mcp_message_response(&format!(
                    "Template '{}' deleted",
                    name_or_id
                )))
            } else {
                Err(McpError::InvalidParams(format!(
                    "template '{}' not found",
                    name_or_id
                )))
            }
        }

        "template_build" => {
            let name_or_id = require_str(arguments, "template")?;
            let build =
                crate::api::trigger_build_for_template(state, name_or_id).map_err(|e| {
                    match e {
                        crate::api::TriggerBuildError::NotFound(msg) => {
                            McpError::InvalidParams(msg)
                        }
                        crate::api::TriggerBuildError::Internal(msg) => McpError::Internal(msg),
                    }
                })?;
            Ok(mcp_text_response(&build))
        }

        // --- Build Tools ---
        "build_list" => {
            let template = optional_str(arguments, "template");
            let builds = state.store.list_builds(template).map_err(store_err)?;
            Ok(mcp_text_response(&builds))
        }

        "build_inspect" => {
            let id_str = require_str(arguments, "id")?;
            let id = nexus_lib::id::Id::decode(id_str).map_err(|_| {
                McpError::InvalidParams(format!("invalid build ID: '{}'", id_str))
            })?;
            let build = state
                .store
                .get_build(id)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("build '{}' not found", id_str))
                })?;
            Ok(mcp_text_response(&build))
        }

        // --- Settings Tools ---
        "settings_list" => {
            let settings = state.store.list_settings().map_err(store_err)?;
            let response: Vec<serde_json::Value> = settings
                .into_iter()
                .map(|(key, value, value_type)| {
                    json!({"key": key, "value": value, "value_type": value_type})
                })
                .collect();
            Ok(mcp_text_response(&response))
        }

        "settings_get" => {
            let key = require_str(arguments, "key")?;
            let value = state
                .store
                .get_setting(key)
                .map_err(store_err)?
                .ok_or_else(|| {
                    McpError::InvalidParams(format!("setting '{}' not found", key))
                })?;
            let value_type = state
                .store
                .list_settings()
                .ok()
                .and_then(|settings| {
                    settings
                        .iter()
                        .find(|(k, _, _)| k == key)
                        .map(|(_, _, t)| t.clone())
                })
                .unwrap_or_else(|| "string".to_string());
            Ok(mcp_text_response(
                &json!({"key": key, "value": value, "value_type": value_type}),
            ))
        }

        "settings_update" => {
            let key = require_str(arguments, "key")?;
            let value = require_str(arguments, "value")?;
            let value_type = state
                .store
                .list_settings()
                .ok()
                .and_then(|settings| {
                    settings
                        .iter()
                        .find(|(k, _, _)| k == key)
                        .map(|(_, _, t)| t.clone())
                })
                .unwrap_or_else(|| "string".to_string());
            state.store.validate_setting(key, value).map_err(|e| {
                McpError::InvalidParams(format!("validation failed: {}", e))
            })?;
            state
                .store
                .set_setting(key, value, &value_type)
                .map_err(store_err)?;
            Ok(mcp_message_response(&format!(
                "Setting '{}' updated",
                key
            )))
        }

        // --- Admin Tools ---
        "health" => {
            let response = match state.store.status() {
                Ok(db_status) => crate::api::HealthResponse {
                    status: "ok".to_string(),
                    database: Some(crate::api::DatabaseInfo::from(db_status)),
                },
                Err(_) => crate::api::HealthResponse {
                    status: "degraded".to_string(),
                    database: None,
                },
            };
            Ok(mcp_text_response(&response))
        }

        "cleanup_network" => {
            let report = state
                .network_service
                .cleanup_network()
                .map_err(|e| McpError::Internal(e.to_string()))?;
            Ok(mcp_text_response(&report))
        }

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
