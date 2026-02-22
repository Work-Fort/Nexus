use anyhow::{Context, Result};
use nexus_protocol::jsonrpc::{self, Request, Response, Notification, RequestId};
use serde_json::Value;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{info, warn, error};

const MCP_PORT: u32 = 200;

/// Start MCP JSON-RPC server on port 200
pub async fn run_mcp_server() -> Result<()> {
    let addr = VsockAddr::new(VMADDR_CID_ANY, MCP_PORT);
    let listener = VsockListener::bind(addr)
        .with_context(|| format!("failed to bind MCP listener on port {}", MCP_PORT))?;

    info!("MCP server started on port {}", MCP_PORT);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!("MCP connection from {:?}", peer);
                tokio::spawn(handle_mcp_connection(stream));
            }
            Err(e) => {
                error!("failed to accept MCP connection: {}", e);
            }
        }
    }
}

async fn handle_mcp_connection(stream: VsockStream) {
    if let Err(e) = handle_mcp_connection_inner(stream).await {
        error!("MCP connection error: {}", e);
    }
}

async fn handle_mcp_connection_inner(stream: VsockStream) -> Result<()> {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await
            .context("failed to read from MCP stream")?;

        if n == 0 {
            info!("MCP connection closed");
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse JSON-RPC request
        let request: Request = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                warn!("failed to parse JSON-RPC request: {}", e);
                let error_response = Response::error(
                    None,
                    jsonrpc::error_codes::PARSE_ERROR,
                    format!("Parse error: {}", e),
                );
                send_response_split(&mut write_half, &error_response).await?;
                continue;
            }
        };

        let request_id = request.id.clone();
        let method = request.method.as_str();

        info!("MCP request: method={}, id={:?}", method, request_id);

        // Dispatch to tool handler
        let response = match method {
            "file_read" => {
                handle_tool_request(request_id, request.params, handle_file_read).await
            }
            "file_write" => {
                handle_tool_request(request_id, request.params, handle_file_write).await
            }
            "file_delete" => {
                handle_tool_request(request_id, request.params, handle_file_delete).await
            }
            "run_command" => {
                // run_command handles its own response (streaming)
                handle_run_command(request_id, request.params, &mut write_half).await;
                continue; // Don't send response here
            }
            _ => {
                Response::error(
                    request_id,
                    jsonrpc::error_codes::METHOD_NOT_FOUND,
                    format!("Method not found: {}", method),
                )
            }
        };

        send_response_split(&mut write_half, &response).await?;
    }

    Ok(())
}

async fn handle_tool_request<F, Fut>(
    id: Option<RequestId>,
    params: Option<Value>,
    handler: F,
) -> Response
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let params = match params {
        Some(p) => p,
        None => {
            return Response::error(
                id,
                jsonrpc::error_codes::INVALID_PARAMS,
                "Missing params",
            );
        }
    };

    match handler(params).await {
        Ok(result) => {
            let request_id = id.unwrap_or(RequestId::Number(0));
            Response::success(request_id, result)
        }
        Err(e) => Response::error(
            id,
            jsonrpc::error_codes::INTERNAL_ERROR,
            e.to_string(),
        ),
    }
}

async fn send_response_split<W: AsyncWriteExt + Unpin>(writer: &mut W, response: &Response) -> Result<()> {
    let json = serde_json::to_string(response)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn send_notification<W: AsyncWriteExt + Unpin>(writer: &mut W, notification: &Notification) -> Result<()> {
    let json = serde_json::to_string(notification)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

/// file_read: read file contents
///
/// Security model: Unrestricted filesystem access within the VM.
/// The VM itself is the security boundary. This tool is for AI agent control,
/// which requires full filesystem access to perform tasks.
async fn handle_file_read(params: Value) -> Result<Value> {
    let path = params["path"]
        .as_str()
        .context("missing or invalid 'path' param")?;

    let content = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read file: {}", path))?;

    Ok(serde_json::json!({ "content": content }))
}

/// file_write: write content to file
///
/// Security model: Unrestricted filesystem access within the VM.
async fn handle_file_write(params: Value) -> Result<Value> {
    let path = params["path"]
        .as_str()
        .context("missing or invalid 'path' param")?;
    let content = params["content"]
        .as_str()
        .context("missing or invalid 'content' param")?;

    // Create parent directories if needed
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent).await
            .with_context(|| format!("failed to create parent dirs for {}", path))?;
    }

    fs::write(path, content)
        .await
        .with_context(|| format!("failed to write file: {}", path))?;

    Ok(serde_json::json!({ "written": content.len() }))
}

/// file_delete: delete a file
///
/// Security model: Unrestricted filesystem access within the VM.
async fn handle_file_delete(params: Value) -> Result<Value> {
    let path = params["path"]
        .as_str()
        .context("missing or invalid 'path' param")?;

    fs::remove_file(path)
        .await
        .with_context(|| format!("failed to delete file: {}", path))?;

    Ok(serde_json::json!({ "deleted": true }))
}

/// run_command: execute a command and stream stdout/stderr
///
/// Security model: Unrestricted command execution within the VM.
/// Commands run as the guest-agent user. The VM is the security boundary.
///
/// Uses channel-based streaming because VsockStream cannot be cloned (no try_clone method).
/// Stdout and stderr are multiplexed through an mpsc channel to a single writer task.
async fn handle_run_command<W: AsyncWriteExt + Unpin + Send + 'static>(
    request_id: Option<RequestId>,
    params: Option<Value>,
    writer: &mut W,
) {
    let result = handle_run_command_inner(request_id.clone(), params, writer).await;

    let response = match result {
        Ok(result_value) => {
            let id = request_id.unwrap_or(RequestId::Number(0));
            Response::success(id, result_value)
        }
        Err(e) => {
            Response::error(
                request_id,
                jsonrpc::error_codes::INTERNAL_ERROR,
                e.to_string(),
            )
        }
    };

    let _ = send_response_split(writer, &response).await;
}

async fn handle_run_command_inner<W: AsyncWriteExt + Unpin + Send + 'static>(
    request_id: Option<RequestId>,
    params: Option<Value>,
    writer: &mut W,
) -> Result<Value> {
    let params = params.context("missing params for run_command")?;

    let command = params["command"]
        .as_str()
        .context("missing or invalid 'command' param")?;
    let args = params["args"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    info!("running command: {} {:?}", command, args);

    let mut child = Command::new(command)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn command")?;

    let stdout = child.stdout.take().context("failed to capture stdout")?;
    let stderr = child.stderr.take().context("failed to capture stderr")?;

    // Channel-based streaming: mpsc channel to serialize stdout/stderr notifications
    // This is necessary because the split writer can't be shared between tasks
    let (tx, mut rx) = mpsc::channel::<Notification>(32);

    let request_id_clone = request_id.clone();
    let tx_stdout = tx.clone();

    // Spawn stdout reader task
    let stdout_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
            let notif = Notification::new(
                "run_command.stdout",
                Some(serde_json::json!({
                    "request_id": request_id_clone,
                    "chunk": line
                })),
            );
            let _ = tx_stdout.send(notif).await;
            line.clear();
        }
    });

    let request_id_clone2 = request_id.clone();
    let tx_stderr = tx.clone();

    // Spawn stderr reader task
    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
            let notif = Notification::new(
                "run_command.stderr",
                Some(serde_json::json!({
                    "request_id": request_id_clone2,
                    "chunk": line
                })),
            );
            let _ = tx_stderr.send(notif).await;
            line.clear();
        }
    });

    // Drop original sender so channel closes when tasks finish
    drop(tx);

    // Process notifications as they arrive and wait for child to complete
    let exit_status = loop {
        tokio::select! {
            Some(notif) = rx.recv() => {
                if let Err(e) = send_notification(writer, &notif).await {
                    error!("failed to send notification: {}", e);
                }
            }
            status = child.wait() => {
                // Child process completed
                let status = status.context("failed to wait for child")?;

                // Drain any remaining notifications
                while let Some(notif) = rx.recv().await {
                    if let Err(e) = send_notification(writer, &notif).await {
                        error!("failed to send notification: {}", e);
                        break;
                    }
                }

                break status;
            }
        }
    };

    // Wait for reader tasks to complete
    let _ = tokio::join!(stdout_task, stderr_task);

    Ok(serde_json::json!({
        "exit_code": exit_status.code().unwrap_or(-1),
        "success": exit_status.success()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn file_read_returns_content() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "test content\n").unwrap();
        let path = file.path().to_string_lossy().to_string();

        let params = serde_json::json!({ "path": path });
        let result = handle_file_read(params).await.unwrap();

        assert!(result["content"].as_str().unwrap().contains("test content"));
    }

    #[tokio::test]
    async fn file_write_creates_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.txt");
        let path_str = path.to_string_lossy().to_string();

        let params = serde_json::json!({
            "path": path_str,
            "content": "hello world"
        });

        let result = handle_file_write(params).await.unwrap();
        assert_eq!(result["written"], 11);

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[tokio::test]
    async fn file_delete_removes_file() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        let path_str = path.to_string_lossy().to_string();

        // Persist the file so it doesn't get auto-deleted when file is dropped
        let (_file, path) = file.keep().unwrap();

        let params = serde_json::json!({ "path": path_str });
        let result = handle_file_delete(params).await.unwrap();
        assert_eq!(result["deleted"], true);

        assert!(!path.exists());
    }
}
