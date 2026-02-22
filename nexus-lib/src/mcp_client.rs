use anyhow::{Context, Result};
use nexus_protocol::jsonrpc::{Request, Response, RequestId, Notification};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// MCP client for invoking tools via JSON-RPC over vsock
pub struct McpClient {
    stream: Arc<Mutex<UnixStream>>,
    request_id: Arc<Mutex<i64>>,
}

impl McpClient {
    pub fn new(stream: Arc<Mutex<UnixStream>>) -> Self {
        Self {
            stream,
            request_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Invoke file_read tool
    pub async fn file_read(&self, path: &str) -> Result<String> {
        let params = serde_json::json!({ "path": path });
        let result = self.call_method("file_read", params).await?;

        result["content"]
            .as_str()
            .map(String::from)
            .context("missing 'content' in file_read response")
    }

    /// Invoke file_write tool
    pub async fn file_write(&self, path: &str, content: &str) -> Result<usize> {
        let params = serde_json::json!({
            "path": path,
            "content": content
        });
        let result = self.call_method("file_write", params).await?;

        result["written"]
            .as_u64()
            .map(|n| n as usize)
            .context("missing 'written' in file_write response")
    }

    /// Invoke file_delete tool
    pub async fn file_delete(&self, path: &str) -> Result<bool> {
        let params = serde_json::json!({ "path": path });
        let result = self.call_method("file_delete", params).await?;

        result["deleted"]
            .as_bool()
            .context("missing 'deleted' in file_delete response")
    }

    /// Invoke run_command tool with streaming output
    pub async fn run_command<F>(
        &self,
        command: &str,
        args: &[String],
        mut on_stdout: F,
    ) -> Result<i32>
    where
        F: FnMut(String) + Send,
    {
        let params = serde_json::json!({
            "command": command,
            "args": args
        });

        let request = self.build_request_with_id("run_command", params).await;
        let request_id = request.id.clone();

        // Send request
        self.send_request(&request).await?;

        // Read streaming notifications and final response
        let mut stream = self.stream.lock().await;
        let mut reader = BufReader::new(&mut *stream);
        let mut line = String::new();
        let mut exit_code = None;

        loop {
            line.clear();
            reader.read_line(&mut line).await
                .context("failed to read run_command response")?;

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Try to parse as notification first
            if let Ok(notif) = serde_json::from_str::<Notification>(trimmed) {
                if notif.method == "run_command.stdout" {
                    if let Some(params) = notif.params {
                        if let Some(chunk) = params["chunk"].as_str() {
                            on_stdout(chunk.to_string());
                        }
                    }
                }
                continue;
            }

            // Try to parse as response
            if let Ok(resp) = serde_json::from_str::<Response>(trimmed) {
                if resp.id == request_id {
                    if let Some(result) = resp.result {
                        exit_code = result["exit_code"].as_i64().map(|n| n as i32);
                        break;
                    } else if let Some(error) = resp.error {
                        anyhow::bail!("run_command error: {}", error.message);
                    }
                }
            }
        }

        exit_code.context("missing exit_code in run_command response")
    }

    async fn call_method(&self, method: &str, params: Value) -> Result<Value> {
        let request = self.build_request_with_id(method, params).await;
        let request_id = request.id.clone();

        self.send_request(&request).await?;

        let response = self.read_response().await?;

        if response.id != request_id {
            anyhow::bail!("response ID mismatch: expected {:?}, got {:?}", request_id, response.id);
        }

        if let Some(error) = response.error {
            anyhow::bail!("JSON-RPC error {}: {}", error.code, error.message);
        }

        response.result.context("missing result in response")
    }

    async fn build_request_with_id(&self, method: &str, params: Value) -> Request {
        let mut id_lock = self.request_id.lock().await;
        let id = *id_lock;
        *id_lock += 1;
        drop(id_lock);

        Self::build_request(id, method, params)
    }

    fn build_request(id: i64, method: &str, params: Value) -> Request {
        Request {
            jsonrpc: "2.0".to_string(),
            id: Some(RequestId::Number(id)),
            method: method.to_string(),
            params: Some(params),
        }
    }

    async fn send_request(&self, request: &Request) -> Result<()> {
        let json = serde_json::to_string(request)?;
        let mut stream = self.stream.lock().await;

        stream.write_all(json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        info!("sent MCP request: {}", request.method);
        Ok(())
    }

    async fn read_response(&self) -> Result<Response> {
        let mut stream = self.stream.lock().await;
        let mut reader = BufReader::new(&mut *stream);
        let mut line = String::new();

        reader.read_line(&mut line).await
            .context("failed to read response")?;

        serde_json::from_str(&line).context("failed to parse response JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_file_read_request() {
        let req = McpClient::build_request(1, "file_read", serde_json::json!({
            "path": "/tmp/test.txt"
        }));

        assert_eq!(req.method, "file_read");
        assert_eq!(req.jsonrpc, "2.0");
        assert!(req.params.is_some());
    }

    #[test]
    fn parse_file_read_response() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"content":"Alpine Linux"}}"#;
        let resp: nexus_protocol::jsonrpc::Response = serde_json::from_str(json).unwrap();

        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        let content = result["content"].as_str().unwrap();
        assert_eq!(content, "Alpine Linux");
    }
}
