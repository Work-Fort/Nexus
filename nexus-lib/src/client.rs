// SPDX-License-Identifier: GPL-2.0-only
use serde::Deserialize;

#[derive(Debug)]
pub enum ClientError {
    /// Cannot connect to the daemon (connection refused, timeout, DNS failure)
    Connect(String),
    /// Connected but got an unexpected response
    Api(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connect(e) => write!(f, "connection error: {e}"),
            ClientError::Api(e) => write!(f, "API error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    pub fn is_connect(&self) -> bool {
        matches!(self, ClientError::Connect(_))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub database: Option<DatabaseInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseInfo {
    pub path: String,
    pub table_count: usize,
    pub size_bytes: Option<u64>,
}

pub struct NexusClient {
    base_url: String,
    http: reqwest::Client,
}

impl NexusClient {
    pub fn new(addr: &str) -> Self {
        NexusClient {
            base_url: format!("http://{addr}"),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn health(&self) -> Result<HealthResponse, ClientError> {
        let url = format!("{}/v1/health", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                ClientError::Connect(e.to_string())
            } else {
                ClientError::Api(e.to_string())
            }
        })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ClientError::Api(format!("unexpected status: {status}")));
        }

        resp.json::<HealthResponse>()
            .await
            .map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn create_vm(&self, params: &crate::vm::CreateVmParams) -> Result<crate::vm::Vm, ClientError> {
        let url = format!("{}/v1/vms", self.base_url);
        let resp = self.http.post(&url).json(params).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                ClientError::Connect(e.to_string())
            } else {
                ClientError::Api(e.to_string())
            }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn list_vms(&self, role: Option<&str>, state: Option<&str>) -> Result<Vec<crate::vm::Vm>, ClientError> {
        let mut url = format!("{}/v1/vms", self.base_url);
        let mut params = Vec::new();
        if let Some(r) = role { params.push(format!("role={r}")); }
        if let Some(s) = state { params.push(format!("state={s}")); }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                ClientError::Connect(e.to_string())
            } else {
                ClientError::Api(e.to_string())
            }
        })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ClientError::Api(format!("unexpected status: {status}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn get_vm(&self, name_or_id: &str) -> Result<Option<crate::vm::Vm>, ClientError> {
        let url = format!("{}/v1/vms/{name_or_id}", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                ClientError::Connect(e.to_string())
            } else {
                ClientError::Api(e.to_string())
            }
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map(Some).map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn delete_vm(&self, name_or_id: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/vms/{name_or_id}", self.base_url);
        let resp = self.http.delete(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                ClientError::Connect(e.to_string())
            } else {
                ClientError::Api(e.to_string())
            }
        })?;

        match resp.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            409 => {
                let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
                Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()))
            }
            other => Err(ClientError::Api(format!("unexpected status: {other}"))),
        }
    }

    pub async fn start_vm(&self, name_or_id: &str) -> Result<crate::vm::Vm, ClientError> {
        let url = format!("{}/v1/vms/{name_or_id}/start", self.base_url);
        let resp = self.http.post(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::Api(format!("VM '{}' not found", name_or_id)));
        }
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn stop_vm(&self, name_or_id: &str) -> Result<crate::vm::Vm, ClientError> {
        let url = format!("{}/v1/vms/{name_or_id}/stop", self.base_url);
        let resp = self.http.post(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::Api(format!("VM '{}' not found", name_or_id)));
        }
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn vm_logs(&self, name_or_id: &str, tail: Option<usize>) -> Result<String, ClientError> {
        let mut url = format!("{}/v1/vms/{name_or_id}/logs", self.base_url);
        if let Some(n) = tail {
            url.push_str(&format!("?tail={n}"));
        }
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::Api(format!("VM '{}' not found or no logs available", name_or_id)));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.text().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    // --- Image methods ---

    pub async fn import_image(&self, params: &crate::workspace::ImportImageParams) -> Result<crate::workspace::MasterImage, ClientError> {
        let url = format!("{}/v1/images", self.base_url);
        let resp = self.http.post(&url).json(params).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn list_images(&self) -> Result<Vec<crate::workspace::MasterImage>, ClientError> {
        let url = format!("{}/v1/images", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn get_image(&self, name_or_id: &str) -> Result<Option<crate::workspace::MasterImage>, ClientError> {
        let url = format!("{}/v1/images/{name_or_id}", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map(Some).map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn delete_image(&self, name_or_id: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/images/{name_or_id}", self.base_url);
        let resp = self.http.delete(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        match resp.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            409 => {
                let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
                Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()))
            }
            other => Err(ClientError::Api(format!("unexpected status: {other}"))),
        }
    }

    // --- Workspace methods ---

    pub async fn create_workspace(&self, params: &crate::workspace::CreateWorkspaceParams) -> Result<crate::workspace::Workspace, ClientError> {
        let url = format!("{}/v1/workspaces", self.base_url);
        let resp = self.http.post(&url).json(params).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn list_workspaces(&self, base: Option<&str>) -> Result<Vec<crate::workspace::Workspace>, ClientError> {
        let mut url = format!("{}/v1/workspaces", self.base_url);
        if let Some(b) = base {
            url.push_str(&format!("?base={b}"));
        }
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn get_workspace(&self, name_or_id: &str) -> Result<Option<crate::workspace::Workspace>, ClientError> {
        let url = format!("{}/v1/workspaces/{name_or_id}", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map(Some).map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn delete_workspace(&self, name_or_id: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/workspaces/{name_or_id}", self.base_url);
        let resp = self.http.delete(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        match resp.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            409 => {
                let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
                Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()))
            }
            other => Err(ClientError::Api(format!("unexpected status: {other}"))),
        }
    }

    pub async fn attach_workspace(
        &self,
        name_or_id: &str,
        vm_id: &str,
        is_root_device: bool,
    ) -> Result<crate::workspace::Workspace, ClientError> {
        let url = format!("{}/v1/workspaces/{name_or_id}/attach", self.base_url);
        let resp = self.http.post(&url)
            .json(&serde_json::json!({
                "vm_id": vm_id,
                "is_root_device": is_root_device,
            }))
            .send().await.map_err(|e| {
                if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
                else { ClientError::Api(e.to_string()) }
            })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::Api(format!("workspace '{}' not found", name_or_id)));
        }
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn detach_workspace(&self, name_or_id: &str) -> Result<crate::workspace::Workspace, ClientError> {
        let url = format!("{}/v1/workspaces/{name_or_id}/detach", self.base_url);
        let resp = self.http.post(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::Api(format!("workspace '{}' not found", name_or_id)));
        }
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    // --- Kernel methods ---

    pub async fn list_kernels(&self) -> Result<Vec<crate::asset::Kernel>, ClientError> {
        let url = format!("{}/v1/kernels", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }
        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn download_kernel(&self, version: &str) -> Result<crate::asset::Kernel, ClientError> {
        let url = format!("{}/v1/kernels/download", self.base_url);
        let resp = self.http.post(&url)
            .json(&serde_json::json!({ "version": version }))
            .send().await.map_err(|e| {
                if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
                else { ClientError::Api(e.to_string()) }
            })?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status: {body}")));
        }
        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn remove_kernel(&self, version: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/kernels/{version}", self.base_url);
        let resp = self.http.delete(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;
        match resp.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            other => Err(ClientError::Api(format!("unexpected status: {other}"))),
        }
    }

    pub async fn verify_kernel(&self, version: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/kernels/{version}/verify", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }
        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    // --- Rootfs methods ---

    pub async fn list_rootfs(&self) -> Result<Vec<crate::asset::RootfsImage>, ClientError> {
        let url = format!("{}/v1/rootfs-images", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }
        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn download_rootfs(&self, distro: &str, version: &str) -> Result<crate::asset::RootfsImage, ClientError> {
        let url = format!("{}/v1/rootfs-images/download", self.base_url);
        let resp = self.http.post(&url)
            .json(&serde_json::json!({ "distro": distro, "version": version }))
            .send().await.map_err(|e| {
                if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
                else { ClientError::Api(e.to_string()) }
            })?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status: {body}")));
        }
        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn remove_rootfs(&self, distro: &str, version: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/rootfs-images/{distro}/{version}", self.base_url);
        let resp = self.http.delete(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;
        match resp.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            other => Err(ClientError::Api(format!("unexpected status: {other}"))),
        }
    }

    // --- Firecracker methods ---

    pub async fn list_firecracker(&self) -> Result<Vec<crate::asset::FirecrackerVersion>, ClientError> {
        let url = format!("{}/v1/firecracker", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }
        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn download_firecracker(&self, version: &str) -> Result<crate::asset::FirecrackerVersion, ClientError> {
        let url = format!("{}/v1/firecracker/download", self.base_url);
        let resp = self.http.post(&url)
            .json(&serde_json::json!({ "version": version }))
            .send().await.map_err(|e| {
                if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
                else { ClientError::Api(e.to_string()) }
            })?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status: {body}")));
        }
        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn remove_firecracker(&self, version: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/firecracker/{version}", self.base_url);
        let resp = self.http.delete(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;
        match resp.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            other => Err(ClientError::Api(format!("unexpected status: {other}"))),
        }
    }

    // --- Template methods ---

    pub async fn create_template(&self, params: &crate::template::CreateTemplateParams) -> Result<crate::template::Template, ClientError> {
        let url = format!("{}/v1/templates", self.base_url);
        let resp = self.http.post(&url).json(params).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::CONFLICT {
            let body: serde_json::Value = resp.json().await.map_err(|e| ClientError::Api(e.to_string()))?;
            return Err(ClientError::Api(body["error"].as_str().unwrap_or("conflict").to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn list_templates(&self) -> Result<Vec<crate::template::Template>, ClientError> {
        let url = format!("{}/v1/templates", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn get_template(&self, name_or_id: &str) -> Result<Option<crate::template::Template>, ClientError> {
        let url = format!("{}/v1/templates/{name_or_id}", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map(Some).map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn delete_template(&self, name_or_id: &str) -> Result<bool, ClientError> {
        let url = format!("{}/v1/templates/{name_or_id}", self.base_url);
        let resp = self.http.delete(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        match resp.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            other => Err(ClientError::Api(format!("unexpected status: {other}"))),
        }
    }

    // --- Build methods ---

    pub async fn trigger_build(&self, template_name_or_id: &str) -> Result<crate::template::Build, ClientError> {
        let url = format!("{}/v1/templates/{template_name_or_id}/build", self.base_url);
        let resp = self.http.post(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::Api(format!("template '{template_name_or_id}' not found")));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Api(format!("unexpected status {status}: {body}")));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn list_builds(&self, template: Option<&str>) -> Result<Vec<crate::template::Build>, ClientError> {
        let mut url = format!("{}/v1/builds", self.base_url);
        if let Some(t) = template {
            url.push_str(&format!("?template={t}"));
        }
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map_err(|e| ClientError::Api(e.to_string()))
    }

    pub async fn get_build(&self, id: &str) -> Result<Option<crate::template::Build>, ClientError> {
        let url = format!("{}/v1/builds/{id}", self.base_url);
        let resp = self.http.get(&url).send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() { ClientError::Connect(e.to_string()) }
            else { ClientError::Api(e.to_string()) }
        })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
        if !resp.status().is_success() {
            return Err(ClientError::Api(format!("unexpected status: {}", resp.status())));
        }

        resp.json().await.map(Some).map_err(|e| ClientError::Api(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_client_uses_default_addr() {
        let client = NexusClient::new("127.0.0.1:9600");
        assert_eq!(client.base_url(), "http://127.0.0.1:9600");
    }

    #[test]
    fn client_with_custom_addr() {
        let client = NexusClient::new("10.0.0.1:8080");
        assert_eq!(client.base_url(), "http://10.0.0.1:8080");
    }

    #[test]
    fn health_response_with_database_deserializes() {
        let json = r#"{"status":"ok","database":{"path":"/tmp/test.db","table_count":2,"size_bytes":8192}}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        let db = resp.database.unwrap();
        assert_eq!(db.path, "/tmp/test.db");
        assert_eq!(db.table_count, 2);
        assert_eq!(db.size_bytes, Some(8192));
    }

    #[test]
    fn health_response_without_database_deserializes() {
        let json = r#"{"status":"ok"}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.database.is_none());
    }

    #[tokio::test]
    async fn health_returns_error_when_daemon_not_running() {
        // Use a port that nothing is listening on
        let client = NexusClient::new("127.0.0.1:19999");
        let result = client.health().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ClientError::Connect(_) => {} // expected
            other => panic!("expected Connect error, got: {other}"),
        }
    }

    #[test]
    fn vm_response_deserializes() {
        let json = r#"{"id":"abc","name":"test","role":"work","state":"created","cid":3,"vcpu_count":1,"mem_size_mib":128,"created_at":1000,"updated_at":1000}"#;
        let vm: crate::vm::Vm = serde_json::from_str(json).unwrap();
        assert_eq!(vm.name, "test");
        assert_eq!(vm.cid, 3);
    }

    #[test]
    fn template_response_deserializes() {
        let json = r#"{"id":"tpl-1","name":"base","version":1,"source_type":"rootfs","source_identifier":"https://example.com/rootfs.tar.gz","created_at":1000,"updated_at":1000}"#;
        let tpl: crate::template::Template = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.name, "base");
        assert_eq!(tpl.version, 1);
    }

    #[test]
    fn build_response_deserializes() {
        let json = r#"{"id":"bld-1","template_id":"tpl-1","template_version":1,"name":"base","source_type":"rootfs","source_identifier":"https://example.com/rootfs.tar.gz","status":"building","created_at":1000}"#;
        let build: crate::template::Build = serde_json::from_str(json).unwrap();
        assert_eq!(build.status, crate::template::BuildStatus::Building);
    }

    #[test]
    fn start_vm_response_deserializes() {
        let json = r#"{"id":"abc","name":"test","role":"work","state":"running","cid":3,"vcpu_count":1,"mem_size_mib":128,"created_at":1000,"updated_at":1000,"pid":1234,"socket_path":"/run/sock","uds_path":"/run/vsock","console_log_path":"/run/console.log"}"#;
        let vm: crate::vm::Vm = serde_json::from_str(json).unwrap();
        assert_eq!(vm.state, crate::vm::VmState::Running);
        assert_eq!(vm.pid, Some(1234));
    }
}
