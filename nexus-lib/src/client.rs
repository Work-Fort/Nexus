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
}
