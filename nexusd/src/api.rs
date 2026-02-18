use axum::{Json, Router, routing::{get, post}};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use nexus_lib::store::traits::{DbStatus, StateStore, StoreError};
use nexus_lib::vm::CreateVmParams;
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseInfo>,
}

#[derive(Serialize)]
pub struct DatabaseInfo {
    pub path: String,
    pub table_count: usize,
    pub size_bytes: Option<u64>,
}

impl From<DbStatus> for DatabaseInfo {
    fn from(s: DbStatus) -> Self {
        DatabaseInfo {
            path: s.path,
            table_count: s.table_count,
            size_bytes: s.size_bytes,
        }
    }
}

/// Application state shared across handlers.
pub struct AppState {
    pub store: Box<dyn StateStore + Send + Sync>,
}

async fn health(State(state): State<Arc<AppState>>) -> (StatusCode, Json<HealthResponse>) {
    match state.store.status() {
        Ok(db_status) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_string(),
                database: Some(DatabaseInfo::from(db_status)),
            }),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "degraded".to_string(),
                database: None,
            }),
        ),
    }
}

async fn create_vm(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CreateVmParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.create_vm(&params) {
        Ok(vm) => (StatusCode::CREATED, Json(serde_json::to_value(vm).unwrap())),
        Err(StoreError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn list_vms(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let role = query.get("role").map(|s| s.as_str());
    let vm_state = query.get("state").map(|s| s.as_str());

    match state.store.list_vms(role, vm_state) {
        Ok(vms) => (StatusCode::OK, Json(serde_json::to_value(vms).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn get_vm(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => (StatusCode::OK, Json(serde_json::to_value(vm).unwrap())),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("VM '{}' not found", name_or_id)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn delete_vm(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.delete_vm(&name_or_id) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("VM '{}' not found", name_or_id)})),
        ),
        Err(StoreError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/vms", post(create_vm).get(list_vms))
        .route("/v1/vms/{name_or_id}", get(get_vm).delete(delete_vm))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use nexus_lib::store::sqlite::SqliteStore;
    use nexus_lib::store::traits::StoreError;
    use nexus_lib::vm::{CreateVmParams, Vm};
    use nexus_lib::workspace::{ImportImageParams, MasterImage, Workspace};
    use tower::ServiceExt;

    /// A mock store for testing the health endpoint without SQLite.
    struct MockStore;

    impl StateStore for MockStore {
        fn init(&self) -> Result<(), StoreError> { Ok(()) }
        fn status(&self) -> Result<DbStatus, StoreError> {
            Ok(DbStatus {
                path: "/tmp/mock.db".to_string(),
                table_count: 2,
                size_bytes: Some(8192),
            })
        }
        fn close(&self) -> Result<(), StoreError> { Ok(()) }
        fn create_vm(&self, _params: &CreateVmParams) -> Result<Vm, StoreError> {
            unimplemented!()
        }
        fn list_vms(&self, _role: Option<&str>, _state: Option<&str>) -> Result<Vec<Vm>, StoreError> {
            unimplemented!()
        }
        fn get_vm(&self, _name_or_id: &str) -> Result<Option<Vm>, StoreError> {
            unimplemented!()
        }
        fn delete_vm(&self, _name_or_id: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn create_image(&self, _params: &ImportImageParams, _subvolume_path: &str) -> Result<MasterImage, StoreError> {
            unimplemented!()
        }
        fn list_images(&self) -> Result<Vec<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn get_image(&self, _name_or_id: &str) -> Result<Option<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn delete_image(&self, _name_or_id: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn create_workspace(&self, _name: Option<&str>, _subvolume_path: &str, _master_image_id: &str) -> Result<Workspace, StoreError> {
            unimplemented!()
        }
        fn list_workspaces(&self, _base: Option<&str>) -> Result<Vec<Workspace>, StoreError> {
            unimplemented!()
        }
        fn get_workspace(&self, _name_or_id: &str) -> Result<Option<Workspace>, StoreError> {
            unimplemented!()
        }
        fn delete_workspace(&self, _name_or_id: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
    }

    struct FailingStore;

    impl StateStore for FailingStore {
        fn init(&self) -> Result<(), StoreError> { Ok(()) }
        fn status(&self) -> Result<DbStatus, StoreError> {
            Err(StoreError::Query("disk I/O error".to_string()))
        }
        fn close(&self) -> Result<(), StoreError> { Ok(()) }
        fn create_vm(&self, _params: &CreateVmParams) -> Result<Vm, StoreError> {
            unimplemented!()
        }
        fn list_vms(&self, _role: Option<&str>, _state: Option<&str>) -> Result<Vec<Vm>, StoreError> {
            unimplemented!()
        }
        fn get_vm(&self, _name_or_id: &str) -> Result<Option<Vm>, StoreError> {
            unimplemented!()
        }
        fn delete_vm(&self, _name_or_id: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn create_image(&self, _params: &ImportImageParams, _subvolume_path: &str) -> Result<MasterImage, StoreError> {
            unimplemented!()
        }
        fn list_images(&self) -> Result<Vec<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn get_image(&self, _name_or_id: &str) -> Result<Option<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn delete_image(&self, _name_or_id: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn create_workspace(&self, _name: Option<&str>, _subvolume_path: &str, _master_image_id: &str) -> Result<Workspace, StoreError> {
            unimplemented!()
        }
        fn list_workspaces(&self, _base: Option<&str>) -> Result<Vec<Workspace>, StoreError> {
            unimplemented!()
        }
        fn get_workspace(&self, _name_or_id: &str) -> Result<Option<Workspace>, StoreError> {
            unimplemented!()
        }
        fn delete_workspace(&self, _name_or_id: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn health_returns_ok_with_db_info() {
        let state = Arc::new(AppState {
            store: Box::new(MockStore),
        });
        let app = router(state);

        let response = app
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "ok");
        assert_eq!(json["database"]["path"], "/tmp/mock.db");
        assert_eq!(json["database"]["table_count"], 2);
        assert_eq!(json["database"]["size_bytes"], 8192);
    }

    #[tokio::test]
    async fn health_returns_503_when_db_unhealthy() {
        let state = Arc::new(AppState {
            store: Box::new(FailingStore),
        });
        let app = router(state);

        let response = app
            .oneshot(Request::get("/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "degraded");
        assert!(json.get("database").is_none() || json["database"].is_null());
    }

    fn test_state() -> Arc<AppState> {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = SqliteStore::open_and_init(&db_path).unwrap();
        // Leak the tempdir so it lives long enough
        std::mem::forget(dir);
        Arc::new(AppState {
            store: Box::new(store),
        })
    }

    #[tokio::test]
    async fn create_vm_returns_201() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::post("/v1/vms")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "test-vm"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "test-vm");
        assert_eq!(json["state"], "created");
        assert_eq!(json["role"], "work");
        assert_eq!(json["cid"], 3);
    }

    #[tokio::test]
    async fn create_vm_duplicate_returns_409() {
        let state = test_state();
        let app = router(state.clone());

        // Create first
        app.clone()
            .oneshot(
                Request::post("/v1/vms")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "dup"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Create duplicate
        let response = router(state)
            .oneshot(
                Request::post("/v1/vms")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "dup"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn list_vms_returns_array() {
        let state = test_state();

        // Create a VM first
        router(state.clone())
            .oneshot(
                Request::post("/v1/vms")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "list-me"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(Request::get("/v1/vms").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["name"], "list-me");
    }

    #[tokio::test]
    async fn get_vm_returns_detail() {
        let state = test_state();

        router(state.clone())
            .oneshot(
                Request::post("/v1/vms")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "detail-vm"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(
                Request::get("/v1/vms/detail-vm")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "detail-vm");
    }

    #[tokio::test]
    async fn get_vm_not_found_returns_404() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::get("/v1/vms/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_vm_returns_204() {
        let state = test_state();

        router(state.clone())
            .oneshot(
                Request::post("/v1/vms")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "doomed"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(
                Request::delete("/v1/vms/doomed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_vm_not_found_returns_404() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::delete("/v1/vms/ghost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
