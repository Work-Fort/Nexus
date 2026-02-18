use axum::{Json, Router, routing::get};
use axum::extract::State;
use axum::http::StatusCode;
use nexus_lib::store::traits::{DbStatus, StateStore};
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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use nexus_lib::store::traits::StoreError;
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
    }

    struct FailingStore;

    impl StateStore for FailingStore {
        fn init(&self) -> Result<(), StoreError> { Ok(()) }
        fn status(&self) -> Result<DbStatus, StoreError> {
            Err(StoreError::Query("disk I/O error".to_string()))
        }
        fn close(&self) -> Result<(), StoreError> { Ok(()) }
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
}
