// SPDX-License-Identifier: GPL-2.0-only
use axum::{Json, Router, routing::{delete, get, post}};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use nexus_lib::backend::traits::WorkspaceBackend;
use nexus_lib::config::FirecrackerConfig;
use nexus_lib::firecracker_service::FirecrackerService;
use nexus_lib::kernel_service::KernelService;
use nexus_lib::pipeline::PipelineExecutor;
use nexus_lib::rootfs_service::RootfsService;
use nexus_lib::store::traits::{DbStatus, StateStore, StoreError};
use nexus_lib::template::CreateTemplateParams;
use nexus_lib::vm::{CreateVmParams, VmState};
use nexus_lib::vm_service;
use nexus_lib::workspace::{ImportImageParams, CreateWorkspaceParams};
use nexus_lib::workspace_service::{WorkspaceService, WorkspaceServiceError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

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

/// Tracks a running Firecracker process and its boot history record ID.
pub struct TrackedProcess {
    pub child: std::process::Child,
    pub boot_id: String,
}

/// Application state shared across handlers.
pub struct AppState {
    pub store: Box<dyn StateStore + Send + Sync>,
    pub backend: Box<dyn WorkspaceBackend>,
    pub workspaces_root: PathBuf,
    pub assets_dir: PathBuf,
    pub executor: PipelineExecutor,
    pub firecracker: FirecrackerConfig,
    /// Map of VM ID -> tracked Firecracker process (child + boot_id).
    /// Protected by a tokio Mutex for async access.
    pub processes: TokioMutex<HashMap<String, TrackedProcess>>,
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

async fn import_image(
    State(state): State<Arc<AppState>>,
    Json(params): Json<ImportImageParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.import_image(&params) {
        Ok(img) => (StatusCode::CREATED, Json(serde_json::to_value(img).unwrap())),
        Err(WorkspaceServiceError::Store(StoreError::Conflict(msg))) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn list_images(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.list_images() {
        Ok(imgs) => (StatusCode::OK, Json(serde_json::to_value(imgs).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn get_image(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.get_image(&name_or_id) {
        Ok(Some(img)) => (StatusCode::OK, Json(serde_json::to_value(img).unwrap())),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("image '{}' not found", name_or_id)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn delete_image_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.delete_image(&name_or_id) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("image '{}' not found", name_or_id)})),
        ),
        Err(WorkspaceServiceError::Store(StoreError::Conflict(msg))) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn create_workspace_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CreateWorkspaceParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.create_workspace(&params.base, params.name.as_deref()) {
        Ok(ws) => (StatusCode::CREATED, Json(serde_json::to_value(ws).unwrap())),
        Err(WorkspaceServiceError::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(WorkspaceServiceError::Store(StoreError::Conflict(msg))) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn list_workspaces(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let base = query.get("base").map(|s| s.as_str());
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.list_workspaces(base) {
        Ok(wss) => (StatusCode::OK, Json(serde_json::to_value(wss).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn get_workspace(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.get_workspace(&name_or_id) {
        Ok(Some(ws)) => (StatusCode::OK, Json(serde_json::to_value(ws).unwrap())),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("workspace '{}' not found", name_or_id)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn delete_workspace_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = WorkspaceService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.workspaces_root.clone(),
    );
    match svc.delete_workspace(&name_or_id) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("workspace '{}' not found", name_or_id)})),
        ),
        Err(WorkspaceServiceError::Store(StoreError::Conflict(msg))) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct AttachWorkspaceRequest {
    vm_id: String,
    #[serde(default)]
    is_root_device: bool,
}

async fn attach_workspace_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
    Json(req): Json<AttachWorkspaceRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Resolve workspace by name or ID
    let ws = match state.store.get_workspace(&name_or_id) {
        Ok(Some(ws)) => ws,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("workspace '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    match state.store.attach_workspace(&ws.id, &req.vm_id, req.is_root_device) {
        Ok(ws) => (StatusCode::OK, Json(serde_json::to_value(ws).unwrap())),
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

async fn detach_workspace_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ws = match state.store.get_workspace(&name_or_id) {
        Ok(Some(ws)) => ws,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("workspace '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    match state.store.detach_workspace(&ws.id) {
        Ok(ws) => (StatusCode::OK, Json(serde_json::to_value(ws).unwrap())),
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

// ---------------------------------------------------------------------------
// Kernel handlers
// ---------------------------------------------------------------------------

async fn list_kernels_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.list_kernels() {
        Ok(kernels) => (StatusCode::OK, Json(serde_json::to_value(kernels).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct DownloadKernelRequest {
    version: String,
}

async fn download_kernel_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DownloadKernelRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let provider_config = match state.store.get_default_provider("kernel") {
        Ok(Some(p)) => p,
        Ok(None) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "no default kernel provider configured"})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    let svc = KernelService::new(state.store.as_ref(), &state.executor, state.assets_dir.clone());
    match svc.download(&req.version, &provider_config).await {
        Ok(kernel) => (StatusCode::CREATED, Json(serde_json::to_value(kernel).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn remove_kernel_handler(
    State(state): State<Arc<AppState>>,
    Path(version): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = KernelService::new(state.store.as_ref(), &state.executor, state.assets_dir.clone());
    match svc.remove(&version) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("kernel '{}' not found", version)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn verify_kernel_handler(
    State(state): State<Arc<AppState>>,
    Path(version): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = KernelService::new(state.store.as_ref(), &state.executor, state.assets_dir.clone());
    match svc.verify(&version) {
        Ok(ok) => (StatusCode::OK, Json(serde_json::json!(ok))),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Rootfs handlers
// ---------------------------------------------------------------------------

async fn list_rootfs_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.list_rootfs_images() {
        Ok(images) => (StatusCode::OK, Json(serde_json::to_value(images).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct DownloadRootfsRequest {
    distro: String,
    version: String,
}

async fn download_rootfs_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DownloadRootfsRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let provider_config = match state.store.get_default_provider("rootfs") {
        Ok(Some(p)) => p,
        Ok(None) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "no default rootfs provider configured"})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    let svc = RootfsService::new(state.store.as_ref(), &state.executor, state.assets_dir.clone());
    match svc.download(&req.distro, &req.version, &provider_config).await {
        Ok(rootfs) => (StatusCode::CREATED, Json(serde_json::to_value(rootfs).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn remove_rootfs_handler(
    State(state): State<Arc<AppState>>,
    Path((distro, version)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = RootfsService::new(state.store.as_ref(), &state.executor, state.assets_dir.clone());
    match svc.remove(&distro, &version) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("rootfs '{distro}-{version}' not found")})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Firecracker handlers
// ---------------------------------------------------------------------------

async fn list_firecracker_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.list_firecracker_versions() {
        Ok(versions) => (StatusCode::OK, Json(serde_json::to_value(versions).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct DownloadFirecrackerRequest {
    version: String,
}

async fn download_firecracker_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DownloadFirecrackerRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let provider_config = match state.store.get_default_provider("firecracker") {
        Ok(Some(p)) => p,
        Ok(None) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "no default firecracker provider configured"})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    let svc = FirecrackerService::from_provider(state.store.as_ref(), &state.executor, state.assets_dir.clone(), &provider_config);
    match svc.download(&req.version, &provider_config).await {
        Ok(fc) => (StatusCode::CREATED, Json(serde_json::to_value(fc).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn remove_firecracker_handler(
    State(state): State<Arc<AppState>>,
    Path(version): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = FirecrackerService::new(state.store.as_ref(), &state.executor, state.assets_dir.clone());
    match svc.remove(&version) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("firecracker '{}' not found", version)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Template handlers
// ---------------------------------------------------------------------------

async fn create_template(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CreateTemplateParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.create_template(&params) {
        Ok(tpl) => (StatusCode::CREATED, Json(serde_json::to_value(tpl).unwrap())),
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

async fn list_templates(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.list_templates() {
        Ok(tpls) => (StatusCode::OK, Json(serde_json::to_value(tpls).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn get_template_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.get_template(&name_or_id) {
        Ok(Some(tpl)) => (StatusCode::OK, Json(serde_json::to_value(tpl).unwrap())),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("template '{}' not found", name_or_id)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn delete_template_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.delete_template(&name_or_id) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("template '{}' not found", name_or_id)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Build handlers
// ---------------------------------------------------------------------------

async fn trigger_build(
    State(state): State<Arc<AppState>>,
    Path(template_name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let template = match state.store.get_template(&template_name_or_id) {
        Ok(Some(tpl)) => tpl,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("template '{}' not found", template_name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    let build = match state.store.create_build(&template) {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    // Spawn background build execution
    let build_clone = build.clone();
    let state_clone = state.clone();
    tokio::spawn(async move {
        let builds_dir = state_clone.assets_dir.parent()
            .unwrap_or(std::path::Path::new("/tmp"))
            .join("builds");
        let _ = std::fs::create_dir_all(&builds_dir);

        let svc = nexus_lib::build_service::BuildService::new(
            state_clone.store.as_ref(),
            state_clone.backend.as_ref(),
            &state_clone.executor,
            state_clone.workspaces_root.clone(),
            builds_dir,
        );
        svc.execute_build(&build_clone).await;
    });

    (StatusCode::CREATED, Json(serde_json::to_value(build).unwrap()))
}

async fn list_builds_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let template = query.get("template").map(|s| s.as_str());
    match state.store.list_builds(template) {
        Ok(builds) => (StatusCode::OK, Json(serde_json::to_value(builds).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn get_build_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.store.get_build(&id) {
        Ok(Some(build)) => (StatusCode::OK, Json(serde_json::to_value(build).unwrap())),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("build '{}' not found", id)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn start_vm_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Look up the VM
    let vm = match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("VM '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    // Resolve rootfs path: look for an attached workspace or use a default
    // For now, require a workspace attached as root device
    let rootfs_path = match find_rootfs_for_vm(&state, &vm.id) {
        Ok(path) => path,
        Err(msg) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        ),
    };

    // Spawn Firecracker
    let (child, runtime_dir) = match vm_service::spawn_firecracker(
        &state.firecracker.binary,
        &vm,
        &state.firecracker.kernel,
        &rootfs_path,
    ) {
        Ok(result) => result,
        Err(e) => {
            // Mark VM as failed
            let _ = state.store.fail_vm(&vm.id);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            );
        }
    };

    let pid = child.id();
    let api_sock = runtime_dir.join("firecracker.sock").to_string_lossy().to_string();
    let vsock_uds = runtime_dir.join("firecracker.vsock").to_string_lossy().to_string();
    let console_log = runtime_dir.join("console.log").to_string_lossy().to_string();

    // Generate config JSON for recording
    let config = vm_service::firecracker_config(
        &vm, &state.firecracker.kernel, &rootfs_path, &vsock_uds,
    );
    let config_str = serde_json::to_string(&config).unwrap_or_default();

    // Update store
    match state.store.start_vm(&vm.id, pid, &api_sock, &vsock_uds, &console_log, &config_str) {
        Ok(updated_vm) => {
            // Record boot history and capture boot_id for the monitor
            let boot_id = state.store.record_boot_start(&vm.id, &console_log)
                .unwrap_or_default();

            // Store the child process + boot_id for monitoring
            state.processes.lock().await.insert(vm.id.clone(), TrackedProcess {
                child,
                boot_id,
            });

            (StatusCode::OK, Json(serde_json::to_value(updated_vm).unwrap()))
        }
        Err(e) => {
            // Kill the just-spawned process
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        }
    }
}

/// Find the rootfs ext4 image for a VM by looking for an attached root-device workspace.
fn find_rootfs_for_vm(state: &AppState, vm_id: &str) -> Result<String, String> {
    // Look for a workspace attached to this VM as root device
    let workspaces = state.store.list_workspaces(None)
        .map_err(|e| format!("cannot list workspaces: {e}"))?;

    for ws in &workspaces {
        if ws.vm_id.as_deref() == Some(vm_id) && ws.is_root_device {
            // The rootfs.ext4 file lives inside the workspace subvolume
            let rootfs = PathBuf::from(&ws.subvolume_path).join("rootfs.ext4");
            if rootfs.exists() {
                return Ok(rootfs.to_string_lossy().to_string());
            }
            return Err(format!(
                "workspace '{}' is attached as root device but rootfs.ext4 not found at {}",
                ws.name.as_deref().unwrap_or(&ws.id),
                rootfs.display()
            ));
        }
    }

    Err(format!(
        "VM '{}' has no workspace attached as root device. Attach one with: \
         nexusctl ws create --base <image> --name <ws> (then attach to VM)",
        vm_id
    ))
}

async fn stop_vm_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let vm = match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("VM '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    if vm.state != VmState::Running {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": format!("VM '{}' is not running (state: {})", vm.name, vm.state)})),
        );
    }

    // Send SIGTERM to the Firecracker process.
    // Do NOT call blocking child.wait() while holding the tokio Mutex.
    // Instead, just signal and remove from the process map — the monitor
    // will detect the exit via try_wait() and transition state to `stopped`.
    if let Some(pid) = vm.pid {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
    }

    // Remove from the process map so the monitor knows this was
    // a deliberate stop, not a crash. Record boot stop with the
    // tracked boot_id before removing.
    {
        let mut processes = state.processes.lock().await;
        if let Some(tracked) = processes.remove(&vm.id) {
            let _ = state.store.record_boot_stop(&tracked.boot_id, None, None);
        }
    }

    match state.store.stop_vm(&vm.id) {
        Ok(stopped) => (StatusCode::OK, Json(serde_json::to_value(stopped).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn vm_logs_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, String) {
    let vm = match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (StatusCode::NOT_FOUND, format!("VM '{}' not found", name_or_id)),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let log_path = match &vm.console_log_path {
        Some(p) => p.clone(),
        None => return (StatusCode::NOT_FOUND, format!("no console log for VM '{}'", vm.name)),
    };

    let tail: usize = query
        .get("tail")
        .and_then(|t| t.parse().ok())
        .unwrap_or(100);

    match std::fs::read_to_string(&log_path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(tail);
            let output = lines[start..].join("\n");
            (StatusCode::OK, output)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::NOT_FOUND, format!("console log not found at {}", log_path))
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("cannot read console log: {e}"))
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/vms", post(create_vm).get(list_vms))
        .route("/v1/vms/{name_or_id}", get(get_vm).delete(delete_vm))
        .route("/v1/vms/{name_or_id}/start", post(start_vm_handler))
        .route("/v1/vms/{name_or_id}/stop", post(stop_vm_handler))
        .route("/v1/vms/{name_or_id}/logs", get(vm_logs_handler))
        .route("/v1/images", post(import_image).get(list_images))
        .route("/v1/images/{name_or_id}", get(get_image).delete(delete_image_handler))
        .route("/v1/workspaces", post(create_workspace_handler).get(list_workspaces))
        .route("/v1/workspaces/{name_or_id}", get(get_workspace).delete(delete_workspace_handler))
        .route("/v1/workspaces/{name_or_id}/attach", post(attach_workspace_handler))
        .route("/v1/workspaces/{name_or_id}/detach", post(detach_workspace_handler))
        .route("/v1/kernels", get(list_kernels_handler))
        .route("/v1/kernels/download", post(download_kernel_handler))
        .route("/v1/kernels/{version}", delete(remove_kernel_handler))
        .route("/v1/kernels/{version}/verify", get(verify_kernel_handler))
        .route("/v1/rootfs-images", get(list_rootfs_handler))
        .route("/v1/rootfs-images/download", post(download_rootfs_handler))
        .route("/v1/rootfs-images/{distro}/{version}", delete(remove_rootfs_handler))
        .route("/v1/firecracker", get(list_firecracker_handler))
        .route("/v1/firecracker/download", post(download_firecracker_handler))
        .route("/v1/firecracker/{version}", delete(remove_firecracker_handler))
        .route("/v1/templates", post(create_template).get(list_templates))
        .route("/v1/templates/{name_or_id}", get(get_template_handler).delete(delete_template_handler))
        .route("/v1/templates/{name_or_id}/build", post(trigger_build))
        .route("/v1/builds", get(list_builds_handler))
        .route("/v1/builds/{id}", get(get_build_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use nexus_lib::store::sqlite::SqliteStore;
    use nexus_lib::asset::{
        FirecrackerVersion, Kernel, Provider, RegisterFirecrackerParams,
        RegisterKernelParams, RegisterRootfsParams, RootfsImage,
    };
    use nexus_lib::store::traits::{AssetStore, BuildStore, ImageStore, StoreError, VmStore, WorkspaceStore};
    use nexus_lib::template::{Build, BuildStatus, CreateTemplateParams, Template};
    use nexus_lib::vm::{CreateVmParams, Vm};
    use nexus_lib::workspace::{ImportImageParams, MasterImage, Workspace};
    use tower::ServiceExt;

    /// A mock store for testing the health endpoint without SQLite.
    struct MockStore;

    impl VmStore for MockStore {
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
        fn start_vm(&self, _: &str, _: u32, _: &str, _: &str, _: &str, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn stop_vm(&self, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn crash_vm(&self, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn fail_vm(&self, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn list_running_vms(&self) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
        fn record_boot_start(&self, _: &str, _: &str) -> Result<String, StoreError> { unimplemented!() }
        fn record_boot_stop(&self, _: &str, _: Option<i32>, _: Option<&str>) -> Result<(), StoreError> { unimplemented!() }
    }

    impl ImageStore for MockStore {
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
    }

    impl WorkspaceStore for MockStore {
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
        fn attach_workspace(&self, _workspace_id: &str, _vm_id: &str, _is_root_device: bool) -> Result<Workspace, StoreError> {
            unimplemented!()
        }
        fn detach_workspace(&self, _workspace_id: &str) -> Result<Workspace, StoreError> {
            unimplemented!()
        }
    }

    impl AssetStore for MockStore {
        fn get_provider(&self, _name_or_id: &str) -> Result<Option<Provider>, StoreError> { unimplemented!() }
        fn get_default_provider(&self, _asset_type: &str) -> Result<Option<Provider>, StoreError> { unimplemented!() }
        fn list_providers(&self, _asset_type: Option<&str>) -> Result<Vec<Provider>, StoreError> { unimplemented!() }
        fn register_kernel(&self, _params: &RegisterKernelParams) -> Result<Kernel, StoreError> { unimplemented!() }
        fn list_kernels(&self) -> Result<Vec<Kernel>, StoreError> { Ok(vec![]) }
        fn get_kernel(&self, _id: &str, _arch: Option<&str>) -> Result<Option<Kernel>, StoreError> { unimplemented!() }
        fn delete_kernel(&self, _id: &str) -> Result<bool, StoreError> { unimplemented!() }
        fn register_rootfs(&self, _params: &RegisterRootfsParams) -> Result<RootfsImage, StoreError> { unimplemented!() }
        fn list_rootfs_images(&self) -> Result<Vec<RootfsImage>, StoreError> { Ok(vec![]) }
        fn get_rootfs(&self, _id: &str, _arch: Option<&str>) -> Result<Option<RootfsImage>, StoreError> { unimplemented!() }
        fn delete_rootfs(&self, _id: &str) -> Result<bool, StoreError> { unimplemented!() }
        fn register_firecracker(&self, _params: &RegisterFirecrackerParams) -> Result<FirecrackerVersion, StoreError> { unimplemented!() }
        fn list_firecracker_versions(&self) -> Result<Vec<FirecrackerVersion>, StoreError> { Ok(vec![]) }
        fn get_firecracker(&self, _id: &str, _arch: Option<&str>) -> Result<Option<FirecrackerVersion>, StoreError> { unimplemented!() }
        fn delete_firecracker(&self, _id: &str) -> Result<bool, StoreError> { unimplemented!() }
    }

    impl BuildStore for MockStore {
        fn create_template(&self, _params: &CreateTemplateParams) -> Result<Template, StoreError> { unimplemented!() }
        fn list_templates(&self) -> Result<Vec<Template>, StoreError> { unimplemented!() }
        fn get_template(&self, _name_or_id: &str) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn delete_template(&self, _name_or_id: &str) -> Result<bool, StoreError> { unimplemented!() }
        fn create_build(&self, _template: &Template) -> Result<Build, StoreError> { unimplemented!() }
        fn list_builds(&self, _template: Option<&str>) -> Result<Vec<Build>, StoreError> { unimplemented!() }
        fn get_build(&self, _id: &str) -> Result<Option<Build>, StoreError> { unimplemented!() }
        fn update_build_status(&self, _id: &str, _status: BuildStatus, _master_image_id: Option<&str>, _build_log_path: Option<&str>) -> Result<Build, StoreError> { unimplemented!() }
    }

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

    impl VmStore for FailingStore {
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
        fn start_vm(&self, _: &str, _: u32, _: &str, _: &str, _: &str, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn stop_vm(&self, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn crash_vm(&self, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn fail_vm(&self, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn list_running_vms(&self) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
        fn record_boot_start(&self, _: &str, _: &str) -> Result<String, StoreError> { unimplemented!() }
        fn record_boot_stop(&self, _: &str, _: Option<i32>, _: Option<&str>) -> Result<(), StoreError> { unimplemented!() }
    }

    impl ImageStore for FailingStore {
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
    }

    impl WorkspaceStore for FailingStore {
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
        fn attach_workspace(&self, _workspace_id: &str, _vm_id: &str, _is_root_device: bool) -> Result<Workspace, StoreError> {
            unimplemented!()
        }
        fn detach_workspace(&self, _workspace_id: &str) -> Result<Workspace, StoreError> {
            unimplemented!()
        }
    }

    impl AssetStore for FailingStore {
        fn get_provider(&self, _name_or_id: &str) -> Result<Option<Provider>, StoreError> { unimplemented!() }
        fn get_default_provider(&self, _asset_type: &str) -> Result<Option<Provider>, StoreError> { unimplemented!() }
        fn list_providers(&self, _asset_type: Option<&str>) -> Result<Vec<Provider>, StoreError> { unimplemented!() }
        fn register_kernel(&self, _params: &RegisterKernelParams) -> Result<Kernel, StoreError> { unimplemented!() }
        fn list_kernels(&self) -> Result<Vec<Kernel>, StoreError> { unimplemented!() }
        fn get_kernel(&self, _id: &str, _arch: Option<&str>) -> Result<Option<Kernel>, StoreError> { unimplemented!() }
        fn delete_kernel(&self, _id: &str) -> Result<bool, StoreError> { unimplemented!() }
        fn register_rootfs(&self, _params: &RegisterRootfsParams) -> Result<RootfsImage, StoreError> { unimplemented!() }
        fn list_rootfs_images(&self) -> Result<Vec<RootfsImage>, StoreError> { unimplemented!() }
        fn get_rootfs(&self, _id: &str, _arch: Option<&str>) -> Result<Option<RootfsImage>, StoreError> { unimplemented!() }
        fn delete_rootfs(&self, _id: &str) -> Result<bool, StoreError> { unimplemented!() }
        fn register_firecracker(&self, _params: &RegisterFirecrackerParams) -> Result<FirecrackerVersion, StoreError> { unimplemented!() }
        fn list_firecracker_versions(&self) -> Result<Vec<FirecrackerVersion>, StoreError> { unimplemented!() }
        fn get_firecracker(&self, _id: &str, _arch: Option<&str>) -> Result<Option<FirecrackerVersion>, StoreError> { unimplemented!() }
        fn delete_firecracker(&self, _id: &str) -> Result<bool, StoreError> { unimplemented!() }
    }

    impl BuildStore for FailingStore {
        fn create_template(&self, _params: &CreateTemplateParams) -> Result<Template, StoreError> { unimplemented!() }
        fn list_templates(&self) -> Result<Vec<Template>, StoreError> { unimplemented!() }
        fn get_template(&self, _name_or_id: &str) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn delete_template(&self, _name_or_id: &str) -> Result<bool, StoreError> { unimplemented!() }
        fn create_build(&self, _template: &Template) -> Result<Build, StoreError> { unimplemented!() }
        fn list_builds(&self, _template: Option<&str>) -> Result<Vec<Build>, StoreError> { unimplemented!() }
        fn get_build(&self, _id: &str) -> Result<Option<Build>, StoreError> { unimplemented!() }
        fn update_build_status(&self, _id: &str, _status: BuildStatus, _master_image_id: Option<&str>, _build_log_path: Option<&str>) -> Result<Build, StoreError> { unimplemented!() }
    }

    impl StateStore for FailingStore {
        fn init(&self) -> Result<(), StoreError> { Ok(()) }
        fn status(&self) -> Result<DbStatus, StoreError> {
            Err(StoreError::Query("disk I/O error".to_string()))
        }
        fn close(&self) -> Result<(), StoreError> { Ok(()) }
    }

    fn mock_state_with_store(store: impl StateStore + Send + Sync + 'static) -> Arc<AppState> {
        Arc::new(AppState {
            store: Box::new(store),
            backend: Box::new(MockBackend),
            workspaces_root: std::path::PathBuf::from("/tmp/mock-ws"),
            assets_dir: std::path::PathBuf::from("/tmp/mock-assets"),
            executor: nexus_lib::pipeline::PipelineExecutor::new(),
            firecracker: nexus_lib::config::FirecrackerConfig::default(),
            processes: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    #[tokio::test]
    async fn health_returns_ok_with_db_info() {
        let state = mock_state_with_store(MockStore);
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
        let state = mock_state_with_store(FailingStore);
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

    use nexus_lib::backend::traits::{BackendError, SubvolumeInfo, WorkspaceBackend};

    /// A no-op backend for API unit tests (no real btrfs needed).
    struct MockBackend;

    impl WorkspaceBackend for MockBackend {
        fn import_image(&self, _source: &std::path::Path, dest: &std::path::Path) -> Result<SubvolumeInfo, BackendError> {
            Ok(SubvolumeInfo { path: dest.to_path_buf(), read_only: true, size_bytes: None })
        }
        fn create_snapshot(&self, _source: &std::path::Path, dest: &std::path::Path) -> Result<SubvolumeInfo, BackendError> {
            Ok(SubvolumeInfo { path: dest.to_path_buf(), read_only: false, size_bytes: None })
        }
        fn delete_subvolume(&self, _path: &std::path::Path) -> Result<(), BackendError> { Ok(()) }
        fn is_subvolume(&self, _path: &std::path::Path) -> Result<bool, BackendError> { Ok(true) }
        fn subvolume_info(&self, path: &std::path::Path) -> Result<SubvolumeInfo, BackendError> {
            Ok(SubvolumeInfo { path: path.to_path_buf(), read_only: false, size_bytes: None })
        }
        fn set_read_only(&self, _path: &std::path::Path, _read_only: bool) -> Result<(), BackendError> { Ok(()) }
    }

    fn test_state() -> Arc<AppState> {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let ws_root = dir.path().join("workspaces");
        let assets_dir = dir.path().join("assets");
        std::fs::create_dir_all(&ws_root).unwrap();
        std::fs::create_dir_all(&assets_dir).unwrap();
        let store = SqliteStore::open_and_init(&db_path).unwrap();
        // Leak the tempdir so it lives long enough
        std::mem::forget(dir);
        Arc::new(AppState {
            store: Box::new(store),
            backend: Box::new(MockBackend),
            workspaces_root: ws_root,
            assets_dir,
            executor: nexus_lib::pipeline::PipelineExecutor::new(),
            firecracker: nexus_lib::config::FirecrackerConfig::default(),
            processes: tokio::sync::Mutex::new(HashMap::new()),
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

    #[tokio::test]
    async fn list_kernels_returns_array() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/v1/kernels").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn list_rootfs_images_returns_array() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/v1/rootfs-images").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_firecracker_returns_array() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/v1/firecracker").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_template_returns_201() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::post("/v1/templates")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "base", "source_type": "rootfs", "source_identifier": "https://example.com/rootfs.tar.gz"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "base");
        assert_eq!(json["source_type"], "rootfs");
        assert_eq!(json["version"], 1);
    }

    #[tokio::test]
    async fn list_templates_returns_array() {
        let state = test_state();

        router(state.clone())
            .oneshot(
                Request::post("/v1/templates")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "tpl1", "source_type": "rootfs", "source_identifier": "https://example.com/rootfs.tar.gz"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(Request::get("/v1/templates").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
    }

    #[tokio::test]
    async fn get_template_returns_detail() {
        let state = test_state();

        router(state.clone())
            .oneshot(
                Request::post("/v1/templates")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "detail-tpl", "source_type": "rootfs", "source_identifier": "https://example.com/rootfs.tar.gz"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(Request::get("/v1/templates/detail-tpl").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "detail-tpl");
    }

    #[tokio::test]
    async fn delete_template_returns_204() {
        let state = test_state();

        router(state.clone())
            .oneshot(
                Request::post("/v1/templates")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "doomed-tpl", "source_type": "rootfs", "source_identifier": "https://example.com/rootfs.tar.gz"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = router(state)
            .oneshot(
                Request::delete("/v1/templates/doomed-tpl")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_builds_returns_array() {
        let state = test_state();
        let response = router(state)
            .oneshot(Request::get("/v1/builds").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn attach_and_detach_workspace() {
        let state = test_state();

        // Create a VM
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/vms")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "attach-vm"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let vm: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let vm_id = vm["id"].as_str().unwrap();

        // Import an image
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/images")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name": "attach-img", "source_path": "/tmp/fake"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Create a workspace
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/workspaces")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"base": "attach-img", "name": "attach-ws"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Attach workspace to VM
        let attach_body = serde_json::json!({
            "vm_id": vm_id,
            "is_root_device": true
        });
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/workspaces/attach-ws/attach")
                    .header("content-type", "application/json")
                    .body(Body::from(attach_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let ws: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(ws["vm_id"], vm_id);
        assert_eq!(ws["is_root_device"], true);

        // Detach workspace
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/workspaces/attach-ws/detach")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let ws: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(ws["vm_id"].is_null());
        assert_eq!(ws["is_root_device"], false);
    }
}
