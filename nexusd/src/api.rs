// SPDX-License-Identifier: GPL-2.0-only
use axum::{Json, Router, routing::{delete, get, post}};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use nexus_lib::backend::traits::DriveBackend;
use nexus_lib::drive::{CreateDriveParams, ImportImageParams};
use nexus_lib::drive_service::{DriveService, DriveServiceError};
use nexus_lib::firecracker_service::FirecrackerService;
use nexus_lib::kernel_service::KernelService;
use nexus_lib::pipeline::PipelineExecutor;
use nexus_lib::rootfs_service::RootfsService;
use nexus_lib::store::traits::{DbStatus, StateStore, StoreError};
use nexus_lib::template::CreateTemplateParams;
use nexus_lib::vm::{CreateVmParams, VmState};
use nexus_lib::vm_service;
use nexus_lib::vsock_manager::VsockManager;
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
    pub boot_id: nexus_lib::id::Id,
}

/// Application state shared across handlers.
pub struct AppState {
    pub store: Arc<dyn StateStore + Send + Sync>,
    pub backend: Box<dyn DriveBackend>,
    pub drives_root: PathBuf,
    pub assets_dir: PathBuf,
    pub executor: PipelineExecutor,
    pub vsock_manager: Arc<VsockManager>,
    pub network_service: nexus_lib::network_service::NetworkService,
    /// Map of VM ID -> tracked Firecracker process (child + boot_id).
    /// Protected by a tokio Mutex for async access.
    pub processes: TokioMutex<HashMap<nexus_lib::id::Id, TrackedProcess>>,
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
        Err(StoreError::InvalidInput(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
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
        Ok(Some(vm)) => {
            let network = state.store.get_vm_network(vm.id.as_i64()).ok().flatten();
            let mut vm_json = serde_json::to_value(&vm).unwrap();
            vm_json["network"] = network.as_ref().map(|n| serde_json::json!({
                "ip_address": n.ip_address,
                "bridge_name": n.bridge_name,
            })).unwrap_or(serde_json::Value::Null);
            (StatusCode::OK, Json(vm_json))
        }
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
    // Resolve to VM first to get the ID
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

    // Clean up tap device and release IP (best-effort, don't block deletion)
    if let Err(e) = state.network_service.destroy_tap(vm.id.as_i64()) {
        tracing::warn!("Failed to destroy tap device for VM {}: {}", vm.name, e);
    }

    match state.store.delete_vm(vm.id) {
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
    let svc = DriveService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.drives_root.clone(),
    );
    match svc.import_image(&params) {
        Ok(img) => (StatusCode::CREATED, Json(serde_json::to_value(img).unwrap())),
        Err(DriveServiceError::Store(StoreError::InvalidInput(msg))) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(DriveServiceError::Store(StoreError::Conflict(msg))) => (
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
    let svc = DriveService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.drives_root.clone(),
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
    let svc = DriveService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.drives_root.clone(),
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
    // Resolve to image first to get the ID
    let image = match state.store.get_image(&name_or_id) {
        Ok(Some(img)) => img,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("image '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    // Delete from filesystem first
    let path = PathBuf::from(&image.subvolume_path);
    if path.exists() {
        if let Err(e) = state.backend.delete_subvolume(&path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("failed to delete subvolume: {e}")})),
            );
        }
    }

    // Then remove from database
    match state.store.delete_image(image.id) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("image '{}' not found", name_or_id)})),
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

async fn create_drive_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CreateDriveParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = DriveService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.drives_root.clone(),
    );
    match svc.create_drive(&params.base, params.name.as_deref(), params.size) {
        Ok(drive) => (StatusCode::CREATED, Json(serde_json::to_value(drive).unwrap())),
        Err(DriveServiceError::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(DriveServiceError::Store(StoreError::InvalidInput(msg))) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(DriveServiceError::Store(StoreError::Conflict(msg))) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn list_drives(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let base = query.get("base").map(|s| s.as_str());
    let svc = DriveService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.drives_root.clone(),
    );
    match svc.list_drives(base) {
        Ok(drives) => (StatusCode::OK, Json(serde_json::to_value(drives).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn get_drive(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let svc = DriveService::new(
        state.store.as_ref(),
        state.backend.as_ref(),
        state.drives_root.clone(),
    );
    match svc.get_drive(&name_or_id) {
        Ok(Some(drive)) => (StatusCode::OK, Json(serde_json::to_value(drive).unwrap())),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("drive '{}' not found", name_or_id)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

async fn delete_drive_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Resolve to drive first to get the ID
    let drive = match state.store.get_drive(&name_or_id) {
        Ok(Some(d)) => d,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("drive '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    // Delete from filesystem first
    let path = PathBuf::from(&drive.subvolume_path);
    if path.exists() {
        if let Err(e) = state.backend.delete_subvolume(&path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("failed to delete subvolume: {e}")})),
            );
        }
    }

    // Then remove from database
    match state.store.delete_drive(drive.id) {
        Ok(true) => (StatusCode::NO_CONTENT, Json(serde_json::json!(null))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("drive '{}' not found", name_or_id)})),
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

#[derive(Deserialize)]
struct AttachDriveRequest {
    vm_id: String,
    #[serde(default)]
    is_root_device: bool,
}

async fn attach_drive_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
    Json(req): Json<AttachDriveRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Resolve drive by name or ID
    let drive = match state.store.get_drive(&name_or_id) {
        Ok(Some(d)) => d,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("drive '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    // Resolve VM by name or ID
    let vm = match state.store.get_vm(&req.vm_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("VM '{}' not found", req.vm_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    match state.store.attach_drive(drive.id, vm.id, req.is_root_device) {
        Ok(drive) => (StatusCode::OK, Json(serde_json::to_value(drive).unwrap())),
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

async fn detach_drive_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let drive = match state.store.get_drive(&name_or_id) {
        Ok(Some(d)) => d,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("drive '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    match state.store.detach_drive(drive.id) {
        Ok(drive) => (StatusCode::OK, Json(serde_json::to_value(drive).unwrap())),
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

    let svc = KernelService::from_provider_config(
        state.store.as_ref(), &state.executor,
        state.assets_dir.clone(), &provider_config,
    );
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

    let svc = RootfsService::from_provider_config(
        state.store.as_ref(), &state.executor,
        state.assets_dir.clone(), &provider_config,
    );
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
        Err(StoreError::InvalidInput(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
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
    // Resolve to template first to get the ID
    let template = match state.store.get_template(&name_or_id) {
        Ok(Some(tpl)) => tpl,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("template '{}' not found", name_or_id)})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    };

    match state.store.delete_template(template.id) {
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

/// Error type for trigger_build operations.
#[derive(Debug)]
pub enum TriggerBuildError {
    NotFound(String),
    Internal(String),
}

impl std::fmt::Display for TriggerBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriggerBuildError::NotFound(msg) => write!(f, "{}", msg),
            TriggerBuildError::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

/// Trigger a build from a template: create the build record and spawn background
/// execution. Returns the build record immediately. Used by both REST and MCP handlers.
pub fn trigger_build_for_template(
    state: &Arc<AppState>,
    template_name_or_id: &str,
) -> Result<nexus_lib::template::Build, TriggerBuildError> {
    let template = state.store.get_template(template_name_or_id)
        .map_err(|e| TriggerBuildError::Internal(e.to_string()))?
        .ok_or_else(|| TriggerBuildError::NotFound(
            format!("template '{}' not found", template_name_or_id)
        ))?;

    let build = state.store.create_build(&template)
        .map_err(|e| TriggerBuildError::Internal(e.to_string()))?;

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
            state_clone.drives_root.clone(),
            builds_dir,
        );
        svc.execute_build(&build_clone).await;
    });

    Ok(build)
}

async fn trigger_build(
    State(state): State<Arc<AppState>>,
    Path(template_name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match trigger_build_for_template(&state, &template_name_or_id) {
        Ok(build) => (StatusCode::CREATED, Json(serde_json::to_value(build).unwrap())),
        Err(TriggerBuildError::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(TriggerBuildError::Internal(msg)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": msg})),
        ),
    }
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
    Path(id_str): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Builds are ID-only (no names), so parse as base32
    let id = match nexus_lib::id::Id::decode(&id_str) {
        Ok(id) => id,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid build ID: '{}'", id_str)})),
        ),
    };

    match state.store.get_build(id) {
        Ok(Some(build)) => (StatusCode::OK, Json(serde_json::to_value(build).unwrap())),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("build '{}' not found", id_str)})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Resolve Firecracker binary path from asset store using default version from settings.
fn resolve_firecracker_binary(state: &AppState) -> Result<String, String> {
    let version = state.store
        .get_setting("default_firecracker_version")
        .map_err(|e| format!("cannot read default_firecracker_version: {}", e))?
        .ok_or_else(|| "default_firecracker_version not set".to_string())?;

    let arch = std::env::consts::ARCH;

    let fc = state.store
        .get_firecracker(&version, Some(arch))
        .map_err(|e| format!("asset store error: {}", e))?
        .ok_or_else(|| format!("Firecracker version {} for {} not found in asset store", version, arch))?;

    Ok(fc.path_on_host)
}

/// Resolve kernel path from asset store using default version from settings.
fn resolve_kernel_path(state: &AppState) -> Result<String, String> {
    let version = state.store
        .get_setting("default_kernel_version")
        .map_err(|e| format!("cannot read default_kernel_version: {}", e))?
        .ok_or_else(|| "default_kernel_version not set".to_string())?;

    let arch = std::env::consts::ARCH;

    let kernel = state.store
        .get_kernel(&version, Some(arch))
        .map_err(|e| format!("asset store error: {}", e))?
        .ok_or_else(|| format!("Kernel version {} for {} not found in asset store", version, arch))?;

    Ok(kernel.path_on_host)
}

/// Error type for start_vm operations.
#[derive(Debug)]
pub enum StartVmError {
    NotFound(String),
    BadRequest(String),
    Conflict(String),
    Internal(String),
}

impl std::fmt::Display for StartVmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartVmError::NotFound(msg) => write!(f, "{}", msg),
            StartVmError::BadRequest(msg) => write!(f, "{}", msg),
            StartVmError::Conflict(msg) => write!(f, "{}", msg),
            StartVmError::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

/// Core VM start logic: resolve rootfs, allocate network, spawn Firecracker,
/// handshake guest-agent, and run provisioning. Used by both REST and MCP handlers.
pub async fn start_vm(state: &AppState, name_or_id: &str) -> Result<nexus_lib::vm::Vm, StartVmError> {
    // Look up the VM
    let vm = state.store.get_vm(name_or_id)
        .map_err(|e| StartVmError::Internal(e.to_string()))?
        .ok_or_else(|| StartVmError::NotFound(format!("VM '{}' not found", name_or_id)))?;

    // Resolve rootfs path
    let rootfs_path = find_rootfs_for_vm(state, &vm.id)
        .map_err(StartVmError::BadRequest)?;

    // Allocate IP and create tap device
    let (tap_device, guest_ip, gateway_ip) = match state.network_service.allocate_ip(vm.id.as_i64()) {
        Ok(ip) => {
            let gateway = state.network_service.gateway_ip().ok();
            match state.network_service.create_tap(vm.id.as_i64()) {
                Ok(tap) => (Some(tap), Some(ip), gateway),
                Err(e) => {
                    tracing::error!("Failed to create tap device for VM {}: {}", vm.name, e);
                    (None, None, None)
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to allocate IP for VM {}: {}", vm.name, e);
            (None, None, None)
        }
    };

    // Resolve Firecracker binary and kernel from asset store
    let firecracker_binary = resolve_firecracker_binary(state)
        .map_err(|e| {
            let _ = state.store.fail_vm(vm.id);
            StartVmError::Internal(format!("Failed to resolve firecracker binary: {}", e))
        })?;

    let kernel_path = resolve_kernel_path(state)
        .map_err(|e| {
            let _ = state.store.fail_vm(vm.id);
            StartVmError::Internal(format!("Failed to resolve kernel: {}", e))
        })?;

    // Spawn Firecracker
    let (child, runtime_dir) = vm_service::spawn_firecracker(
        &firecracker_binary,
        &vm,
        &kernel_path,
        &rootfs_path,
        tap_device.as_deref(),
        guest_ip.as_deref(),
        gateway_ip.as_deref(),
    ).map_err(|e| {
        let _ = state.store.fail_vm(vm.id);
        StartVmError::Internal(e.to_string())
    })?;

    let pid = child.id();
    let api_sock = runtime_dir.join("firecracker.sock").to_string_lossy().to_string();
    let vsock_uds = runtime_dir.join("firecracker.vsock").to_string_lossy().to_string();
    let console_log = runtime_dir.join("console.log").to_string_lossy().to_string();

    // Generate config JSON for recording
    let config = vm_service::firecracker_config(
        &vm,
        &kernel_path,
        &rootfs_path,
        &vsock_uds,
        tap_device.as_deref(),
        guest_ip.as_deref(),
        gateway_ip.as_deref(),
    );
    let config_str = serde_json::to_string(&config).unwrap_or_default();

    // Update store
    let updated_vm = state.store.start_vm(vm.id, pid, &api_sock, &vsock_uds, &console_log, &config_str)
        .map_err(|e| {
            // Kill the just-spawned process
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            StartVmError::Conflict(e.to_string())
        })?;

    // Record boot history and capture boot_id for the monitor
    let boot_id = state.store.record_boot_start(vm.id, &console_log)
        .unwrap_or_else(|_| nexus_lib::id::Id::from_i64(0));

    // Store the child process + boot_id for monitoring
    state.processes.lock().await.insert(vm.id, TrackedProcess {
        child,
        boot_id,
    });

    // Connect to guest-agent and wait for handshake
    match state.vsock_manager.connect_and_handshake(vm.id, runtime_dir.clone()).await {
        Ok(metadata) => {
            tracing::info!("guest-agent connected for VM {}: {:?}", vm.id, metadata);

            // Connect to MCP server (port 200) - non-fatal if it fails
            if let Err(e) = state.vsock_manager.connect_mcp(vm.id, runtime_dir.clone()).await {
                tracing::warn!("failed to establish MCP connection for VM {}: {}", vm.id, e);
            }

            // Build DNS resolv.conf content
            let resolv_conf = if let Ok(Some(_network_cfg)) = state.store.get_vm_network(vm.id.as_i64()) {
                let dns_servers = match state.network_service.dns_servers() {
                    Ok(servers) => servers,
                    Err(e) => {
                        tracing::error!("Failed to get DNS servers: {}", e);
                        "8.8.8.8,1.1.1.1".to_string()
                    }
                };
                Some(format!(
                    "# Generated by nexusd\n{}\n",
                    dns_servers
                        .split(',')
                        .map(|s: &str| format!("nameserver {}", s.trim()))
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
            } else {
                None
            };

            // Load provision files for this VM
            let provision_files = match state.store.list_provision_files(vm.id) {
                Ok(files) => files,
                Err(e) => {
                    tracing::warn!("Failed to load provision files for VM {}: {}", vm.id, e);
                    vec![]
                }
            };

            // Run provisioning sequence (online -> provisioning -> ready)
            if let Err(e) = state.vsock_manager.provision_vm(
                vm.id,
                runtime_dir.clone(),
                resolv_conf,
                provision_files,
            ).await {
                tracing::error!("Provisioning failed for VM {}: {}", vm.id, e);
            }
        }
        Err(e) => {
            tracing::warn!("failed to connect to guest-agent for VM {}: {}", vm.id, e);
            // State will transition to unreachable via monitor task
        }
    }

    Ok(updated_vm)
}

async fn start_vm_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match start_vm(&state, &name_or_id).await {
        Ok(vm) => (StatusCode::OK, Json(serde_json::to_value(vm).unwrap())),
        Err(StartVmError::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(StartVmError::BadRequest(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(StartVmError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(StartVmError::Internal(msg)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": msg})),
        ),
    }
}

/// Find the rootfs ext4 image for a VM by looking for an attached root-device drive.
fn find_rootfs_for_vm(state: &AppState, vm_id: &nexus_lib::id::Id) -> Result<String, String> {
    // Look for a drive attached to this VM as root device
    let drives = state.store.list_drives(None)
        .map_err(|e| format!("cannot list drives: {e}"))?;

    for drive in &drives {
        if drive.vm_id.as_ref() == Some(vm_id) && drive.is_root_device {
            // The rootfs.ext4 file lives inside the drive subvolume
            let rootfs = PathBuf::from(&drive.subvolume_path).join("rootfs.ext4");
            if rootfs.exists() {
                return Ok(rootfs.to_string_lossy().to_string());
            }
            return Err(format!(
                "drive '{}' is attached as root device but rootfs.ext4 not found at {}",
                drive.name.as_deref().unwrap_or(&drive.id.encode()),
                rootfs.display()
            ));
        }
    }

    Err(format!(
        "VM '{}' has no drive attached as root device. Attach one with: \
         nexusctl drive create --base <image> --name <drive> (then attach to VM)",
        vm_id.encode()
    ))
}

/// Error type for stop_vm operations.
#[derive(Debug)]
pub enum StopVmError {
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl std::fmt::Display for StopVmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopVmError::NotFound(msg) => write!(f, "{}", msg),
            StopVmError::Conflict(msg) => write!(f, "{}", msg),
            StopVmError::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

/// Core VM stop logic: validate state, send SIGTERM, clean up process map
/// and network resources. Used by both REST and MCP handlers.
pub async fn stop_vm(state: &AppState, name_or_id: &str) -> Result<nexus_lib::vm::Vm, StopVmError> {
    let vm = state.store.get_vm(name_or_id)
        .map_err(|e| StopVmError::Internal(e.to_string()))?
        .ok_or_else(|| StopVmError::NotFound(format!("VM '{}' not found", name_or_id)))?;

    if vm.state != VmState::Running && vm.state != VmState::Ready
        && vm.state != VmState::Unreachable && vm.state != VmState::Online
        && vm.state != VmState::Provisioning {
        return Err(StopVmError::Conflict(format!(
            "VM '{}' is not running (state: {})", vm.name, vm.state
        )));
    }

    // Send SIGTERM to the Firecracker process
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
            let _ = state.store.record_boot_stop(tracked.boot_id, None, None);
        }
    }

    // Close vsock connections (both control and MCP)
    state.vsock_manager.close_connection(vm.id).await;

    // Destroy tap device and release IP
    if let Err(e) = state.network_service.destroy_tap(vm.id.as_i64()) {
        tracing::warn!("Failed to destroy tap device for VM {}: {}", vm.name, e);
    }

    state.store.stop_vm(vm.id)
        .map_err(|e| StopVmError::Internal(e.to_string()))
}

async fn stop_vm_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match stop_vm(&state, &name_or_id).await {
        Ok(vm) => (StatusCode::OK, Json(serde_json::to_value(vm).unwrap())),
        Err(StopVmError::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(StopVmError::Conflict(msg)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": msg})),
        ),
        Err(StopVmError::Internal(msg)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": msg})),
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

async fn vm_history_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Resolve VM name/ID to VM
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

    // Get state history
    match state.store.get_state_history(vm.id) {
        Ok(history) => (StatusCode::OK, Json(serde_json::to_value(history).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// Gate with #[cfg(debug_assertions)] to exclude from release builds
async fn cleanup_network_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.network_service.cleanup_network() {
        Ok(report) => (StatusCode::OK, Json(serde_json::json!(report))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// Settings handlers
async fn list_settings_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SettingResponse>>, (StatusCode, Json<serde_json::Value>)> {
    match state.store.list_settings() {
        Ok(settings) => {
            let response: Vec<SettingResponse> = settings
                .into_iter()
                .map(|(key, value, value_type)| SettingResponse {
                    key,
                    value,
                    value_type,
                })
                .collect();
            Ok(Json(response))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}

async fn get_setting_handler(
    Path(key): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<SettingResponse>, (StatusCode, Json<serde_json::Value>)> {
    match state.store.get_setting(&key) {
        Ok(Some(value)) => {
            // Get type from database
            let value_type = match state.store.list_settings() {
                Ok(settings) => settings
                    .iter()
                    .find(|(k, _, _)| k == &key)
                    .map(|(_, _, t)| t.clone())
                    .unwrap_or_else(|| "string".to_string()),
                Err(_) => "string".to_string(),
            };

            Ok(Json(SettingResponse {
                key,
                value,
                value_type,
            }))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("setting '{}' not found", key)})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}

async fn update_setting_handler(
    Path(key): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateSettingRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // Infer type from current setting (or default to "string" for new settings)
    let value_type = state
        .store
        .get_setting(&key)
        .ok()
        .flatten()
        .and_then(|_| {
            state
                .store
                .list_settings()
                .ok()
                .and_then(|settings| {
                    settings
                        .iter()
                        .find(|(k, _, _)| k == &key)
                        .map(|(_, _, t)| t.clone())
                })
        })
        .unwrap_or_else(|| "string".to_string());

    // Validate before updating
    if let Err(e) = state.store.validate_setting(&key, &payload.value) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("validation failed: {}", e)})),
        ));
    }

    // Update setting
    match state.store.set_setting(&key, &payload.value, &value_type) {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}

#[derive(Debug, serde::Serialize)]
struct SettingResponse {
    key: String,
    value: String,
    value_type: String,
}

#[derive(Debug, serde::Deserialize)]
struct UpdateSettingRequest {
    value: String,
}

async fn add_vm_tag_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let vm = match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "VM not found"}))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    };
    let tag = match body["tag"].as_str() {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing 'tag' field"}))),
    };
    match state.store.add_vm_tag(vm.id, tag) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn list_vm_tags_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let vm = match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "VM not found"}))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    };
    match state.store.list_vm_tags(vm.id) {
        Ok(tags) => (StatusCode::OK, Json(serde_json::to_value(tags).unwrap())),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn remove_vm_tag_handler(
    State(state): State<Arc<AppState>>,
    Path((name_or_id, tag)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let vm = match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "VM not found"}))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    };
    match state.store.remove_vm_tag(vm.id, &tag) {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn exec_async_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let vm = match state.store.get_vm(&name_or_id) {
        Ok(Some(vm)) => vm,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "VM not found"}))),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    };

    if vm.state != VmState::Ready {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("VM is not ready (state: {})", vm.state)})));
    }

    let command = match body["command"].as_str() {
        Some(c) => c.to_string(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "missing 'command' field"}))),
    };
    let args: Vec<String> = body.get("args")
        .and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let runtime_dir = nexus_lib::vm_service::vm_runtime_dir(&vm.id);
    let stream = match state.vsock_manager.get_mcp_connection(vm.id, runtime_dir).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("vsock connection failed: {e}")}))),
    };
    let mcp_client = nexus_lib::mcp_client::McpClient::new(stream);

    match mcp_client.run_command_async(&command, &args).await {
        Ok(pid) => (StatusCode::OK, Json(serde_json::json!({"pid": pid}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

#[derive(Debug, Deserialize)]
struct SharkfinWebhook {
    event: String,
    recipient: String,
    channel: String,
    from: String,
    #[allow(dead_code)]
    message_id: u64,
    #[allow(dead_code)]
    sent_at: String,
}

async fn sharkfin_webhook_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SharkfinWebhook>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Only handle message.new events
    if payload.event != "message.new" {
        return (StatusCode::OK, Json(serde_json::json!({"skipped": true, "reason": "unsupported event"})));
    }

    // Look up VM by sharkfin_user tag
    let tag = format!("sharkfin_user:{}", payload.recipient);
    let vms = match state.store.list_vms_by_tag(&tag) {
        Ok(vms) => vms,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))),
    };

    let vm = match vms.into_iter().find(|v| v.state == VmState::Ready) {
        Some(vm) => vm,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": format!("no ready VM for user '{}'", payload.recipient)}))),
    };

    // Build the claude command, wrapped in a shell to set HOME=/root.
    // Alpine's root user has HOME=/ by default, but credentials and MCP config
    // are provisioned to /root/.claude/.
    let prompt = format!(
        "You are {}. You have a new message from {} in the '{}' channel. \
         Check your unread messages using the sharkfin MCP tools and respond appropriately.",
        payload.recipient, payload.from, payload.channel
    );

    let shell_cmd = format!(
        "cd /root && HOME=/root claude -p '{}' --allowedTools 'mcp__sharkfin__*'",
        prompt.replace('\'', "'\\''")
    );

    let command = "/bin/sh".to_string();
    let args = vec!["-c".to_string(), shell_cmd];

    // Fire and forget — spawn in background
    let vsock_manager = state.vsock_manager.clone();
    let vm_id = vm.id;
    let vm_name = vm.name.clone();
    let runtime_dir = nexus_lib::vm_service::vm_runtime_dir(&vm.id);

    tokio::spawn(async move {
        match vsock_manager.get_mcp_connection(vm_id, runtime_dir).await {
            Ok(stream) => {
                let mcp_client = nexus_lib::mcp_client::McpClient::new(stream);
                match mcp_client.run_command_async(&command, &args).await {
                    Ok(pid) => tracing::info!("Webhook launched claude for {} (PID {})", tag, pid),
                    Err(e) => tracing::warn!("Webhook exec failed for {}: {}", tag, e),
                }
            }
            Err(e) => tracing::warn!("Webhook vsock connection failed for {}: {}", tag, e),
        }
    });

    (StatusCode::OK, Json(serde_json::json!({"ok": true, "vm": vm_name})))
}

async fn add_provision_file_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
    Json(params): Json<nexus_lib::vm::AddProvisionFileParams>,
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

    match state.store.add_provision_file(vm.id, &params) {
        Ok(pf) => (StatusCode::CREATED, Json(serde_json::to_value(pf).unwrap())),
        Err(e) => {
            let status = match &e {
                nexus_lib::store::traits::StoreError::Conflict(_) => StatusCode::CONFLICT,
                nexus_lib::store::traits::StoreError::InvalidInput(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(serde_json::json!({"error": e.to_string()})))
        }
    }
}

async fn list_provision_files_handler(
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

    match state.store.list_provision_files(vm.id) {
        Ok(files) => (StatusCode::OK, Json(serde_json::to_value(files).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Request body for removing a provision file.
#[derive(serde::Deserialize)]
struct RemoveProvisionFileParams {
    guest_path: String,
}

async fn remove_provision_file_handler(
    State(state): State<Arc<AppState>>,
    Path(name_or_id): Path<String>,
    Json(params): Json<RemoveProvisionFileParams>,
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

    match state.store.remove_provision_file(vm.id, &params.guest_path) {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"deleted": true}))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("no provision file for guest path '{}'", params.guest_path)})),
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
        // Gate with #[cfg(debug_assertions)] to exclude from release builds
        .route("/v1/admin/cleanup-network", post(cleanup_network_handler))
        .route("/v1/vms", post(create_vm).get(list_vms))
        .route("/v1/vms/{name_or_id}", get(get_vm).delete(delete_vm))
        .route("/v1/vms/{name_or_id}/start", post(start_vm_handler))
        .route("/v1/vms/{name_or_id}/stop", post(stop_vm_handler))
        .route("/v1/vms/{name_or_id}/logs", get(vm_logs_handler))
        .route("/v1/vms/{name_or_id}/history", get(vm_history_handler))
        .route("/v1/vms/{name_or_id}/tags", post(add_vm_tag_handler).get(list_vm_tags_handler))
        .route("/v1/vms/{name_or_id}/tags/{tag}", delete(remove_vm_tag_handler))
        .route("/v1/vms/{name_or_id}/exec-async", post(exec_async_handler))
        .route("/v1/webhooks/sharkfin", post(sharkfin_webhook_handler))
        .route("/v1/vms/{name_or_id}/provision-files", post(add_provision_file_handler).get(list_provision_files_handler))
        .route("/v1/vms/{name_or_id}/provision-files/remove", post(remove_provision_file_handler))
        .route("/v1/images", post(import_image).get(list_images))
        .route("/v1/images/{name_or_id}", get(get_image).delete(delete_image_handler))
        .route("/v1/drives", post(create_drive_handler).get(list_drives))
        .route("/v1/drives/{name_or_id}", get(get_drive).delete(delete_drive_handler))
        .route("/v1/drives/{name_or_id}/attach", post(attach_drive_handler))
        .route("/v1/drives/{name_or_id}/detach", post(detach_drive_handler))
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
        .route("/v1/settings", get(list_settings_handler))
        .route("/v1/settings/{key}", get(get_setting_handler).put(update_setting_handler))
        .route("/mcp", post(crate::mcp_handler::handle_mcp_request)
            .layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024)))
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
    use nexus_lib::store::traits::{AssetStore, BuildStore, DriveStore, ImageStore, StoreError, VmStore};
    use nexus_lib::template::{Build, BuildStatus, CreateTemplateParams, Template};
    use nexus_lib::vm::{CreateVmParams, Vm};
    use nexus_lib::drive::{Drive, ImportImageParams, MasterImage};
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
        fn get_vm_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<Vm>, StoreError> { unimplemented!() }
        fn get_vm_by_name(&self, _name: &str) -> Result<Option<Vm>, StoreError> { unimplemented!() }
        fn get_vm(&self, _name_or_id: &str) -> Result<Option<Vm>, StoreError> {
            unimplemented!()
        }
        fn delete_vm(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn start_vm(&self, _: nexus_lib::id::Id, _: u32, _: &str, _: &str, _: &str, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn stop_vm(&self, _: nexus_lib::id::Id) -> Result<Vm, StoreError> { unimplemented!() }
        fn crash_vm(&self, _: nexus_lib::id::Id) -> Result<Vm, StoreError> { unimplemented!() }
        fn fail_vm(&self, _: nexus_lib::id::Id) -> Result<Vm, StoreError> { unimplemented!() }
        fn list_running_vms(&self) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
        fn record_boot_start(&self, _: nexus_lib::id::Id, _: &str) -> Result<nexus_lib::id::Id, StoreError> { unimplemented!() }
        fn record_boot_stop(&self, _: nexus_lib::id::Id, _: Option<i32>, _: Option<&str>) -> Result<(), StoreError> { unimplemented!() }
        fn update_vm_state(&self, _: nexus_lib::id::Id, _: &str, _: Option<&str>) -> Result<(), StoreError> { unimplemented!() }
        fn get_state_history(&self, _: nexus_lib::id::Id) -> Result<Vec<nexus_lib::vm::StateHistory>, StoreError> { unimplemented!() }
        fn set_vm_agent_connected_at(&self, _: nexus_lib::id::Id, _: i64) -> Result<(), StoreError> { unimplemented!() }
        fn list_vms_by_state(&self, _: &str) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
    }

    impl ImageStore for MockStore {
        fn create_image(&self, _params: &ImportImageParams, _subvolume_path: &str) -> Result<MasterImage, StoreError> {
            unimplemented!()
        }
        fn list_images(&self) -> Result<Vec<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn get_image_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<MasterImage>, StoreError> { unimplemented!() }
        fn get_image_by_name(&self, _name: &str) -> Result<Option<MasterImage>, StoreError> { unimplemented!() }
        fn get_image(&self, _name_or_id: &str) -> Result<Option<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn delete_image(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> {
            unimplemented!()
        }
    }

    impl DriveStore for MockStore {
        fn create_drive(&self, _name: Option<&str>, _subvolume_path: &str, _master_image_id: nexus_lib::id::Id) -> Result<Drive, StoreError> {
            unimplemented!()
        }
        fn list_drives(&self, _base: Option<&str>) -> Result<Vec<Drive>, StoreError> {
            unimplemented!()
        }
        fn get_drive_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<Drive>, StoreError> { unimplemented!() }
        fn get_drive_by_name(&self, _name: &str) -> Result<Option<Drive>, StoreError> { unimplemented!() }
        fn get_drive(&self, _name_or_id: &str) -> Result<Option<Drive>, StoreError> {
            unimplemented!()
        }
        fn delete_drive(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn attach_drive(&self, _drive_id: nexus_lib::id::Id, _vm_id: nexus_lib::id::Id, _is_root_device: bool) -> Result<Drive, StoreError> {
            unimplemented!()
        }
        fn detach_drive(&self, _drive_id: nexus_lib::id::Id) -> Result<Drive, StoreError> {
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
        fn delete_kernel(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
        fn register_rootfs(&self, _params: &RegisterRootfsParams) -> Result<RootfsImage, StoreError> { unimplemented!() }
        fn list_rootfs_images(&self) -> Result<Vec<RootfsImage>, StoreError> { Ok(vec![]) }
        fn get_rootfs(&self, _id: &str, _arch: Option<&str>) -> Result<Option<RootfsImage>, StoreError> { unimplemented!() }
        fn delete_rootfs(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
        fn register_firecracker(&self, _params: &RegisterFirecrackerParams) -> Result<FirecrackerVersion, StoreError> { unimplemented!() }
        fn list_firecracker_versions(&self) -> Result<Vec<FirecrackerVersion>, StoreError> { Ok(vec![]) }
        fn get_firecracker(&self, _id: &str, _arch: Option<&str>) -> Result<Option<FirecrackerVersion>, StoreError> { unimplemented!() }
        fn delete_firecracker(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
    }

    impl BuildStore for MockStore {
        fn create_template(&self, _params: &CreateTemplateParams) -> Result<Template, StoreError> { unimplemented!() }
        fn list_templates(&self) -> Result<Vec<Template>, StoreError> { unimplemented!() }
        fn get_template_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn get_template_by_name(&self, _name: &str) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn get_template(&self, _name_or_id: &str) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn delete_template(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
        fn create_build(&self, _template: &Template) -> Result<Build, StoreError> { unimplemented!() }
        fn list_builds(&self, _template: Option<&str>) -> Result<Vec<Build>, StoreError> { unimplemented!() }
        fn get_build(&self, _id: nexus_lib::id::Id) -> Result<Option<Build>, StoreError> { unimplemented!() }
        fn update_build_status(&self, _id: nexus_lib::id::Id, _status: BuildStatus, _master_image_id: Option<nexus_lib::id::Id>, _build_log_path: Option<&str>) -> Result<Build, StoreError> { unimplemented!() }
    }

    impl nexus_lib::store::traits::NetworkStore for MockStore {
        fn create_bridge(&self, _name: &str, _subnet: &str, _gateway: &str, _interface: &str) -> Result<(), StoreError> { unimplemented!() }
        fn list_bridges(&self) -> Result<Vec<nexus_lib::store::traits::Bridge>, StoreError> { unimplemented!() }
        fn get_bridge(&self, _name: &str) -> Result<Option<nexus_lib::store::traits::Bridge>, StoreError> { unimplemented!() }
        fn assign_vm_ip(&self, _vm_id: i64, _ip_address: &str, _bridge_name: &str) -> Result<(), StoreError> { unimplemented!() }
        fn get_vm_network(&self, _vm_id: i64) -> Result<Option<nexus_lib::store::traits::VmNetwork>, StoreError> { unimplemented!() }
        fn release_vm_ip(&self, _vm_id: i64) -> Result<(), StoreError> { unimplemented!() }
        fn list_allocated_ips(&self, _bridge_name: &str) -> Result<Vec<String>, StoreError> { unimplemented!() }
    }

    impl nexus_lib::store::traits::ProvisionStore for MockStore {
        fn add_provision_file(&self, _vm_id: nexus_lib::id::Id, _params: &nexus_lib::vm::AddProvisionFileParams) -> Result<nexus_lib::vm::ProvisionFile, StoreError> {
            unimplemented!()
        }
        fn list_provision_files(&self, _vm_id: nexus_lib::id::Id) -> Result<Vec<nexus_lib::vm::ProvisionFile>, StoreError> {
            Ok(vec![])
        }
        fn remove_provision_file(&self, _vm_id: nexus_lib::id::Id, _guest_path: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
    }

    impl nexus_lib::store::traits::SettingsStore for MockStore {
        fn get_setting(&self, _key: &str) -> Result<Option<String>, StoreError> { Ok(None) }
        fn set_setting(&self, _key: &str, _value: &str, _value_type: &str) -> Result<(), StoreError> { unimplemented!() }
        fn rollback_setting(&self, _key: &str, _version: i64) -> Result<(), StoreError> { unimplemented!() }
        fn list_settings(&self) -> Result<Vec<(String, String, String)>, StoreError> { Ok(vec![]) }
        fn validate_setting(&self, _key: &str, _value: &str) -> Result<(), StoreError> { unimplemented!() }
    }

    impl nexus_lib::store::traits::TagStore for MockStore {
        fn add_vm_tag(&self, _vm_id: nexus_lib::id::Id, _tag: &str) -> Result<(), StoreError> { unimplemented!() }
        fn list_vm_tags(&self, _vm_id: nexus_lib::id::Id) -> Result<Vec<String>, StoreError> { unimplemented!() }
        fn list_vms_by_tag(&self, _tag: &str) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
        fn remove_vm_tag(&self, _vm_id: nexus_lib::id::Id, _tag: &str) -> Result<bool, StoreError> { unimplemented!() }
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
        fn get_vm_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<Vm>, StoreError> { unimplemented!() }
        fn get_vm_by_name(&self, _name: &str) -> Result<Option<Vm>, StoreError> { unimplemented!() }
        fn get_vm(&self, _name_or_id: &str) -> Result<Option<Vm>, StoreError> {
            unimplemented!()
        }
        fn delete_vm(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn start_vm(&self, _: nexus_lib::id::Id, _: u32, _: &str, _: &str, _: &str, _: &str) -> Result<Vm, StoreError> { unimplemented!() }
        fn stop_vm(&self, _: nexus_lib::id::Id) -> Result<Vm, StoreError> { unimplemented!() }
        fn crash_vm(&self, _: nexus_lib::id::Id) -> Result<Vm, StoreError> { unimplemented!() }
        fn fail_vm(&self, _: nexus_lib::id::Id) -> Result<Vm, StoreError> { unimplemented!() }
        fn list_running_vms(&self) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
        fn record_boot_start(&self, _: nexus_lib::id::Id, _: &str) -> Result<nexus_lib::id::Id, StoreError> { unimplemented!() }
        fn record_boot_stop(&self, _: nexus_lib::id::Id, _: Option<i32>, _: Option<&str>) -> Result<(), StoreError> { unimplemented!() }
        fn update_vm_state(&self, _: nexus_lib::id::Id, _: &str, _: Option<&str>) -> Result<(), StoreError> { unimplemented!() }
        fn get_state_history(&self, _: nexus_lib::id::Id) -> Result<Vec<nexus_lib::vm::StateHistory>, StoreError> { unimplemented!() }
        fn set_vm_agent_connected_at(&self, _: nexus_lib::id::Id, _: i64) -> Result<(), StoreError> { unimplemented!() }
        fn list_vms_by_state(&self, _: &str) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
    }

    impl ImageStore for FailingStore {
        fn create_image(&self, _params: &ImportImageParams, _subvolume_path: &str) -> Result<MasterImage, StoreError> {
            unimplemented!()
        }
        fn list_images(&self) -> Result<Vec<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn get_image_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<MasterImage>, StoreError> { unimplemented!() }
        fn get_image_by_name(&self, _name: &str) -> Result<Option<MasterImage>, StoreError> { unimplemented!() }
        fn get_image(&self, _name_or_id: &str) -> Result<Option<MasterImage>, StoreError> {
            unimplemented!()
        }
        fn delete_image(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> {
            unimplemented!()
        }
    }

    impl DriveStore for FailingStore {
        fn create_drive(&self, _name: Option<&str>, _subvolume_path: &str, _master_image_id: nexus_lib::id::Id) -> Result<Drive, StoreError> {
            unimplemented!()
        }
        fn list_drives(&self, _base: Option<&str>) -> Result<Vec<Drive>, StoreError> {
            unimplemented!()
        }
        fn get_drive_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<Drive>, StoreError> { unimplemented!() }
        fn get_drive_by_name(&self, _name: &str) -> Result<Option<Drive>, StoreError> { unimplemented!() }
        fn get_drive(&self, _name_or_id: &str) -> Result<Option<Drive>, StoreError> {
            unimplemented!()
        }
        fn delete_drive(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> {
            unimplemented!()
        }
        fn attach_drive(&self, _drive_id: nexus_lib::id::Id, _vm_id: nexus_lib::id::Id, _is_root_device: bool) -> Result<Drive, StoreError> {
            unimplemented!()
        }
        fn detach_drive(&self, _drive_id: nexus_lib::id::Id) -> Result<Drive, StoreError> {
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
        fn delete_kernel(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
        fn register_rootfs(&self, _params: &RegisterRootfsParams) -> Result<RootfsImage, StoreError> { unimplemented!() }
        fn list_rootfs_images(&self) -> Result<Vec<RootfsImage>, StoreError> { unimplemented!() }
        fn get_rootfs(&self, _id: &str, _arch: Option<&str>) -> Result<Option<RootfsImage>, StoreError> { unimplemented!() }
        fn delete_rootfs(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
        fn register_firecracker(&self, _params: &RegisterFirecrackerParams) -> Result<FirecrackerVersion, StoreError> { unimplemented!() }
        fn list_firecracker_versions(&self) -> Result<Vec<FirecrackerVersion>, StoreError> { unimplemented!() }
        fn get_firecracker(&self, _id: &str, _arch: Option<&str>) -> Result<Option<FirecrackerVersion>, StoreError> { unimplemented!() }
        fn delete_firecracker(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
    }

    impl BuildStore for FailingStore {
        fn create_template(&self, _params: &CreateTemplateParams) -> Result<Template, StoreError> { unimplemented!() }
        fn list_templates(&self) -> Result<Vec<Template>, StoreError> { unimplemented!() }
        fn get_template_by_id(&self, _id: nexus_lib::id::Id) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn get_template_by_name(&self, _name: &str) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn get_template(&self, _name_or_id: &str) -> Result<Option<Template>, StoreError> { unimplemented!() }
        fn delete_template(&self, _id: nexus_lib::id::Id) -> Result<bool, StoreError> { unimplemented!() }
        fn create_build(&self, _template: &Template) -> Result<Build, StoreError> { unimplemented!() }
        fn list_builds(&self, _template: Option<&str>) -> Result<Vec<Build>, StoreError> { unimplemented!() }
        fn get_build(&self, _id: nexus_lib::id::Id) -> Result<Option<Build>, StoreError> { unimplemented!() }
        fn update_build_status(&self, _id: nexus_lib::id::Id, _status: BuildStatus, _master_image_id: Option<nexus_lib::id::Id>, _build_log_path: Option<&str>) -> Result<Build, StoreError> { unimplemented!() }
    }

    impl nexus_lib::store::traits::NetworkStore for FailingStore {
        fn create_bridge(&self, _name: &str, _subnet: &str, _gateway: &str, _interface: &str) -> Result<(), StoreError> { unimplemented!() }
        fn list_bridges(&self) -> Result<Vec<nexus_lib::store::traits::Bridge>, StoreError> { unimplemented!() }
        fn get_bridge(&self, _name: &str) -> Result<Option<nexus_lib::store::traits::Bridge>, StoreError> { unimplemented!() }
        fn assign_vm_ip(&self, _vm_id: i64, _ip_address: &str, _bridge_name: &str) -> Result<(), StoreError> { unimplemented!() }
        fn get_vm_network(&self, _vm_id: i64) -> Result<Option<nexus_lib::store::traits::VmNetwork>, StoreError> { unimplemented!() }
        fn release_vm_ip(&self, _vm_id: i64) -> Result<(), StoreError> { unimplemented!() }
        fn list_allocated_ips(&self, _bridge_name: &str) -> Result<Vec<String>, StoreError> { unimplemented!() }
    }

    impl nexus_lib::store::traits::ProvisionStore for FailingStore {
        fn add_provision_file(&self, _vm_id: nexus_lib::id::Id, _params: &nexus_lib::vm::AddProvisionFileParams) -> Result<nexus_lib::vm::ProvisionFile, StoreError> {
            unimplemented!()
        }
        fn list_provision_files(&self, _vm_id: nexus_lib::id::Id) -> Result<Vec<nexus_lib::vm::ProvisionFile>, StoreError> {
            Ok(vec![])
        }
        fn remove_provision_file(&self, _vm_id: nexus_lib::id::Id, _guest_path: &str) -> Result<bool, StoreError> {
            unimplemented!()
        }
    }

    impl nexus_lib::store::traits::SettingsStore for FailingStore {
        fn get_setting(&self, _key: &str) -> Result<Option<String>, StoreError> { Ok(None) }
        fn set_setting(&self, _key: &str, _value: &str, _value_type: &str) -> Result<(), StoreError> { unimplemented!() }
        fn rollback_setting(&self, _key: &str, _version: i64) -> Result<(), StoreError> { unimplemented!() }
        fn list_settings(&self) -> Result<Vec<(String, String, String)>, StoreError> { Ok(vec![]) }
        fn validate_setting(&self, _key: &str, _value: &str) -> Result<(), StoreError> { unimplemented!() }
    }

    impl nexus_lib::store::traits::TagStore for FailingStore {
        fn add_vm_tag(&self, _vm_id: nexus_lib::id::Id, _tag: &str) -> Result<(), StoreError> { unimplemented!() }
        fn list_vm_tags(&self, _vm_id: nexus_lib::id::Id) -> Result<Vec<String>, StoreError> { unimplemented!() }
        fn list_vms_by_tag(&self, _tag: &str) -> Result<Vec<Vm>, StoreError> { unimplemented!() }
        fn remove_vm_tag(&self, _vm_id: nexus_lib::id::Id, _tag: &str) -> Result<bool, StoreError> { unimplemented!() }
    }

    impl StateStore for FailingStore {
        fn init(&self) -> Result<(), StoreError> { Ok(()) }
        fn status(&self) -> Result<DbStatus, StoreError> {
            Err(StoreError::Query("disk I/O error".to_string()))
        }
        fn close(&self) -> Result<(), StoreError> { Ok(()) }
    }

    fn mock_state_with_store(store: impl StateStore + Send + Sync + 'static) -> Arc<AppState> {
        let store_arc: Arc<dyn StateStore + Send + Sync> = Arc::new(store);
        let vsock_manager = Arc::new(VsockManager::new(store_arc.clone()));
        let network_service = nexus_lib::network_service::NetworkService::new(
            store_arc.clone(),
            store_arc.clone(), // StateStore implements SettingsStore
        );
        Arc::new(AppState {
            store: store_arc,
            backend: Box::new(MockBackend),
            drives_root: std::path::PathBuf::from("/tmp/mock-ws"),
            assets_dir: std::path::PathBuf::from("/tmp/mock-assets"),
            executor: nexus_lib::pipeline::PipelineExecutor::new(),
            vsock_manager,
            network_service,
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

    use nexus_lib::backend::traits::{BackendError, DriveBackend, SubvolumeInfo};

    /// A no-op backend for API unit tests (no real btrfs needed).
    struct MockBackend;

    impl DriveBackend for MockBackend {
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
        fn resize_drive(&self, _subvolume_path: &std::path::Path, _size_bytes: u64) -> Result<(), BackendError> { Ok(()) }
    }

    fn test_state() -> Arc<AppState> {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let drives_root = dir.path().join("drives");
        let assets_dir = dir.path().join("assets");
        std::fs::create_dir_all(&drives_root).unwrap();
        std::fs::create_dir_all(&assets_dir).unwrap();
        let store = SqliteStore::open_and_init(&db_path).unwrap();
        // Leak the tempdir so it lives long enough
        std::mem::forget(dir);
        let store_arc: Arc<dyn StateStore + Send + Sync> = Arc::new(store);
        let vsock_manager = Arc::new(VsockManager::new(store_arc.clone()));
        let network_service = nexus_lib::network_service::NetworkService::new(
            store_arc.clone(),
            store_arc.clone(), // StateStore implements SettingsStore
        );
        Arc::new(AppState {
            store: store_arc,
            backend: Box::new(MockBackend),
            drives_root,
            assets_dir,
            executor: nexus_lib::pipeline::PipelineExecutor::new(),
            vsock_manager,
            network_service,
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

    #[tokio::test(flavor = "multi_thread")]
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
    async fn attach_and_detach_drive() {
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

        // Create a drive
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/drives")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"base": "attach-img", "name": "attach-ws"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Attach drive to VM
        let attach_body = serde_json::json!({
            "vm_id": vm_id,
            "is_root_device": true
        });
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/drives/attach-ws/attach")
                    .header("content-type", "application/json")
                    .body(Body::from(attach_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let drive: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(drive["vm_id"], vm_id);
        assert_eq!(drive["is_root_device"], true);

        // Detach drive
        let resp = router(state.clone())
            .oneshot(
                Request::post("/v1/drives/attach-ws/detach")
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

    #[tokio::test]
    async fn vm_history_endpoint() {
        let state = test_state();

        // Create a VM
        let params = CreateVmParams {
            name: "test-vm".to_string(),
            role: nexus_lib::vm::VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        let vm = state.store.create_vm(&params).unwrap();

        // Trigger state transitions
        state.store.update_vm_state(vm.id, "running", Some("started")).unwrap();
        state.store.update_vm_state(vm.id, "online", Some("agent connected")).unwrap();
        state.store.update_vm_state(vm.id, "provisioning", Some("provisioning started")).unwrap();
        state.store.update_vm_state(vm.id, "ready", Some("provisioning complete")).unwrap();

        let app = router(state);

        let req = Request::builder()
            .uri("/v1/vms/test-vm/history")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let history: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

        assert_eq!(history.len(), 4);
        assert_eq!(history[0]["from_state"], "provisioning");
        assert_eq!(history[0]["to_state"], "ready");
        assert_eq!(history[1]["from_state"], "online");
        assert_eq!(history[1]["to_state"], "provisioning");
        assert_eq!(history[2]["from_state"], "running");
        assert_eq!(history[2]["to_state"], "online");
        assert_eq!(history[3]["from_state"], "created");
        assert_eq!(history[3]["to_state"], "running");
    }

    #[tokio::test]
    async fn vm_history_not_found() {
        let state = test_state();
        let app = router(state);

        let req = Request::builder()
            .uri("/v1/vms/nonexistent/history")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
