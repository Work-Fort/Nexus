// SPDX-License-Identifier: GPL-2.0-only
use crate::asset::{
    FirecrackerVersion, Kernel, Provider, RegisterFirecrackerParams,
    RegisterKernelParams, RegisterRootfsParams, RootfsImage,
};
use crate::drive::{Drive, ImportImageParams, MasterImage};
use crate::id::Id;
use crate::template::{Build, BuildStatus, CreateTemplateParams, Template};
use crate::vm::{CreateVmParams, Vm};

/// Information about the database for status reporting.
#[derive(Debug, Clone)]
pub struct DbStatus {
    /// Path to the database file (or connection string for non-file backends)
    pub path: String,
    /// Number of user tables in the database
    pub table_count: usize,
    /// Size of the database file in bytes (None if not applicable)
    pub size_bytes: Option<u64>,
}

/// Errors from the state store.
#[derive(Debug)]
pub enum StoreError {
    /// Database connection or initialization failed
    Init(String),
    /// Query execution failed
    Query(String),
    /// Schema migration required (version mismatch)
    SchemaMismatch { expected: u32, found: u32 },
    /// Operation not allowed in current state
    Conflict(String),
    /// Invalid input (e.g., name validation failed)
    InvalidInput(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Init(e) => write!(f, "store initialization failed: {e}"),
            StoreError::Query(e) => write!(f, "store query failed: {e}"),
            StoreError::SchemaMismatch { expected, found } => {
                write!(f, "schema version mismatch: expected {expected}, found {found}")
            }
            StoreError::Conflict(e) => write!(f, "conflict: {e}"),
            StoreError::InvalidInput(e) => write!(f, "invalid input: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone)]
pub struct Bridge {
    pub name: String,
    pub subnet: String,
    pub gateway: String,
    pub interface: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct VmNetwork {
    pub vm_id: i64,
    pub ip_address: String,
    pub bridge_name: String,
}

/// VM record persistence.
pub trait VmStore {
    /// Create a new VM record. Assigns a unique ID and auto-assigns a vsock CID.
    /// Returns the created VM.
    fn create_vm(&self, params: &CreateVmParams) -> Result<Vm, StoreError>;

    /// List all VMs, optionally filtered by role and/or state.
    fn list_vms(&self, role: Option<&str>, state: Option<&str>) -> Result<Vec<Vm>, StoreError>;

    /// Get a single VM by ID.
    fn get_vm_by_id(&self, id: Id) -> Result<Option<Vm>, StoreError>;

    /// Get a single VM by name.
    fn get_vm_by_name(&self, name: &str) -> Result<Option<Vm>, StoreError>;

    /// Get a single VM by name or ID (convenience method for API layer).
    fn get_vm(&self, name_or_id: &str) -> Result<Option<Vm>, StoreError>;

    /// Delete a VM by ID. Returns true if a record was deleted.
    /// Refuses to delete VMs in the `running` state (returns StoreError).
    fn delete_vm(&self, id: Id) -> Result<bool, StoreError>;

    /// Update VM state and runtime fields when starting.
    /// Sets state to `running`, records pid, socket_path, uds_path,
    /// console_log_path, config_json, started_at, and updated_at.
    fn start_vm(
        &self,
        id: Id,
        pid: u32,
        socket_path: &str,
        uds_path: &str,
        console_log_path: &str,
        config_json: &str,
    ) -> Result<Vm, StoreError>;

    /// Update VM state to `stopped`. Clears pid, sets stopped_at and updated_at.
    fn stop_vm(&self, id: Id) -> Result<Vm, StoreError>;

    /// Update VM state to `crashed`. Clears pid, sets stopped_at and updated_at.
    fn crash_vm(&self, id: Id) -> Result<Vm, StoreError>;

    /// Update VM state to `failed`. Clears pid, sets stopped_at and updated_at.
    fn fail_vm(&self, id: Id) -> Result<Vm, StoreError>;

    /// List all VMs in the `running` state.
    fn list_running_vms(&self) -> Result<Vec<Vm>, StoreError>;

    /// Record a boot event in vm_boot_history. Returns the boot record ID.
    fn record_boot_start(&self, vm_id: Id, console_log_path: &str) -> Result<Id, StoreError>;

    /// Complete a boot history record with exit details.
    fn record_boot_stop(
        &self,
        boot_id: Id,
        exit_code: Option<i32>,
        error_message: Option<&str>,
    ) -> Result<(), StoreError>;

    /// Update VM state and record transition in history
    fn update_vm_state(&self, id: Id, new_state: &str, reason: Option<&str>) -> Result<(), StoreError>;

    /// Get state transition history for a VM, ordered by timestamp (newest first).
    fn get_state_history(&self, vm_id: Id) -> Result<Vec<crate::vm::StateHistory>, StoreError>;

    /// Set agent_connected_at timestamp
    fn set_vm_agent_connected_at(&self, id: Id, timestamp: i64) -> Result<(), StoreError>;

    /// List VMs by state
    fn list_vms_by_state(&self, state: &str) -> Result<Vec<Vm>, StoreError>;
}

/// Master image record persistence.
pub trait ImageStore {
    /// Register a master image in the database.
    fn create_image(&self, params: &ImportImageParams, subvolume_path: &str) -> Result<MasterImage, StoreError>;

    /// List all master images.
    fn list_images(&self) -> Result<Vec<MasterImage>, StoreError>;

    /// Get a master image by ID.
    fn get_image_by_id(&self, id: Id) -> Result<Option<MasterImage>, StoreError>;

    /// Get a master image by name.
    fn get_image_by_name(&self, name: &str) -> Result<Option<MasterImage>, StoreError>;

    /// Get a master image by name or ID (convenience method for API layer).
    fn get_image(&self, name_or_id: &str) -> Result<Option<MasterImage>, StoreError>;

    /// Delete a master image by ID.
    /// Returns true if deleted, false if not found.
    /// Fails with Conflict if drives reference this image.
    fn delete_image(&self, id: Id) -> Result<bool, StoreError>;
}

/// Drive record persistence.
pub trait DriveStore {
    /// Register a drive in the database.
    fn create_drive(
        &self,
        name: Option<&str>,
        subvolume_path: &str,
        master_image_id: Id,
    ) -> Result<Drive, StoreError>;

    /// List all drives, optionally filtered by master image name.
    fn list_drives(&self, base: Option<&str>) -> Result<Vec<Drive>, StoreError>;

    /// Get a drive by ID.
    fn get_drive_by_id(&self, id: Id) -> Result<Option<Drive>, StoreError>;

    /// Get a drive by name.
    fn get_drive_by_name(&self, name: &str) -> Result<Option<Drive>, StoreError>;

    /// Get a drive by name or ID (convenience method for API layer).
    fn get_drive(&self, name_or_id: &str) -> Result<Option<Drive>, StoreError>;

    /// Delete a drive by ID.
    /// Returns true if deleted, false if not found.
    /// Fails with Conflict if drive is attached to a VM.
    fn delete_drive(&self, id: Id) -> Result<bool, StoreError>;

    /// Attach a drive to a VM. Sets vm_id, is_root_device, and attached_at.
    fn attach_drive(&self, drive_id: Id, vm_id: Id, is_root_device: bool) -> Result<Drive, StoreError>;

    /// Detach a drive from a VM. Clears vm_id, is_root_device, sets detached_at.
    fn detach_drive(&self, drive_id: Id) -> Result<Drive, StoreError>;
}

/// Provider and downloaded asset persistence.
pub trait AssetStore {
    /// Get a provider by name or ID (convenience method for API layer).
    fn get_provider(&self, name_or_id: &str) -> Result<Option<Provider>, StoreError>;

    /// Get the default provider for an asset type ("kernel", "rootfs", "firecracker").
    fn get_default_provider(&self, asset_type: &str) -> Result<Option<Provider>, StoreError>;

    /// List all providers, optionally filtered by asset type.
    fn list_providers(&self, asset_type: Option<&str>) -> Result<Vec<Provider>, StoreError>;

    /// Register a downloaded kernel. Assigns a unique ID. Returns the created record.
    fn register_kernel(&self, params: &RegisterKernelParams) -> Result<Kernel, StoreError>;

    /// List all downloaded kernels.
    fn list_kernels(&self) -> Result<Vec<Kernel>, StoreError>;

    /// Get a kernel by version+arch or by ID (convenience method for API layer).
    fn get_kernel(&self, id_or_version: &str, arch: Option<&str>) -> Result<Option<Kernel>, StoreError>;

    /// Delete a kernel record by ID. Returns true if deleted.
    fn delete_kernel(&self, id: Id) -> Result<bool, StoreError>;

    /// Register a downloaded rootfs image. Assigns a unique ID. Returns the created record.
    fn register_rootfs(&self, params: &RegisterRootfsParams) -> Result<RootfsImage, StoreError>;

    /// List all downloaded rootfs images.
    fn list_rootfs_images(&self) -> Result<Vec<RootfsImage>, StoreError>;

    /// Get a rootfs image by distro+version+arch or by ID (convenience method for API layer).
    fn get_rootfs(&self, id_or_version: &str, arch: Option<&str>) -> Result<Option<RootfsImage>, StoreError>;

    /// Delete a rootfs image record by ID. Returns true if deleted.
    fn delete_rootfs(&self, id: Id) -> Result<bool, StoreError>;

    /// Register a downloaded Firecracker binary. Assigns a unique ID. Returns the created record.
    fn register_firecracker(&self, params: &RegisterFirecrackerParams) -> Result<FirecrackerVersion, StoreError>;

    /// List all downloaded Firecracker versions.
    fn list_firecracker_versions(&self) -> Result<Vec<FirecrackerVersion>, StoreError>;

    /// Get a Firecracker version by version+arch or by ID (convenience method for API layer).
    fn get_firecracker(&self, id_or_version: &str, arch: Option<&str>) -> Result<Option<FirecrackerVersion>, StoreError>;

    /// Delete a Firecracker version record by ID. Returns true if deleted.
    fn delete_firecracker(&self, id: Id) -> Result<bool, StoreError>;
}

/// Template and build persistence.
pub trait BuildStore {
    /// Create a new template. Returns the created template.
    fn create_template(&self, params: &CreateTemplateParams) -> Result<Template, StoreError>;

    /// List all templates.
    fn list_templates(&self) -> Result<Vec<Template>, StoreError>;

    /// Get a template by ID.
    fn get_template_by_id(&self, id: Id) -> Result<Option<Template>, StoreError>;

    /// Get a template by name.
    fn get_template_by_name(&self, name: &str) -> Result<Option<Template>, StoreError>;

    /// Get a template by name or ID (convenience method for API layer).
    fn get_template(&self, name_or_id: &str) -> Result<Option<Template>, StoreError>;

    /// Delete a template by ID. Cascade-deletes associated builds.
    /// Returns true if deleted, false if not found.
    fn delete_template(&self, id: Id) -> Result<bool, StoreError>;

    /// Create a new build from a template snapshot.
    fn create_build(&self, template: &Template) -> Result<Build, StoreError>;

    /// List all builds, optionally filtered by template name.
    fn list_builds(&self, template: Option<&str>) -> Result<Vec<Build>, StoreError>;

    /// Get a build by ID.
    fn get_build(&self, id: Id) -> Result<Option<Build>, StoreError>;

    /// Update a build's status. Sets completed_at when status is success or failed.
    /// For success, also sets master_image_id.
    fn update_build_status(
        &self,
        id: Id,
        status: BuildStatus,
        master_image_id: Option<Id>,
        build_log_path: Option<&str>,
    ) -> Result<Build, StoreError>;
}

/// Network state management (Step 12)
pub trait NetworkStore {
    // Bridge management
    fn create_bridge(
        &self,
        name: &str,
        subnet: &str,
        gateway: &str,
        interface: &str,
    ) -> Result<(), StoreError>;
    fn list_bridges(&self) -> Result<Vec<Bridge>, StoreError>;
    fn get_bridge(&self, name: &str) -> Result<Option<Bridge>, StoreError>;

    // VM network assignment
    fn assign_vm_ip(
        &self,
        vm_id: i64,
        ip_address: &str,
        bridge_name: &str,
    ) -> Result<(), StoreError>;
    fn get_vm_network(&self, vm_id: i64) -> Result<Option<VmNetwork>, StoreError>;
    fn release_vm_ip(&self, vm_id: i64) -> Result<(), StoreError>;
    fn list_allocated_ips(&self, bridge_name: &str) -> Result<Vec<String>, StoreError>;
}

/// Settings store for runtime preferences (versioned key-value store).
pub trait SettingsStore {
    /// Get the current value for a setting key.
    /// Returns None if the key does not exist.
    fn get_setting(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Set a setting value, creating a new version.
    /// Marks the new version as current and marks all other versions as not current.
    /// `value_type` must be one of: 'string', 'int', 'bool', 'json'.
    fn set_setting(&self, key: &str, value: &str, value_type: &str) -> Result<(), StoreError>;

    /// Rollback a setting to a specific version.
    /// Marks the target version as current and marks all other versions as not current.
    /// For non-JSON settings, version parameter is ignored (latest historical value used).
    /// For JSON settings, version must match the `version` field in the JSON value.
    fn rollback_setting(&self, key: &str, version: i64) -> Result<(), StoreError>;

    /// List all settings with their current values.
    fn list_settings(&self) -> Result<Vec<(String, String, String)>, StoreError>;

    /// Validate a setting value against its schema.
    /// Returns Ok(()) if valid, Err with detailed message if invalid.
    /// See config-schemas.md for validation rules per setting.
    fn validate_setting(&self, key: &str, value: &str) -> Result<(), StoreError>;
}

/// Convenience super-trait for code that needs the full store.
///
/// All state persistence goes through this trait. The pre-alpha
/// implementation is SQLite; this trait exists so the backend can
/// be swapped to Postgres or etcd for clustering later.
pub trait StateStore: VmStore + ImageStore + DriveStore + AssetStore + BuildStore + NetworkStore + SettingsStore {
    /// Initialize the store (create schema if needed, run migrations).
    fn init(&self) -> Result<(), StoreError>;

    /// Return database status information for health/status reporting.
    fn status(&self) -> Result<DbStatus, StoreError>;

    /// Close the store and release resources.
    fn close(&self) -> Result<(), StoreError>;

    // NOTE: get_setting() removed from StateStore - now provided by SettingsStore trait
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_status_fields_accessible() {
        let status = DbStatus {
            path: "/tmp/test.db".to_string(),
            table_count: 5,
            size_bytes: Some(4096),
        };
        assert_eq!(status.path, "/tmp/test.db");
        assert_eq!(status.table_count, 5);
        assert_eq!(status.size_bytes, Some(4096));
    }

    #[test]
    fn store_error_display() {
        let err = StoreError::Init("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));

        let err = StoreError::SchemaMismatch { expected: 2, found: 1 };
        assert!(err.to_string().contains("expected 2"));
        assert!(err.to_string().contains("found 1"));
    }
}
