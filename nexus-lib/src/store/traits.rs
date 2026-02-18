use crate::vm::{CreateVmParams, Vm};
use crate::workspace::{ImportImageParams, MasterImage, Workspace};

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
        }
    }
}

impl std::error::Error for StoreError {}

/// Storage abstraction trait for future backend swaps.
///
/// All state persistence goes through this trait. The pre-alpha
/// implementation is SQLite; this trait exists so the backend can
/// be swapped to Postgres or etcd for clustering later.
pub trait StateStore {
    /// Initialize the store (create schema if needed, run migrations).
    fn init(&self) -> Result<(), StoreError>;

    /// Return database status information for health/status reporting.
    fn status(&self) -> Result<DbStatus, StoreError>;

    /// Close the store and release resources.
    fn close(&self) -> Result<(), StoreError>;

    /// Create a new VM record. Assigns a unique ID and auto-assigns a vsock CID.
    /// Returns the created VM.
    fn create_vm(&self, params: &CreateVmParams) -> Result<Vm, StoreError>;

    /// List all VMs, optionally filtered by role and/or state.
    fn list_vms(&self, role: Option<&str>, state: Option<&str>) -> Result<Vec<Vm>, StoreError>;

    /// Get a single VM by name or ID.
    fn get_vm(&self, name_or_id: &str) -> Result<Option<Vm>, StoreError>;

    /// Delete a VM by name or ID. Returns true if a record was deleted.
    /// Refuses to delete VMs in the `running` state (returns StoreError).
    fn delete_vm(&self, name_or_id: &str) -> Result<bool, StoreError>;

    // --- Master Image methods ---

    /// Register a master image in the database.
    fn create_image(&self, params: &ImportImageParams, subvolume_path: &str) -> Result<MasterImage, StoreError>;

    /// List all master images.
    fn list_images(&self) -> Result<Vec<MasterImage>, StoreError>;

    /// Get a master image by name or ID.
    fn get_image(&self, name_or_id: &str) -> Result<Option<MasterImage>, StoreError>;

    /// Delete a master image by name or ID.
    /// Returns true if deleted, false if not found.
    /// Fails with Conflict if workspaces reference this image.
    fn delete_image(&self, name_or_id: &str) -> Result<bool, StoreError>;

    // --- Workspace methods ---

    /// Register a workspace in the database.
    fn create_workspace(
        &self,
        name: Option<&str>,
        subvolume_path: &str,
        master_image_id: &str,
    ) -> Result<Workspace, StoreError>;

    /// List all workspaces, optionally filtered by master image name.
    fn list_workspaces(&self, base: Option<&str>) -> Result<Vec<Workspace>, StoreError>;

    /// Get a workspace by name or ID.
    fn get_workspace(&self, name_or_id: &str) -> Result<Option<Workspace>, StoreError>;

    /// Delete a workspace by name or ID.
    /// Returns true if deleted, false if not found.
    /// Fails with Conflict if workspace is attached to a VM.
    fn delete_workspace(&self, name_or_id: &str) -> Result<bool, StoreError>;
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
