// SPDX-License-Identifier: GPL-2.0-only
use std::path::{Path, PathBuf};

/// Errors from workspace backend operations.
#[derive(Debug)]
pub enum BackendError {
    /// The source path does not exist or is inaccessible
    NotFound(String),
    /// A subvolume/image with this name already exists
    AlreadyExists(String),
    /// Filesystem operation failed
    Io(String),
    /// The backend does not support this operation
    Unsupported(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::NotFound(e) => write!(f, "not found: {e}"),
            BackendError::AlreadyExists(e) => write!(f, "already exists: {e}"),
            BackendError::Io(e) => write!(f, "I/O error: {e}"),
            BackendError::Unsupported(e) => write!(f, "unsupported: {e}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Information about a subvolume/snapshot returned by the backend.
#[derive(Debug, Clone)]
pub struct SubvolumeInfo {
    pub path: PathBuf,
    pub read_only: bool,
    /// Size in bytes, if available
    pub size_bytes: Option<u64>,
}

/// Filesystem-agnostic trait for workspace storage operations.
///
/// The btrfs implementation uses subvolumes and CoW snapshots.
/// Other implementations could use directory copies, ZFS, OverlayFS, etc.
///
/// This trait is `Send + Sync` so it can be stored in `AppState` and
/// shared across async tasks.
pub trait WorkspaceBackend: Send + Sync {
    /// Import a directory as a new master image subvolume.
    ///
    /// 1. Creates a new subvolume at `dest` (under the workspaces root)
    /// 2. Copies contents from `source` into the subvolume
    /// 3. Marks the subvolume as read-only
    ///
    /// Returns the path to the created subvolume.
    fn import_image(&self, source: &Path, dest: &Path) -> Result<SubvolumeInfo, BackendError>;

    /// Create a snapshot of an existing subvolume.
    ///
    /// For btrfs: `btrfs subvolume snapshot source dest`
    /// The snapshot is writable by default.
    fn create_snapshot(&self, source: &Path, dest: &Path) -> Result<SubvolumeInfo, BackendError>;

    /// Delete a subvolume/snapshot.
    fn delete_subvolume(&self, path: &Path) -> Result<(), BackendError>;

    /// Check if a path is a valid subvolume managed by this backend.
    fn is_subvolume(&self, path: &Path) -> Result<bool, BackendError>;

    /// Get information about a subvolume.
    fn subvolume_info(&self, path: &Path) -> Result<SubvolumeInfo, BackendError>;

    /// Set whether a subvolume is read-only.
    fn set_read_only(&self, path: &Path, read_only: bool) -> Result<(), BackendError>;
}
