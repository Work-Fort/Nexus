use crate::backend::traits::{BackendError, SubvolumeInfo, WorkspaceBackend};
use std::path::{Path, PathBuf};

/// btrfs-backed implementation of WorkspaceBackend.
///
/// Uses libbtrfsutil for subvolume operations. Common operations
/// (create, snapshot) work unprivileged — no CAP_SYS_ADMIN required.
pub struct BtrfsBackend {
    /// Root directory for all workspace subvolumes.
    /// Typically $XDG_DATA_HOME/nexus/workspaces/
    workspaces_root: PathBuf,
}

impl BtrfsBackend {
    pub fn new(workspaces_root: PathBuf) -> Result<Self, BackendError> {
        // Ensure the workspaces root directory exists
        std::fs::create_dir_all(&workspaces_root).map_err(|e| {
            BackendError::Io(format!(
                "cannot create workspaces directory {}: {e}",
                workspaces_root.display()
            ))
        })?;

        Ok(BtrfsBackend { workspaces_root })
    }

    pub fn workspaces_root(&self) -> &Path {
        &self.workspaces_root
    }
}

impl WorkspaceBackend for BtrfsBackend {
    fn import_image(&self, source: &Path, dest: &Path) -> Result<SubvolumeInfo, BackendError> {
        // Validate source exists
        if !source.exists() {
            return Err(BackendError::NotFound(format!(
                "source path does not exist: {}",
                source.display()
            )));
        }

        // Check dest doesn't already exist
        if dest.exists() {
            return Err(BackendError::AlreadyExists(format!(
                "destination already exists: {}",
                dest.display()
            )));
        }

        // Create a subvolume at dest
        libbtrfsutil::create_subvolume(dest).map_err(|e| {
            BackendError::Io(format!(
                "cannot create subvolume at {}: {e}",
                dest.display()
            ))
        })?;

        // Copy contents from source into the new subvolume
        copy_dir_contents(source, dest).map_err(|e| {
            // Clean up the subvolume on failure
            let _ = libbtrfsutil::delete_subvolume(dest);
            BackendError::Io(format!(
                "cannot copy contents from {} to {}: {e}",
                source.display(),
                dest.display()
            ))
        })?;

        // Mark as read-only
        libbtrfsutil::set_subvolume_read_only(dest, true).map_err(|e| {
            BackendError::Io(format!(
                "cannot set read-only on {}: {e}",
                dest.display()
            ))
        })?;

        Ok(SubvolumeInfo {
            path: dest.to_path_buf(),
            read_only: true,
            size_bytes: dir_size(dest).ok(),
        })
    }

    fn create_snapshot(&self, source: &Path, dest: &Path) -> Result<SubvolumeInfo, BackendError> {
        // Validate source is a subvolume
        if !libbtrfsutil::is_subvolume(source).unwrap_or(false) {
            return Err(BackendError::NotFound(format!(
                "source is not a btrfs subvolume: {}",
                source.display()
            )));
        }

        // Check dest doesn't already exist
        if dest.exists() {
            return Err(BackendError::AlreadyExists(format!(
                "destination already exists: {}",
                dest.display()
            )));
        }

        // Create a writable snapshot
        libbtrfsutil::CreateSnapshotOptions::new()
            .create(source, dest)
            .map_err(|e| {
                BackendError::Io(format!(
                    "cannot create snapshot from {} to {}: {e}",
                    source.display(),
                    dest.display()
                ))
            })?;

        Ok(SubvolumeInfo {
            path: dest.to_path_buf(),
            read_only: false,
            size_bytes: dir_size(dest).ok(),
        })
    }

    fn delete_subvolume(&self, path: &Path) -> Result<(), BackendError> {
        if !path.exists() {
            return Err(BackendError::NotFound(format!(
                "subvolume does not exist: {}",
                path.display()
            )));
        }

        // If read-only, make writable first (required for deletion)
        if libbtrfsutil::subvolume_read_only(path).unwrap_or(false) {
            libbtrfsutil::set_subvolume_read_only(path, false).map_err(|e| {
                BackendError::Io(format!(
                    "cannot unset read-only on {}: {e}",
                    path.display()
                ))
            })?;
        }

        libbtrfsutil::delete_subvolume(path).map_err(|e| {
            BackendError::Io(format!(
                "cannot delete subvolume {}: {e}",
                path.display()
            ))
        })
    }

    fn is_subvolume(&self, path: &Path) -> Result<bool, BackendError> {
        Ok(libbtrfsutil::is_subvolume(path).unwrap_or(false))
    }

    fn subvolume_info(&self, path: &Path) -> Result<SubvolumeInfo, BackendError> {
        if !path.exists() {
            return Err(BackendError::NotFound(format!(
                "path does not exist: {}",
                path.display()
            )));
        }

        let read_only = libbtrfsutil::subvolume_read_only(path).map_err(|e| {
            BackendError::Io(format!(
                "cannot query subvolume {}: {e}",
                path.display()
            ))
        })?;

        Ok(SubvolumeInfo {
            path: path.to_path_buf(),
            read_only,
            size_bytes: dir_size(path).ok(),
        })
    }

    fn set_read_only(&self, path: &Path, read_only: bool) -> Result<(), BackendError> {
        libbtrfsutil::set_subvolume_read_only(path, read_only).map_err(|e| {
            BackendError::Io(format!(
                "cannot set read-only={read_only} on {}: {e}",
                path.display()
            ))
        })
    }
}

/// Recursively copy directory contents from src to dest.
/// dest must already exist.
fn copy_dir_contents(src: &Path, dest: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            copy_dir_contents(&src_path, &dest_path)?;
        } else {
            std::fs::copy(&src_path, &dest_path)?;
        }
    }
    Ok(())
}

/// Estimate directory size by summing file sizes.
fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size(&entry.path())?;
        }
    }
    Ok(total)
}
