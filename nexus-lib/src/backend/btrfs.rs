// SPDX-License-Identifier: GPL-2.0-only
use crate::backend::traits::{BackendError, DriveBackend, SubvolumeInfo};
use std::path::{Path, PathBuf};

/// btrfs-backed implementation of DriveBackend.
///
/// Uses libbtrfsutil for subvolume operations. Common operations
/// (create, snapshot) work unprivileged — no CAP_SYS_ADMIN required.
pub struct BtrfsBackend {
    /// Root directory for all drive subvolumes.
    /// Typically $XDG_DATA_HOME/nexus/drives/
    drives_root: PathBuf,
}

impl BtrfsBackend {
    pub fn new(drives_root: PathBuf) -> Result<Self, BackendError> {
        // Ensure the drives root directory exists
        std::fs::create_dir_all(&drives_root).map_err(|e| {
            BackendError::Io(format!(
                "cannot create drives directory {}: {e}",
                drives_root.display()
            ))
        })?;

        Ok(BtrfsBackend { drives_root })
    }

    pub fn drives_root(&self) -> &Path {
        &self.drives_root
    }
}

impl DriveBackend for BtrfsBackend {
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
            // Clean up the subvolume on failure (VFS path)
            let _ = remove_subvolume_contents(dest);
            let _ = std::fs::remove_dir(dest);
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

        // If read-only, make writable first (required to remove contents)
        if libbtrfsutil::subvolume_read_only(path).unwrap_or(false) {
            libbtrfsutil::set_subvolume_read_only(path, false).map_err(|e| {
                BackendError::Io(format!(
                    "cannot unset read-only on {}: {e}",
                    path.display()
                ))
            })?;
        }

        // Delete via VFS (rm contents + rmdir) instead of the btrfs ioctl.
        // The BTRFS_IOC_SNAP_DESTROY ioctl always requires CAP_SYS_ADMIN,
        // but rmdir(2) on an empty subvolume works unprivileged since kernel 4.18.
        // This is the same approach used by containers/storage (Docker/Podman).
        remove_subvolume_contents(path).map_err(|e| {
            BackendError::Io(format!(
                "cannot remove contents of subvolume {}: {e}",
                path.display()
            ))
        })?;

        std::fs::remove_dir(path).map_err(|e| {
            BackendError::Io(format!(
                "cannot rmdir subvolume {}: {e}",
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

    fn resize_drive(&self, subvolume_path: &Path, size_bytes: u64) -> Result<(), BackendError> {
        let ext4_path = subvolume_path.join("rootfs.ext4");

        if !ext4_path.exists() {
            return Err(BackendError::NotFound(format!(
                "rootfs.ext4 not found in {}",
                subvolume_path.display()
            )));
        }

        // Check current size
        let current_size = std::fs::metadata(&ext4_path)
            .map_err(|e| BackendError::Io(format!(
                "cannot stat {}: {e}", ext4_path.display()
            )))?
            .len();

        if size_bytes < current_size {
            return Err(BackendError::Unsupported(format!(
                "requested size {} bytes is smaller than current image size {} bytes (shrinking not supported)",
                size_bytes, current_size
            )));
        }

        if size_bytes == current_size {
            return Ok(());  // No resize needed
        }

        // Step 1: Extend the file with truncate
        let output = std::process::Command::new("truncate")
            .arg("-s")
            .arg(size_bytes.to_string())
            .arg(&ext4_path)
            .output()
            .map_err(|e| BackendError::Io(format!("cannot run truncate: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BackendError::Io(format!("truncate failed: {stderr}")));
        }

        // Step 2: Check and repair filesystem before resize
        let output = std::process::Command::new("e2fsck")
            .arg("-fy")
            .arg(&ext4_path)
            .output()
            .map_err(|e| BackendError::Io(format!("cannot run e2fsck: {e}")))?;

        // e2fsck exit codes are bitmasks: bit 0 = errors corrected (OK),
        // bit 1 = reboot needed (irrelevant for offline images), bit 2 = uncorrected errors.
        // Reject only if bit 2 (uncorrected errors) or higher bits are set.
        let code = output.status.code().unwrap_or(-1);
        if code < 0 || code & 0xFC != 0 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BackendError::Io(format!(
                "e2fsck failed (exit {}): {}", code, stderr
            )));
        }

        // Step 3: Resize the filesystem to fill the file
        let output = std::process::Command::new("resize2fs")
            .arg(&ext4_path)
            .output()
            .map_err(|e| BackendError::Io(format!("cannot run resize2fs: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BackendError::Io(format!("resize2fs failed: {stderr}")));
        }

        Ok(())
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

/// Remove all contents inside a subvolume without removing the subvolume directory itself.
/// After this, the subvolume is empty and can be deleted with `std::fs::remove_dir`.
fn remove_subvolume_contents(path: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            std::fs::remove_dir_all(&p)?;
        } else {
            std::fs::remove_file(&p)?;
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
