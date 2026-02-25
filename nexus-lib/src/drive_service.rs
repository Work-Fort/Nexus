// SPDX-License-Identifier: GPL-2.0-only
use crate::backend::traits::{BackendError, DriveBackend};
use crate::store::traits::{StateStore, StoreError};
use crate::drive::{Drive, ImportImageParams, MasterImage};
use std::path::PathBuf;
use uuid::Uuid;

/// Errors from drive service operations.
#[derive(Debug)]
pub enum DriveServiceError {
    Store(StoreError),
    Backend(BackendError),
    /// A referenced entity (e.g., master image) was not found.
    NotFound(String),
}

impl std::fmt::Display for DriveServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriveServiceError::Store(e) => write!(f, "{e}"),
            DriveServiceError::Backend(e) => write!(f, "{e}"),
            DriveServiceError::NotFound(e) => write!(f, "not found: {e}"),
        }
    }
}

impl std::error::Error for DriveServiceError {}

impl From<StoreError> for DriveServiceError {
    fn from(e: StoreError) -> Self {
        DriveServiceError::Store(e)
    }
}

impl From<BackendError> for DriveServiceError {
    fn from(e: BackendError) -> Self {
        DriveServiceError::Backend(e)
    }
}

/// Orchestrates drive operations between the filesystem backend and the database.
pub struct DriveService<'a> {
    store: &'a dyn StateStore,
    backend: &'a dyn DriveBackend,
    drives_root: PathBuf,
}

impl<'a> DriveService<'a> {
    pub fn new(
        store: &'a dyn StateStore,
        backend: &'a dyn DriveBackend,
        drives_root: PathBuf,
    ) -> Self {
        DriveService {
            store,
            backend,
            drives_root,
        }
    }

    /// Import a directory as a master image.
    ///
    /// 1. Creates a btrfs subvolume from the source directory
    /// 2. Marks it read-only
    /// 3. Registers in the database
    pub fn import_image(&self, params: &ImportImageParams) -> Result<MasterImage, DriveServiceError> {
        let source = PathBuf::from(&params.source_path);
        let dest = self.drives_root.join(format!("@{}", params.name));

        // Create the subvolume on disk (copies source, marks read-only)
        self.backend.import_image(&source, &dest)?;

        // Register in database; roll back subvolume on failure
        let image = match self.store.create_image(params, &dest.to_string_lossy()) {
            Ok(img) => img,
            Err(e) => {
                let _ = self.backend.delete_subvolume(&dest);
                return Err(e.into());
            }
        };

        Ok(image)
    }

    /// Create a drive by snapshotting a master image.
    ///
    /// 1. Looks up the master image by name
    /// 2. Creates a btrfs snapshot
    /// 3. If size is specified, resizes the ext4 image inside the snapshot
    /// 4. Registers in the database
    pub fn create_drive(
        &self,
        base_name: &str,
        drive_name: Option<&str>,
        size: Option<u64>,
    ) -> Result<Drive, DriveServiceError> {
        // Look up the master image
        let image = self.store.get_image(base_name)?
            .ok_or_else(|| DriveServiceError::NotFound(
                format!("master image '{}' not found", base_name)
            ))?;

        let source = PathBuf::from(&image.subvolume_path);
        let snap_name = match drive_name {
            Some(name) => name.to_string(),
            None => format!("{}-{}", base_name, &Uuid::new_v4().to_string()[..8]),
        };
        let dest = self.drives_root.join(format!("@{}", snap_name));

        // Create the snapshot on disk
        self.backend.create_snapshot(&source, &dest)?;

        // Resize if requested
        if let Some(requested_size) = size {
            if let Err(e) = self.backend.resize_drive(&dest, requested_size) {
                // Roll back the snapshot on resize failure
                let _ = self.backend.delete_subvolume(&dest);
                return Err(e.into());
            }
        }

        // Register in database; roll back snapshot on failure
        let drive = match self.store.create_drive(
            drive_name,
            &dest.to_string_lossy(),
            image.id,
        ) {
            Ok(d) => d,
            Err(e) => {
                let _ = self.backend.delete_subvolume(&dest);
                return Err(e.into());
            }
        };

        Ok(drive)
    }

    /// Delete a drive: delete the subvolume first, then remove from DB.
    /// Filesystem-first ordering ensures no orphaned subvolumes if the DB
    /// delete were to succeed but the filesystem delete fails.
    pub fn delete_drive(&self, name_or_id: &str) -> Result<bool, DriveServiceError> {
        let drive = match self.store.get_drive(name_or_id)? {
            Some(d) => d,
            None => return Ok(false),
        };

        // Delete from filesystem first
        let path = PathBuf::from(&drive.subvolume_path);
        if path.exists() {
            self.backend.delete_subvolume(&path)?;
        }

        // Then remove the DB record
        self.store.delete_drive(drive.id)?;

        Ok(true)
    }

    /// Delete a master image: ensure no drives reference it, then remove.
    /// Filesystem-first ordering ensures no orphaned subvolumes.
    pub fn delete_image(&self, name_or_id: &str) -> Result<bool, DriveServiceError> {
        let image = match self.store.get_image(name_or_id)? {
            Some(img) => img,
            None => return Ok(false),
        };

        // Delete from filesystem first
        let path = PathBuf::from(&image.subvolume_path);
        if path.exists() {
            self.backend.delete_subvolume(&path)?;
        }

        // Then remove the DB record (validates constraints like drive references)
        self.store.delete_image(image.id)?;

        Ok(true)
    }

    /// List all master images (delegates to store).
    pub fn list_images(&self) -> Result<Vec<MasterImage>, DriveServiceError> {
        Ok(self.store.list_images()?)
    }

    /// Get a master image by name or ID (delegates to store).
    pub fn get_image(&self, name_or_id: &str) -> Result<Option<MasterImage>, DriveServiceError> {
        Ok(self.store.get_image(name_or_id)?)
    }

    /// List all drives, optionally filtered (delegates to store).
    pub fn list_drives(&self, base: Option<&str>) -> Result<Vec<Drive>, DriveServiceError> {
        Ok(self.store.list_drives(base)?)
    }

    /// Get a drive by name or ID (delegates to store).
    pub fn get_drive(&self, name_or_id: &str) -> Result<Option<Drive>, DriveServiceError> {
        Ok(self.store.get_drive(name_or_id)?)
    }
}
