// SPDX-License-Identifier: GPL-2.0-only
use crate::backend::traits::{BackendError, WorkspaceBackend};
use crate::store::traits::{StateStore, StoreError};
use crate::workspace::{ImportImageParams, MasterImage, Workspace};
use std::path::PathBuf;
use uuid::Uuid;

/// Errors from workspace service operations.
#[derive(Debug)]
pub enum WorkspaceServiceError {
    Store(StoreError),
    Backend(BackendError),
    /// A referenced entity (e.g., master image) was not found.
    NotFound(String),
}

impl std::fmt::Display for WorkspaceServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceServiceError::Store(e) => write!(f, "{e}"),
            WorkspaceServiceError::Backend(e) => write!(f, "{e}"),
            WorkspaceServiceError::NotFound(e) => write!(f, "not found: {e}"),
        }
    }
}

impl std::error::Error for WorkspaceServiceError {}

impl From<StoreError> for WorkspaceServiceError {
    fn from(e: StoreError) -> Self {
        WorkspaceServiceError::Store(e)
    }
}

impl From<BackendError> for WorkspaceServiceError {
    fn from(e: BackendError) -> Self {
        WorkspaceServiceError::Backend(e)
    }
}

/// Orchestrates workspace operations between the filesystem backend and the database.
pub struct WorkspaceService<'a> {
    store: &'a dyn StateStore,
    backend: &'a dyn WorkspaceBackend,
    workspaces_root: PathBuf,
}

impl<'a> WorkspaceService<'a> {
    pub fn new(
        store: &'a dyn StateStore,
        backend: &'a dyn WorkspaceBackend,
        workspaces_root: PathBuf,
    ) -> Self {
        WorkspaceService {
            store,
            backend,
            workspaces_root,
        }
    }

    /// Import a directory as a master image.
    ///
    /// 1. Creates a btrfs subvolume from the source directory
    /// 2. Marks it read-only
    /// 3. Registers in the database
    pub fn import_image(&self, params: &ImportImageParams) -> Result<MasterImage, WorkspaceServiceError> {
        let source = PathBuf::from(&params.source_path);
        let dest = self.workspaces_root.join(format!("@{}", params.name));

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

    /// Create a workspace by snapshotting a master image.
    ///
    /// 1. Looks up the master image by name
    /// 2. Creates a btrfs snapshot
    /// 3. Registers in the database
    pub fn create_workspace(
        &self,
        base_name: &str,
        ws_name: Option<&str>,
    ) -> Result<Workspace, WorkspaceServiceError> {
        // Look up the master image
        let image = self.store.get_image(base_name)?
            .ok_or_else(|| WorkspaceServiceError::NotFound(
                format!("master image '{}' not found", base_name)
            ))?;

        let source = PathBuf::from(&image.subvolume_path);
        let snap_name = match ws_name {
            Some(name) => name.to_string(),
            None => format!("{}-{}", base_name, &Uuid::new_v4().to_string()[..8]),
        };
        let dest = self.workspaces_root.join(format!("@{}", snap_name));

        // Create the snapshot on disk
        self.backend.create_snapshot(&source, &dest)?;

        // Register in database; roll back snapshot on failure
        let workspace = match self.store.create_workspace(
            ws_name,
            &dest.to_string_lossy(),
            &image.id,
        ) {
            Ok(ws) => ws,
            Err(e) => {
                let _ = self.backend.delete_subvolume(&dest);
                return Err(e.into());
            }
        };

        Ok(workspace)
    }

    /// Delete a workspace: delete the subvolume first, then remove from DB.
    /// Filesystem-first ordering ensures no orphaned subvolumes if the DB
    /// delete were to succeed but the filesystem delete fails.
    pub fn delete_workspace(&self, name_or_id: &str) -> Result<bool, WorkspaceServiceError> {
        let ws = match self.store.get_workspace(name_or_id)? {
            Some(ws) => ws,
            None => return Ok(false),
        };

        // Delete from filesystem first
        let path = PathBuf::from(&ws.subvolume_path);
        if path.exists() {
            self.backend.delete_subvolume(&path)?;
        }

        // Then remove the DB record
        self.store.delete_workspace(&ws.id)?;

        Ok(true)
    }

    /// Delete a master image: ensure no workspaces reference it, then remove.
    /// Filesystem-first ordering ensures no orphaned subvolumes.
    pub fn delete_image(&self, name_or_id: &str) -> Result<bool, WorkspaceServiceError> {
        let image = match self.store.get_image(name_or_id)? {
            Some(img) => img,
            None => return Ok(false),
        };

        // Delete from filesystem first
        let path = PathBuf::from(&image.subvolume_path);
        if path.exists() {
            self.backend.delete_subvolume(&path)?;
        }

        // Then remove the DB record (validates constraints like workspace references)
        self.store.delete_image(&image.id)?;

        Ok(true)
    }

    /// List all master images (delegates to store).
    pub fn list_images(&self) -> Result<Vec<MasterImage>, WorkspaceServiceError> {
        Ok(self.store.list_images()?)
    }

    /// Get a master image by name or ID (delegates to store).
    pub fn get_image(&self, name_or_id: &str) -> Result<Option<MasterImage>, WorkspaceServiceError> {
        Ok(self.store.get_image(name_or_id)?)
    }

    /// List all workspaces, optionally filtered (delegates to store).
    pub fn list_workspaces(&self, base: Option<&str>) -> Result<Vec<Workspace>, WorkspaceServiceError> {
        Ok(self.store.list_workspaces(base)?)
    }

    /// Get a workspace by name or ID (delegates to store).
    pub fn get_workspace(&self, name_or_id: &str) -> Result<Option<Workspace>, WorkspaceServiceError> {
        Ok(self.store.get_workspace(name_or_id)?)
    }
}
