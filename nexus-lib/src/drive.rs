// SPDX-License-Identifier: GPL-2.0-only
use crate::id::Id;
use serde::{Deserialize, Serialize};

/// A master image: a read-only btrfs subvolume registered in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterImage {
    pub id: Id,
    pub name: String,
    pub subvolume_path: String,
    pub size_bytes: Option<i64>,
    pub created_at: i64,
}

/// Parameters for importing a master image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportImageParams {
    /// Human-readable name for the image
    pub name: String,
    /// Path to the directory to import as a btrfs subvolume
    pub source_path: String,
}

/// A drive: a btrfs subvolume snapshot, optionally attached to a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub id: Id,
    pub name: Option<String>,
    pub vm_id: Option<Id>,
    pub subvolume_path: String,
    pub master_image_id: Option<Id>,
    pub parent_drive_id: Option<Id>,
    pub size_bytes: Option<i64>,
    pub is_root_device: bool,
    pub is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detached_at: Option<i64>,
    pub created_at: i64,
}

impl CreateDriveParams {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref name) = self.name {
            if Id::is_valid_base32(name) {
                return Err(format!(
                    "Drive name '{}' cannot be a valid base32 ID (reserved for resource IDs)",
                    name
                ));
            }
        }
        Ok(())
    }
}

impl ImportImageParams {
    pub fn validate(&self) -> Result<(), String> {
        if Id::is_valid_base32(&self.name) {
            return Err(format!(
                "Image name '{}' cannot be a valid base32 ID (reserved for resource IDs)",
                self.name
            ));
        }
        Ok(())
    }
}

/// Parameters for creating a drive from a master image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDriveParams {
    /// Drive name (optional, auto-generated if omitted)
    pub name: Option<String>,
    /// Name of the master image to snapshot from
    pub base: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_image_serializes() {
        let img = MasterImage {
            id: Id::from_i64(1),
            name: "base-agent".to_string(),
            subvolume_path: "/data/drives/@base-agent".to_string(),
            size_bytes: Some(1024 * 1024),
            created_at: 1000,
        };
        let json = serde_json::to_string(&img).unwrap();
        assert!(json.contains("base-agent"));
        assert!(json.contains("1048576"));
    }

    #[test]
    fn drive_serializes_without_none_fields() {
        let drive = Drive {
            id: Id::from_i64(1),
            name: Some("my-drive".to_string()),
            vm_id: None,
            subvolume_path: "/data/drives/@my-drive".to_string(),
            master_image_id: Some(Id::from_i64(2)),
            parent_drive_id: None,
            size_bytes: None,
            is_root_device: false,
            is_read_only: false,
            attached_at: None,
            detached_at: None,
            created_at: 2000,
        };
        let json = serde_json::to_string(&drive).unwrap();
        assert!(json.contains("my-drive"));
        assert!(!json.contains("attached_at"));
        assert!(!json.contains("detached_at"));
    }

    #[test]
    fn import_params_deserializes() {
        let json = r#"{"name": "base", "source_path": "/tmp/rootfs"}"#;
        let params: ImportImageParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "base");
        assert_eq!(params.source_path, "/tmp/rootfs");
    }

    #[test]
    fn create_drive_params_deserializes_with_name() {
        let json = r#"{"name": "my-drive", "base": "base-agent"}"#;
        let params: CreateDriveParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, Some("my-drive".to_string()));
        assert_eq!(params.base, "base-agent");
    }

    #[test]
    fn create_drive_params_deserializes_without_name() {
        let json = r#"{"base": "base-agent"}"#;
        let params: CreateDriveParams = serde_json::from_str(json).unwrap();
        assert!(params.name.is_none());
        assert_eq!(params.base, "base-agent");
    }
}
