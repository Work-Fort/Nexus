use serde::{Deserialize, Serialize};

/// A master image: a read-only btrfs subvolume registered in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterImage {
    pub id: String,
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

/// A workspace: a btrfs subvolume snapshot, optionally attached to a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub name: Option<String>,
    pub vm_id: Option<String>,
    pub subvolume_path: String,
    pub master_image_id: Option<String>,
    pub parent_workspace_id: Option<String>,
    pub size_bytes: Option<i64>,
    pub is_root_device: bool,
    pub is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detached_at: Option<i64>,
    pub created_at: i64,
}

/// Parameters for creating a workspace from a master image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWorkspaceParams {
    /// Workspace name (optional, auto-generated if omitted)
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
            id: "img-1".to_string(),
            name: "base-agent".to_string(),
            subvolume_path: "/data/workspaces/@base-agent".to_string(),
            size_bytes: Some(1024 * 1024),
            created_at: 1000,
        };
        let json = serde_json::to_string(&img).unwrap();
        assert!(json.contains("base-agent"));
        assert!(json.contains("1048576"));
    }

    #[test]
    fn workspace_serializes_without_none_fields() {
        let ws = Workspace {
            id: "ws-1".to_string(),
            name: Some("my-ws".to_string()),
            vm_id: None,
            subvolume_path: "/data/workspaces/@my-ws".to_string(),
            master_image_id: Some("img-1".to_string()),
            parent_workspace_id: None,
            size_bytes: None,
            is_root_device: false,
            is_read_only: false,
            attached_at: None,
            detached_at: None,
            created_at: 2000,
        };
        let json = serde_json::to_string(&ws).unwrap();
        assert!(json.contains("my-ws"));
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
    fn create_workspace_params_deserializes_with_name() {
        let json = r#"{"name": "my-ws", "base": "base-agent"}"#;
        let params: CreateWorkspaceParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, Some("my-ws".to_string()));
        assert_eq!(params.base, "base-agent");
    }

    #[test]
    fn create_workspace_params_deserializes_without_name() {
        let json = r#"{"base": "base-agent"}"#;
        let params: CreateWorkspaceParams = serde_json::from_str(json).unwrap();
        assert!(params.name.is_none());
        assert_eq!(params.base, "base-agent");
    }
}
