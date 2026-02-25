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

/// Parse a human-readable size string into bytes.
///
/// Accepts: plain bytes ("67108864"), megabytes ("256M", "256MB"),
/// gigabytes ("1G", "1GB"). Case-insensitive.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("size cannot be empty".to_string());
    }

    // Find where digits end and suffix begins
    let digit_end = s
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(s.len());

    let (num_str, suffix) = s.split_at(digit_end);
    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid size number: '{num_str}'"))?;

    if num == 0 {
        return Err("size must be greater than zero".to_string());
    }

    let multiplier: u64 = match suffix.to_uppercase().as_str() {
        "" => 1,
        "M" | "MB" => 1024 * 1024,
        "G" | "GB" => 1024 * 1024 * 1024,
        other => return Err(format!("unknown size suffix: '{other}' (use M, MB, G, or GB)")),
    };

    num.checked_mul(multiplier)
        .ok_or_else(|| format!("size overflow: {num}{suffix}"))
}

/// Parameters for creating a drive from a master image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDriveParams {
    /// Drive name (optional, auto-generated if omitted)
    pub name: Option<String>,
    /// Name of the master image to snapshot from
    pub base: String,
    /// Desired drive size in bytes (optional, defaults to master image size).
    /// Must be >= the master image's ext4 file size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
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

    #[test]
    fn parse_size_megabytes() {
        assert_eq!(parse_size("256M").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_size("256m").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_size("64MB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("64mb").unwrap(), 64 * 1024 * 1024);
    }

    #[test]
    fn parse_size_gigabytes() {
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("2g").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_plain_bytes() {
        assert_eq!(parse_size("67108864").unwrap(), 67108864);
    }

    #[test]
    fn parse_size_invalid() {
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("-100M").is_err());
        assert!(parse_size("0M").is_err());
    }

    #[test]
    fn create_drive_params_with_size() {
        let json = r#"{"base": "base-agent", "size": 268435456}"#;
        let params: CreateDriveParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.size, Some(268435456));
    }

    #[test]
    fn create_drive_params_without_size() {
        let json = r#"{"base": "base-agent"}"#;
        let params: CreateDriveParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.size, None);
    }
}
