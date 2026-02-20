// SPDX-License-Identifier: GPL-2.0-only
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A template: a blueprint for building rootfs images.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub version: i64,
    pub source_type: String,
    pub source_identifier: String,
    /// File overlays: maps filesystem paths to file contents.
    /// e.g., {"/etc/inittab": "::sysinit:...", "/etc/fstab": "..."}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlays: Option<HashMap<String, String>>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Parameters for creating a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTemplateParams {
    pub name: String,
    pub source_type: String,
    pub source_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlays: Option<HashMap<String, String>>,
}

/// Build status values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildStatus {
    Building,
    Success,
    Failed,
}

impl std::fmt::Display for BuildStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildStatus::Building => write!(f, "building"),
            BuildStatus::Success => write!(f, "success"),
            BuildStatus::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for BuildStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "building" => Ok(BuildStatus::Building),
            "success" => Ok(BuildStatus::Success),
            "failed" => Ok(BuildStatus::Failed),
            other => Err(format!("invalid build status: '{other}'")),
        }
    }
}

/// A build: an immutable snapshot of a template at build time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Build {
    pub id: String,
    pub template_id: String,
    pub template_version: i64,
    pub name: String,
    pub source_type: String,
    pub source_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlays: Option<HashMap<String, String>>,
    pub status: BuildStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_image_id: Option<String>,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_serializes() {
        let tpl = Template {
            id: "tpl-1".to_string(),
            name: "base-agent".to_string(),
            version: 1,
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
            created_at: 1000,
            updated_at: 1000,
        };
        let json = serde_json::to_string(&tpl).unwrap();
        assert!(json.contains("base-agent"));
        assert!(!json.contains("overlays")); // None fields skipped
    }

    #[test]
    fn template_with_overlays_serializes() {
        let mut overlays = HashMap::new();
        overlays.insert("/etc/hostname".to_string(), "nexus-vm".to_string());
        let tpl = Template {
            id: "tpl-2".to_string(),
            name: "with-overlays".to_string(),
            version: 1,
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: Some(overlays),
            created_at: 1000,
            updated_at: 1000,
        };
        let json = serde_json::to_string(&tpl).unwrap();
        assert!(json.contains("overlays"));
        assert!(json.contains("nexus-vm"));
    }

    #[test]
    fn create_template_params_deserializes() {
        let json = r#"{"name": "base", "source_type": "rootfs", "source_identifier": "https://example.com/rootfs.tar.gz"}"#;
        let params: CreateTemplateParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "base");
        assert_eq!(params.source_type, "rootfs");
        assert!(params.overlays.is_none());
    }

    #[test]
    fn create_template_params_with_overlays_deserializes() {
        let json = r#"{"name": "base", "source_type": "rootfs", "source_identifier": "https://example.com/rootfs.tar.gz", "overlays": {"/etc/hostname": "nexus-vm"}}"#;
        let params: CreateTemplateParams = serde_json::from_str(json).unwrap();
        assert!(params.overlays.is_some());
        assert_eq!(params.overlays.unwrap().get("/etc/hostname").unwrap(), "nexus-vm");
    }

    #[test]
    fn build_serializes() {
        let build = Build {
            id: "bld-1".to_string(),
            template_id: "tpl-1".to_string(),
            template_version: 1,
            name: "base-agent".to_string(),
            source_type: "rootfs".to_string(),
            source_identifier: "https://example.com/rootfs.tar.gz".to_string(),
            overlays: None,
            status: BuildStatus::Building,
            build_log_path: None,
            master_image_id: None,
            created_at: 1000,
            completed_at: None,
        };
        let json = serde_json::to_string(&build).unwrap();
        assert!(json.contains("building"));
        assert!(!json.contains("master_image_id")); // None fields skipped
    }

    #[test]
    fn build_status_display() {
        assert_eq!(BuildStatus::Building.to_string(), "building");
        assert_eq!(BuildStatus::Success.to_string(), "success");
        assert_eq!(BuildStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn build_status_from_str() {
        assert_eq!("building".parse::<BuildStatus>().unwrap(), BuildStatus::Building);
        assert_eq!("success".parse::<BuildStatus>().unwrap(), BuildStatus::Success);
        assert_eq!("failed".parse::<BuildStatus>().unwrap(), BuildStatus::Failed);
        assert!("invalid".parse::<BuildStatus>().is_err());
    }
}
