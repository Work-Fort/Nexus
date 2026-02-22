// SPDX-License-Identifier: GPL-2.0-only
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum ConfigError {
    NotFound(std::io::Error),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::NotFound(e) => write!(f, "config file not found: {e}"),
            ConfigError::Invalid(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, ConfigError::NotFound(_))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FirecrackerConfig {
    pub binary: String,
    pub kernel: String,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .expect("cannot determine XDG_DATA_HOME")
            .join("nexus");
        FirecrackerConfig {
            binary: "/usr/bin/firecracker".to_string(),
            kernel: data_dir.join("images").join("vmlinux").to_string_lossy().to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub api: ApiConfig,
    pub storage: StorageConfig,
    pub firecracker: FirecrackerConfig,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub drives: String,
    pub assets: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .expect("cannot determine XDG_DATA_HOME")
            .join("nexus");
        StorageConfig {
            drives: data_dir.join("drives").to_string_lossy().to_string(),
            assets: data_dir.join("assets").to_string_lossy().to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub listen: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        ApiConfig {
            listen: "127.0.0.1:9600".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub bridge_name: String,
    pub subnet: String,
    pub dns_servers: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            bridge_name: "nexbr0".to_string(),
            subnet: "172.16.0.0/12".to_string(),
            dns_servers: vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
            ],
        }
    }
}

/// Returns the default config file path: $XDG_CONFIG_HOME/nexus/nexus.yaml
pub fn default_config_path() -> PathBuf {
    let config_dir = dirs::config_dir()
        .expect("cannot determine XDG_CONFIG_HOME")
        .join("nexus");
    config_dir.join("nexus.yaml")
}

/// Returns the default drives path: $XDG_DATA_HOME/nexus/drives
pub fn default_drives_path() -> PathBuf {
    let data_dir = dirs::data_dir()
        .expect("cannot determine XDG_DATA_HOME")
        .join("nexus");
    data_dir.join("drives")
}

/// Returns the default database path: $XDG_STATE_HOME/nexus/nexus.db
pub fn default_db_path() -> PathBuf {
    let state_dir = dirs::state_dir()
        .expect("cannot determine XDG_STATE_HOME")
        .join("nexus");
    state_dir.join("nexus.db")
}

/// Returns the default assets directory: $XDG_DATA_HOME/nexus/assets
pub fn default_assets_dir() -> PathBuf {
    let data_dir = dirs::data_dir()
        .expect("cannot determine XDG_DATA_HOME")
        .join("nexus");
    data_dir.join("assets")
}

/// Returns the default runtime path: $XDG_RUNTIME_DIR/nexus
pub fn default_runtime_path() -> PathBuf {
    dirs::runtime_dir()
        .unwrap_or_else(|| {
            // Fallback: /run/user/$UID or /tmp/nexus-runtime-$UID
            let uid = nix::unistd::getuid();
            let run_user = PathBuf::from(format!("/run/user/{}", uid));
            if run_user.exists() {
                run_user
            } else {
                std::env::temp_dir().join(format!("nexus-runtime-{}", uid))
            }
        })
        .join("nexus")
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::NotFound(e)
            } else {
                ConfigError::Invalid(e.to_string())
            }
        })?;
        let config: Config =
            serde_norway::from_str(&content).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_minimal_config() {
        let yaml = r#"
api:
  listen: "127.0.0.1:8080"
"#;
        let config: Config = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.api.listen, "127.0.0.1:8080");
    }

    #[test]
    fn default_config_values() {
        let config = Config::default();
        assert_eq!(config.api.listen, "127.0.0.1:9600");
    }

    #[test]
    fn partial_yaml_uses_defaults() {
        let yaml = "{}";
        let config: Config = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.api.listen, "127.0.0.1:9600");
    }

    #[test]
    fn default_db_path_ends_with_nexus_db() {
        let path = default_db_path();
        assert!(path.ends_with("nexus/nexus.db"), "expected path ending with nexus/nexus.db, got: {}", path.display());
    }

    #[test]
    fn storage_config_defaults() {
        let config = Config::default();
        assert!(config.storage.drives.contains("nexus/drives"));
    }

    #[test]
    fn config_with_storage_section_deserializes() {
        let yaml = r#"
api:
  listen: "127.0.0.1:8080"
storage:
  drives: "/mnt/btrfs/nexus/drives"
"#;
        let config: Config = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.storage.drives, "/mnt/btrfs/nexus/drives");
    }

    #[test]
    fn load_nonexistent_file_returns_not_found() {
        let result = Config::load("/nonexistent/path/config.yaml");
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_found());
    }

    #[test]
    fn load_invalid_yaml_returns_invalid() {
        let dir = std::env::temp_dir();
        let path = dir.join("nexus-test-bad-config.yaml");
        std::fs::write(&path, "{{invalid yaml").unwrap();
        let result = Config::load(&path);
        assert!(result.is_err());
        assert!(!result.unwrap_err().is_not_found());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn firecracker_config_defaults() {
        let config = Config::default();
        assert!(config.firecracker.binary.contains("firecracker"));
        assert!(config.firecracker.kernel.contains("vmlinux"));
    }

    #[test]
    fn default_runtime_path_ends_with_nexus() {
        let path = default_runtime_path();
        assert!(
            path.to_string_lossy().contains("nexus"),
            "expected path containing nexus, got: {}",
            path.display()
        );
    }

    #[test]
    fn config_with_firecracker_section_deserializes() {
        let yaml = r#"
api:
  listen: "127.0.0.1:8080"
firecracker:
  binary: "/usr/local/bin/firecracker"
  kernel: "/opt/kernels/vmlinux"
"#;
        let config: Config = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.firecracker.binary, "/usr/local/bin/firecracker");
        assert_eq!(config.firecracker.kernel, "/opt/kernels/vmlinux");
    }

    #[test]
    fn network_config_defaults_are_correct() {
        let config = NetworkConfig::default();
        assert_eq!(config.bridge_name, "nexbr0");
        assert_eq!(config.subnet, "172.16.0.0/12");
        assert_eq!(config.dns_servers, vec!["8.8.8.8", "1.1.1.1"]);
    }

    #[test]
    fn network_config_loads_from_yaml() {
        let yaml = r#"
api:
  listen: "127.0.0.1:9600"
network:
  bridge_name: "testbr0"
  subnet: "192.168.100.0/24"
  dns_servers:
    - "1.1.1.1"
"#;
        let config: Config = serde_norway::from_str(yaml).unwrap();
        assert_eq!(config.network.bridge_name, "testbr0");
        assert_eq!(config.network.subnet, "192.168.100.0/24");
        assert_eq!(config.network.dns_servers, vec!["1.1.1.1"]);
    }
}
