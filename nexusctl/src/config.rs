use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CtlConfig {
    /// Daemon address in host:port format
    pub daemon: String,
}

impl Default for CtlConfig {
    fn default() -> Self {
        CtlConfig {
            daemon: "127.0.0.1:9600".to_string(),
        }
    }
}

/// Returns the default config file path: $XDG_CONFIG_HOME/nexusctl/config.yaml
pub fn default_config_path() -> PathBuf {
    let config_dir = dirs::config_dir()
        .expect("cannot determine XDG_CONFIG_HOME")
        .join("nexusctl");
    config_dir.join("config.yaml")
}

/// Load config from the given path. Returns defaults if the file does not exist.
pub fn load(path: impl AsRef<Path>) -> CtlConfig {
    let path = path.as_ref();
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_norway::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "Warning: failed to parse config {}: {e}, using defaults",
                    path.display()
                );
                CtlConfig::default()
            }
        },
        Err(_) => CtlConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_correct_daemon_addr() {
        let cfg = CtlConfig::default();
        assert_eq!(cfg.daemon, "127.0.0.1:9600");
    }

    #[test]
    fn deserialize_config_with_daemon() {
        let yaml = r#"
daemon: "10.0.0.1:8080"
"#;
        let cfg: CtlConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(cfg.daemon, "10.0.0.1:8080");
    }

    #[test]
    fn load_nonexistent_returns_default() {
        let cfg = load("/nonexistent/path/config.yaml");
        assert_eq!(cfg.daemon, "127.0.0.1:9600");
    }
}
