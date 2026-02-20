use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Image metadata from /etc/nexus/image.yaml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMetadata {
    pub image_id: String,      // base32 ID (13 chars, a-z, 2-7)
    pub image_name: String,
    pub build_id: String,       // base32 ID (13 chars, a-z, 2-7)
    pub built_at: i64,
}

impl ImageMetadata {
    /// Parse image metadata from /etc/nexus/image.yaml
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read {}", path.as_ref().display()))?;

        serde_yml::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.as_ref().display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_valid_image_yaml() {
        let yaml = r#"
image_id: "abcd3fg4ijklm"
image_name: "base-alpine"
build_id: "n2pqr5tu7wxyz"
built_at: 1708387200
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let metadata = ImageMetadata::load(file.path()).unwrap();
        assert_eq!(metadata.image_id, "abcd3fg4ijklm");
        assert_eq!(metadata.image_name, "base-alpine");
        assert_eq!(metadata.build_id, "n2pqr5tu7wxyz");
        assert_eq!(metadata.built_at, 1708387200);
    }

    #[test]
    fn parse_missing_field() {
        let yaml = r#"
image_id: "abcd3fg4ijklm"
image_name: "base-alpine"
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let result = ImageMetadata::load(file.path());
        assert!(result.is_err());
    }
}
