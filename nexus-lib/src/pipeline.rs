// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/pipeline.rs

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing;

// ---------------------------------------------------------------------------
// Pipeline stage types (stored as JSON in the providers table)
// ---------------------------------------------------------------------------

/// A single stage in a download pipeline.
/// Deserialized from JSON objects like `{"transport": "http", ...}` or `{"checksum": "SHA256"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PipelineStage {
    Transport {
        transport: String,           // "http" or "file"
        #[serde(default)]
        credentials: serde_json::Value, // empty object for now
        #[serde(default)]
        host: String,                // override host, empty = use URL host
        #[serde(default)]
        encrypted: bool,             // require TLS
    },
    Checksum {
        checksum: String,            // "SHA256"
    },
    Verify {
        verify: String,              // "pgp" or "none"
    },
    Decompress {
        decompress: String,          // "xz", "gzip", or "none"
    },
}

/// A set of expected checksums for pipeline verification.
/// Keys are stage-index-qualified identifiers (e.g., "transport" for the streaming
/// checksum during download, "decompressed" for the post-decompression hash).
#[derive(Debug, Clone, Default)]
pub struct ChecksumSet {
    /// Expected SHA256 of the compressed/transported file (verified during streaming).
    pub transport_sha256: Option<String>,
    /// Expected SHA256 of the decompressed file on disk (verified after decompression).
    pub decompressed_sha256: Option<String>,
}

// ---------------------------------------------------------------------------
// Pipeline errors and results
// ---------------------------------------------------------------------------

/// Errors from pipeline operations.
#[derive(Debug)]
pub enum PipelineError {
    /// HTTP request failed.
    Http(String),
    /// File I/O error.
    Io(String),
    /// SHA256 checksum mismatch.
    ChecksumMismatch {
        stage: String,
        expected: String,
        actual: String,
    },
    /// PGP signature verification failed.
    PgpVerification(String),
    /// Decompression error.
    Decompression(String),
    /// Invalid pipeline configuration.
    InvalidPipeline(String),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::Http(e) => write!(f, "download failed: {e}"),
            PipelineError::Io(e) => write!(f, "I/O error: {e}"),
            PipelineError::ChecksumMismatch { stage, expected, actual } => {
                write!(f, "SHA256 mismatch at {stage}: expected {expected}, got {actual}")
            }
            PipelineError::PgpVerification(e) => write!(f, "PGP verification failed: {e}"),
            PipelineError::Decompression(e) => write!(f, "decompression failed: {e}"),
            PipelineError::InvalidPipeline(e) => write!(f, "invalid pipeline: {e}"),
        }
    }
}

impl std::error::Error for PipelineError {}

/// Result of a successful pipeline execution.
#[derive(Debug)]
pub struct PipelineResult {
    /// Path to the final file on disk.
    pub path: PathBuf,
    /// SHA256 hex digest of the file at rest (after all pipeline stages).
    /// For kernels with two checksum stages, this is the decompressed hash.
    pub sha256: String,
    /// Size of the final file in bytes.
    pub size: u64,
    /// Whether PGP verification succeeded.
    pub pgp_verified: bool,
}

/// Executes a sequence of pipeline stages defined in the providers table.
///
/// Replaces the old `Downloader` with a data-driven approach: instead of
/// separate `download()`, `download_xz()`, `copy_local()` methods, the
/// executor walks through a `Vec<PipelineStage>` from the database.
///
/// **Streaming checksum:** The first checksum stage after transport computes
/// SHA256 as bytes stream through (`reqwest::bytes_stream()` + `sha2` hasher
/// updating per chunk), NOT download-then-hash.
///
/// **Two checksum stages for anvil kernels:** The first checksum verifies
/// the compressed download (streaming). The second checksum (after decompress)
/// verifies the decompressed file on disk. The second hash is what goes in
/// the `kernels.sha256` DB column -- the at-rest hash for later re-verification.
pub struct PipelineExecutor {
    client: reqwest::Client,
}

impl Default for PipelineExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineExecutor {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("nexus-asset-downloader")
            .build()
            .expect("failed to build HTTP client");
        PipelineExecutor { client }
    }

    /// Execute a pipeline: transport -> checksum -> verify -> decompress -> checksum.
    ///
    /// The `url` is the download source. The `dest` is the final file path.
    /// `stages` come from the provider's pipeline JSON. `checksums` contains
    /// the expected hashes for each checksum stage.
    /// `pgp_data` optionally provides (public_key, signature, signed_data) for PGP verification.
    pub async fn execute(
        &self,
        url: &str,
        dest: &Path,
        stages: &[PipelineStage],
        checksums: &ChecksumSet,
        pgp_data: Option<(&str, &str, &[u8])>,
    ) -> Result<PipelineResult, PipelineError> {
        // Ensure parent directory exists
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PipelineError::Io(format!("cannot create directory {}: {e}", parent.display())))?;
        }

        let temp_path = dest.with_extension("download");
        let mut transport_sha256: Option<String> = None;
        let mut pgp_verified = false;
        let mut checksum_stage_count = 0;

        for stage in stages {
            match stage {
                PipelineStage::Transport { transport, encrypted, .. } => {
                    if *encrypted && url.starts_with("http://") {
                        return Err(PipelineError::InvalidPipeline(
                            "pipeline requires encryption but URL is HTTP".to_string()
                        ));
                    }

                    match transport.as_str() {
                        "http" => {
                            tracing::info!(url = %url, dest = %dest.display(), "downloading asset (streaming)");

                            let response = self.client.get(url).send().await
                                .map_err(|e| PipelineError::Http(e.to_string()))?;

                            if !response.status().is_success() {
                                return Err(PipelineError::Http(
                                    format!("HTTP {} from {}", response.status(), url)
                                ));
                            }

                            // Stream bytes to disk while computing SHA256
                            let mut hasher = Sha256::new();
                            let mut file = std::fs::File::create(&temp_path)
                                .map_err(|e| PipelineError::Io(format!("cannot create temp file: {e}")))?;
                            let mut stream = response.bytes_stream();

                            while let Some(chunk) = stream.next().await {
                                let chunk = chunk.map_err(|e| PipelineError::Http(format!("stream error: {e}")))?;
                                hasher.update(&chunk);
                                std::io::Write::write_all(&mut file, &chunk)
                                    .map_err(|e| PipelineError::Io(format!("write error: {e}")))?;
                            }

                            transport_sha256 = Some(format!("{:x}", hasher.finalize()));
                        }
                        "file" => {
                            let src = Path::new(url);
                            if !src.exists() {
                                return Err(PipelineError::Io(format!("source file not found: {}", src.display())));
                            }
                            tracing::info!(src = %src.display(), dest = %dest.display(), "copying local asset");
                            std::fs::copy(src, &temp_path)
                                .map_err(|e| PipelineError::Io(format!("copy error: {e}")))?;
                            transport_sha256 = Some(compute_sha256_file(&temp_path)?);
                        }
                        other => return Err(PipelineError::InvalidPipeline(format!("unknown transport: {other}"))),
                    }
                }

                PipelineStage::Checksum { checksum } => {
                    if checksum != "SHA256" {
                        return Err(PipelineError::InvalidPipeline(format!("unsupported checksum: {checksum}")));
                    }
                    checksum_stage_count += 1;

                    if checksum_stage_count == 1 {
                        // First checksum: verify the transported (possibly compressed) file.
                        // SHA256 was computed during streaming transport.
                        let actual = transport_sha256.as_ref()
                            .ok_or_else(|| PipelineError::InvalidPipeline("checksum stage before transport".to_string()))?;
                        if let Some(expected) = &checksums.transport_sha256 {
                            if actual != expected {
                                let _ = std::fs::remove_file(&temp_path);
                                return Err(PipelineError::ChecksumMismatch {
                                    stage: "transport".to_string(),
                                    expected: expected.clone(),
                                    actual: actual.clone(),
                                });
                            }
                            tracing::info!("transport SHA256 verified: {actual}");
                        }
                    } else {
                        // Second checksum: verify the decompressed file on disk.
                        let actual = compute_sha256_file(&temp_path)?;
                        if let Some(expected) = &checksums.decompressed_sha256 {
                            if actual != *expected {
                                let _ = std::fs::remove_file(&temp_path);
                                return Err(PipelineError::ChecksumMismatch {
                                    stage: "decompressed".to_string(),
                                    expected: expected.clone(),
                                    actual,
                                });
                            }
                            tracing::info!("decompressed SHA256 verified: {actual}");
                        }
                    }
                }

                PipelineStage::Verify { verify } => {
                    match verify.as_str() {
                        "pgp" => {
                            if let Some((key, sig, data)) = pgp_data {
                                crate::pgp::verify_detached_signature(key, sig, data)
                                    .map_err(|e| PipelineError::PgpVerification(e.to_string()))?;
                                pgp_verified = true;
                                tracing::info!("PGP signature verified");
                            } else {
                                tracing::warn!("PGP verification requested but no key/signature data provided, skipping");
                            }
                        }
                        "none" => {}
                        other => return Err(PipelineError::InvalidPipeline(format!("unknown verify method: {other}"))),
                    }
                }

                PipelineStage::Decompress { decompress } => {
                    match decompress.as_str() {
                        "xz" => {
                            let compressed = std::fs::read(&temp_path)
                                .map_err(|e| PipelineError::Io(format!("cannot read compressed file: {e}")))?;
                            let mut decompressor = xz2::read::XzDecoder::new(&compressed[..]);
                            let mut decompressed = Vec::new();
                            std::io::Read::read_to_end(&mut decompressor, &mut decompressed)
                                .map_err(|e| PipelineError::Decompression(format!("xz decompression failed: {e}")))?;
                            std::fs::write(&temp_path, &decompressed)
                                .map_err(|e| PipelineError::Io(format!("cannot write decompressed file: {e}")))?;
                            tracing::info!("xz decompressed: {} -> {} bytes", compressed.len(), decompressed.len());
                        }
                        "gzip" => {
                            let file = std::fs::File::open(&temp_path)
                                .map_err(|e| PipelineError::Io(format!("cannot open for gzip: {e}")))?;
                            let mut decoder = flate2::read::GzDecoder::new(file);
                            let mut decompressed = Vec::new();
                            std::io::Read::read_to_end(&mut decoder, &mut decompressed)
                                .map_err(|e| PipelineError::Decompression(format!("gzip decompression failed: {e}")))?;
                            std::fs::write(&temp_path, &decompressed)
                                .map_err(|e| PipelineError::Io(format!("cannot write decompressed file: {e}")))?;
                        }
                        "none" => {}
                        other => return Err(PipelineError::InvalidPipeline(format!("unknown decompress: {other}"))),
                    }
                }
            }
        }

        // Compute final SHA256 and size
        let final_sha256 = compute_sha256_file(&temp_path)?;
        let size = std::fs::metadata(&temp_path)
            .map_err(|e| PipelineError::Io(e.to_string()))?.len();

        // Atomic move to final destination
        std::fs::rename(&temp_path, dest)
            .map_err(|e| PipelineError::Io(format!("cannot rename to {}: {e}", dest.display())))?;

        Ok(PipelineResult {
            path: dest.to_path_buf(),
            sha256: final_sha256,
            size,
            pgp_verified,
        })
    }

    /// Access the underlying HTTP client (for GitHub API calls, checksums fetching, etc.).
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

/// Compute SHA256 hex digest of a file.
pub fn compute_sha256_file(path: &Path) -> Result<String, PipelineError> {
    let data = std::fs::read(path)
        .map_err(|e| PipelineError::Io(format!("cannot read {}: {e}", path.display())))?;
    Ok(compute_sha256_bytes(&data))
}

/// Compute SHA256 hex digest of a byte slice.
pub fn compute_sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Parse a SHA256SUMS file and find the checksum for a given filename.
/// Format: `<sha256>  <filename>` (two spaces between hash and name).
pub fn find_sha256_in_sums(sums_content: &str, filename: &str) -> Option<String> {
    for line in sums_content.lines() {
        let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
        if parts.len() == 2 {
            let hash = parts[0].trim();
            let name = parts[1].trim().trim_start_matches('*');
            if name == filename {
                return Some(hash.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_sha256_bytes_produces_hex() {
        let hash = compute_sha256_bytes(b"hello world");
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn compute_sha256_file_works() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.txt");
        std::fs::write(&path, b"hello world").unwrap();
        let hash = compute_sha256_file(&path).unwrap();
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn find_sha256_in_sums_finds_match() {
        let sums = "abc123  vmlinux-6.18.9-x86_64.xz\ndef456  vmlinux-6.18.9-aarch64.xz\n";
        assert_eq!(
            find_sha256_in_sums(sums, "vmlinux-6.18.9-x86_64.xz"),
            Some("abc123".to_string())
        );
        assert_eq!(
            find_sha256_in_sums(sums, "vmlinux-6.18.9-aarch64.xz"),
            Some("def456".to_string())
        );
    }

    #[test]
    fn find_sha256_in_sums_returns_none_for_missing() {
        let sums = "abc123  vmlinux-6.18.9-x86_64.xz\n";
        assert_eq!(find_sha256_in_sums(sums, "nonexistent"), None);
    }

    #[test]
    fn find_sha256_in_sums_handles_star_prefix() {
        let sums = "abc123 *binary.xz\n";
        assert_eq!(
            find_sha256_in_sums(sums, "binary.xz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn pipeline_stage_deserializes_transport() {
        let json = r#"{"transport": "http", "credentials": {}, "host": "", "encrypted": true}"#;
        let stage: PipelineStage = serde_json::from_str(json).unwrap();
        match stage {
            PipelineStage::Transport { transport, encrypted, .. } => {
                assert_eq!(transport, "http");
                assert!(encrypted);
            }
            _ => panic!("expected Transport stage"),
        }
    }

    #[test]
    fn pipeline_stage_deserializes_checksum() {
        let json = r#"{"checksum": "SHA256"}"#;
        let stage: PipelineStage = serde_json::from_str(json).unwrap();
        assert_eq!(stage, PipelineStage::Checksum { checksum: "SHA256".to_string() });
    }

    #[test]
    fn pipeline_stage_deserializes_verify() {
        let json = r#"{"verify": "pgp"}"#;
        let stage: PipelineStage = serde_json::from_str(json).unwrap();
        assert_eq!(stage, PipelineStage::Verify { verify: "pgp".to_string() });
    }

    #[test]
    fn pipeline_stage_deserializes_decompress() {
        let json = r#"{"decompress": "xz"}"#;
        let stage: PipelineStage = serde_json::from_str(json).unwrap();
        assert_eq!(stage, PipelineStage::Decompress { decompress: "xz".to_string() });
    }

    #[test]
    fn full_pipeline_deserializes() {
        let json = r#"[
            {"transport": "http", "credentials": {}, "host": "", "encrypted": true},
            {"checksum": "SHA256"},
            {"verify": "pgp"},
            {"decompress": "xz"},
            {"checksum": "SHA256"}
        ]"#;
        let stages: Vec<PipelineStage> = serde_json::from_str(json).unwrap();
        assert_eq!(stages.len(), 5);
    }

    #[test]
    fn pipeline_error_display() {
        let err = PipelineError::ChecksumMismatch {
            stage: "transport".to_string(),
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert!(err.to_string().contains("SHA256 mismatch"));
        assert!(err.to_string().contains("transport"));
    }

    #[tokio::test]
    async fn file_transport_pipeline() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source.bin");
        std::fs::write(&src, b"pipeline test data").unwrap();
        let expected_sha256 = compute_sha256_bytes(b"pipeline test data");

        let stages = vec![
            PipelineStage::Transport {
                transport: "file".to_string(),
                credentials: serde_json::Value::Object(Default::default()),
                host: String::new(),
                encrypted: false,
            },
            PipelineStage::Checksum { checksum: "SHA256".to_string() },
            PipelineStage::Verify { verify: "none".to_string() },
            PipelineStage::Decompress { decompress: "none".to_string() },
        ];

        let checksums = ChecksumSet {
            transport_sha256: Some(expected_sha256.clone()),
            decompressed_sha256: None,
        };

        let executor = PipelineExecutor::new();
        let dest = tmp.path().join("dest.bin");
        let result = executor.execute(
            src.to_str().unwrap(), &dest, &stages, &checksums, None,
        ).await.unwrap();

        assert!(dest.exists());
        assert_eq!(result.sha256, expected_sha256);
        assert!(!result.pgp_verified);
    }

    #[tokio::test]
    async fn file_transport_rejects_bad_checksum() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source.bin");
        std::fs::write(&src, b"data").unwrap();

        let stages = vec![
            PipelineStage::Transport {
                transport: "file".to_string(),
                credentials: serde_json::Value::Object(Default::default()),
                host: String::new(),
                encrypted: false,
            },
            PipelineStage::Checksum { checksum: "SHA256".to_string() },
        ];

        let checksums = ChecksumSet {
            transport_sha256: Some("wrong_hash".to_string()),
            decompressed_sha256: None,
        };

        let executor = PipelineExecutor::new();
        let dest = tmp.path().join("dest.bin");
        let result = executor.execute(
            src.to_str().unwrap(), &dest, &stages, &checksums, None,
        ).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_transport_missing_source_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let stages = vec![
            PipelineStage::Transport {
                transport: "file".to_string(),
                credentials: serde_json::Value::Object(Default::default()),
                host: String::new(),
                encrypted: false,
            },
        ];

        let executor = PipelineExecutor::new();
        let dest = tmp.path().join("dest.bin");
        let result = executor.execute(
            "/nonexistent/path", &dest, &stages, &ChecksumSet::default(), None,
        ).await;

        assert!(result.is_err());
    }
}
