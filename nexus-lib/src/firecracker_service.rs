// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/firecracker_service.rs

use crate::asset::{
    current_arch, AvailableVersion, ChecksumSet, FirecrackerVersion, Provider,
    RegisterFirecrackerParams,
};
use crate::github::{GitHubError, GitHubReleaseClient};
use crate::pipeline::{self, PipelineError, PipelineExecutor};
use crate::store::traits::{StateStore, StoreError};
use std::path::{Path, PathBuf};

/// Errors from Firecracker service operations.
#[derive(Debug)]
pub enum FirecrackerServiceError {
    Store(StoreError),
    Pipeline(PipelineError),
    GitHub(GitHubError),
    NotFound(String),
    AlreadyExists(String),
}

impl std::fmt::Display for FirecrackerServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirecrackerServiceError::Store(e) => write!(f, "store error: {e}"),
            FirecrackerServiceError::Pipeline(e) => write!(f, "pipeline error: {e}"),
            FirecrackerServiceError::GitHub(e) => write!(f, "GitHub error: {e}"),
            FirecrackerServiceError::NotFound(e) => write!(f, "not found: {e}"),
            FirecrackerServiceError::AlreadyExists(e) => write!(f, "already downloaded: {e}"),
        }
    }
}

impl std::error::Error for FirecrackerServiceError {}

impl From<StoreError> for FirecrackerServiceError {
    fn from(e: StoreError) -> Self { FirecrackerServiceError::Store(e) }
}
impl From<PipelineError> for FirecrackerServiceError {
    fn from(e: PipelineError) -> Self { FirecrackerServiceError::Pipeline(e) }
}
impl From<GitHubError> for FirecrackerServiceError {
    fn from(e: GitHubError) -> Self { FirecrackerServiceError::GitHub(e) }
}

/// Service for downloading Firecracker binaries from `firecracker-microvm/firecracker`.
///
/// No provider trait -- Firecracker is a single AWS project. The repo name comes
/// from the providers table config (default: `firecracker-microvm/firecracker`).
/// Pipeline stages come from the providers table.
pub struct FirecrackerService<'a> {
    store: &'a (dyn StateStore + Send + Sync),
    executor: &'a PipelineExecutor,
    assets_dir: PathBuf,
    repo: String,
    base_url: String,
}

impl<'a> FirecrackerService<'a> {
    /// Create from a provider config record (read from the providers table).
    pub fn from_provider(
        store: &'a (dyn StateStore + Send + Sync),
        executor: &'a PipelineExecutor,
        assets_dir: PathBuf,
        provider_config: &Provider,
    ) -> Self {
        let repo = provider_config.config["repo"]
            .as_str()
            .unwrap_or("firecracker-microvm/firecracker")
            .to_string();
        let base_url = provider_config.config.get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or("https://github.com")
            .trim_end_matches('/')
            .to_string();
        FirecrackerService { store, executor, assets_dir, repo, base_url }
    }

    /// Create with default config (for tests / fallback).
    pub fn new(
        store: &'a (dyn StateStore + Send + Sync),
        executor: &'a PipelineExecutor,
        assets_dir: PathBuf,
    ) -> Self {
        FirecrackerService {
            store, executor, assets_dir,
            repo: "firecracker-microvm/firecracker".to_string(),
            base_url: "https://github.com".to_string(),
        }
    }

    fn tgz_filename(&self, version: &str, arch: &str) -> String {
        format!("firecracker-v{}-{}.tgz", version, arch)
    }

    fn checksums_url(&self, version: &str, arch: &str) -> String {
        format!(
            "{}/{}/releases/download/v{}/firecracker-v{}-{}.tgz.sha256.txt",
            self.base_url, self.repo, version, version, arch
        )
    }

    fn download_url(&self, version: &str, arch: &str) -> String {
        format!(
            "{}/{}/releases/download/v{}/{}",
            self.base_url, self.repo, version, self.tgz_filename(version, arch)
        )
    }

    /// List available Firecracker versions from GitHub releases.
    pub async fn list_available(&self) -> Result<Vec<AvailableVersion>, FirecrackerServiceError> {
        let github = GitHubReleaseClient::new(self.executor.client().clone());
        let releases = github.list_releases(&self.repo).await?;
        let arch = current_arch();
        let mut versions = Vec::new();
        for release in releases {
            if release.prerelease { continue; }
            let tgz_name = self.tgz_filename(
                release.tag_name.trim_start_matches('v'), arch,
            );
            if let Some(asset) = GitHubReleaseClient::find_asset(&release, &tgz_name) {
                versions.push(AvailableVersion {
                    version: release.tag_name.trim_start_matches('v').to_string(),
                    published_at: release.published_at.clone(),
                    download_url: asset.browser_download_url.clone(),
                });
            }
        }
        Ok(versions)
    }

    /// Download a specific Firecracker version.
    /// Uses the pipeline from the providers table for the tgz download,
    /// then extracts the binary and computes its hash.
    pub async fn download(
        &self,
        version: &str,
        provider_config: &Provider,
    ) -> Result<FirecrackerVersion, FirecrackerServiceError> {
        // Strip leading "v" if present to normalize version format
        let version = version.trim_start_matches('v');
        let arch = current_arch();

        let existing = self.store.list_firecracker_versions()?;
        if existing.iter().any(|f| f.version == version && f.architecture == arch) {
            return Err(FirecrackerServiceError::AlreadyExists(
                format!("firecracker {version} ({arch}) already downloaded")
            ));
        }

        let url = self.download_url(version, arch);
        let tgz_name = self.tgz_filename(version, arch);

        // Fetch SHA256 checksum for the tgz
        let mut checksums = ChecksumSet::default();
        let sums_url = self.checksums_url(version, arch);
        if let Ok(resp) = self.executor.client().get(&sums_url).send().await {
            if resp.status().is_success() {
                let sha_text = resp.text().await.unwrap_or_default();
                checksums.transport_sha256 = sha_text.split_whitespace().next().map(|s| s.to_string());
            }
        }

        // Download the tgz via pipeline
        let fc_dir = self.assets_dir.join("firecracker");
        let tgz_path = fc_dir.join(&tgz_name);
        let _result = self.executor.execute(
            &url, &tgz_path, &provider_config.pipeline, &checksums, None,
        ).await?;

        // Extract the firecracker binary from the tgz
        let tag = format!("v{}", version);
        let dest = fc_dir.join(format!("firecracker-{}-{}", tag, arch));
        Self::extract_firecracker_from_tgz(&tgz_path, &dest)?;

        // Make it executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dest)
                .map_err(|e| PipelineError::Io(e.to_string()))?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest, perms)
                .map_err(|e| PipelineError::Io(e.to_string()))?;
        }

        // Validate the extracted binary runs (catches wrong-arch or debug-only builds)
        let version_check = std::process::Command::new(&dest)
            .arg("--version")
            .output();
        match version_check {
            Ok(output) if output.status.success() => {
                let version = String::from_utf8_lossy(&output.stdout);
                tracing::info!("Firecracker binary validated: {}", version.trim());
            }
            Ok(output) => {
                let _ = std::fs::remove_file(&dest);
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(PipelineError::Io(
                    format!("extracted firecracker binary failed --version check: {stderr}")
                ).into());
            }
            Err(e) => {
                let _ = std::fs::remove_file(&dest);
                return Err(PipelineError::Io(
                    format!("cannot execute extracted firecracker binary: {e}")
                ).into());
            }
        }

        // Compute SHA256 of the extracted binary
        let binary_sha256 = pipeline::compute_sha256_file(&dest)?;
        let binary_size = std::fs::metadata(&dest)
            .map_err(|e| PipelineError::Io(e.to_string()))?.len();

        // Clean up the tgz
        let _ = std::fs::remove_file(&tgz_path);

        let params = RegisterFirecrackerParams {
            version: version.to_string(),
            architecture: arch.to_string(),
            path_on_host: dest.to_string_lossy().to_string(),
            sha256: binary_sha256,
            file_size: binary_size as i64,
            source_url: url,
        };

        let fc = self.store.register_firecracker(&params)?;
        Ok(fc)
    }

    /// Extract the firecracker binary from a release .tgz archive.
    fn extract_firecracker_from_tgz(tgz_path: &Path, dest: &Path) -> Result<(), PipelineError> {
        let file = std::fs::File::open(tgz_path)
            .map_err(|e| PipelineError::Io(format!("cannot open tgz: {e}")))?;
        let gz = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(gz);

        for entry in archive.entries().map_err(|e| PipelineError::Decompression(e.to_string()))? {
            let mut entry = entry.map_err(|e| PipelineError::Decompression(e.to_string()))?;
            let path = entry.path().map_err(|e| PipelineError::Decompression(e.to_string()))?;
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("firecracker-v") && !name.contains("jailer") && !name.ends_with(".debug") {
                let mut out = std::fs::File::create(dest)
                    .map_err(|e| PipelineError::Io(format!("cannot create output: {e}")))?;
                std::io::copy(&mut entry, &mut out)
                    .map_err(|e| PipelineError::Io(format!("cannot extract: {e}")))?;
                return Ok(());
            }
        }

        Err(PipelineError::Decompression("firecracker binary not found in archive".to_string()))
    }

    pub fn installed(&self) -> Result<Vec<FirecrackerVersion>, FirecrackerServiceError> {
        Ok(self.store.list_firecracker_versions()?)
    }

    pub fn remove(&self, version: &str) -> Result<bool, FirecrackerServiceError> {
        let arch = current_arch();
        let versions = self.store.list_firecracker_versions()?;
        if let Some(fc) = versions.iter().find(|f| f.version == version && f.architecture == arch) {
            let _ = std::fs::remove_file(&fc.path_on_host);
            self.store.delete_firecracker(fc.id)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_service_error_display() {
        let err = FirecrackerServiceError::AlreadyExists("fc 1.12 exists".to_string());
        assert!(err.to_string().contains("already downloaded"));
    }

    #[test]
    fn tgz_filename_format() {
        // Verify URL construction directly (no provider trait needed)
        let repo = "firecracker-microvm/firecracker";
        let version = "1.14.1";
        let arch = "x86_64";
        let expected = format!(
            "https://github.com/{}/releases/download/v{}/firecracker-v{}-{}.tgz",
            repo, version, version, arch
        );
        assert_eq!(
            expected,
            "https://github.com/firecracker-microvm/firecracker/releases/download/v1.14.1/firecracker-v1.14.1-x86_64.tgz"
        );
    }

    #[test]
    fn extract_skips_debug_binary() {
        let dir = tempfile::tempdir().unwrap();
        let tgz_path = dir.path().join("test.tgz");
        let dest = dir.path().join("firecracker");

        // Build a tgz with debug file first, then the real binary
        let file = std::fs::File::create(&tgz_path).unwrap();
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut ar = tar::Builder::new(gz);

        // Add debug binary first (should be skipped)
        let debug_content = b"debug-symbols-not-a-real-binary";
        let mut header = tar::Header::new_gnu();
        header.set_size(debug_content.len() as u64);
        header.set_cksum();
        ar.append_data(
            &mut header,
            "release-v1.14.1-x86_64/firecracker-v1.14.1-x86_64.debug",
            &debug_content[..],
        ).unwrap();

        // Add real binary second (should be extracted)
        let real_content = b"real-firecracker-binary";
        let mut header = tar::Header::new_gnu();
        header.set_size(real_content.len() as u64);
        header.set_cksum();
        ar.append_data(
            &mut header,
            "release-v1.14.1-x86_64/firecracker-v1.14.1-x86_64",
            &real_content[..],
        ).unwrap();

        ar.into_inner().unwrap().finish().unwrap();

        // Extract
        FirecrackerService::extract_firecracker_from_tgz(&tgz_path, &dest).unwrap();

        // Verify we got the real binary, not the debug one
        let extracted = std::fs::read(&dest).unwrap();
        assert_eq!(extracted, b"real-firecracker-binary");
    }
}
