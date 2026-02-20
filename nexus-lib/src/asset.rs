// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/asset.rs

use crate::id::Id;
use serde::{Deserialize, Serialize};

// Re-export pipeline stage types for consumers that think of them as "asset" types.
pub use crate::pipeline::{ChecksumSet, PipelineStage};

// ---------------------------------------------------------------------------
// Provider configuration (stored in the providers table)
// ---------------------------------------------------------------------------

/// A provider configuration record from the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: Id,
    pub name: String,
    pub asset_type: String,        // "kernel", "rootfs", "firecracker"
    pub provider_type: String,     // "github_release", "archive", "alpine_cdn"
    pub config: serde_json::Value, // parsed JSON config
    pub pipeline: Vec<PipelineStage>, // parsed JSON pipeline stages
    pub is_default: bool,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Asset domain types
// ---------------------------------------------------------------------------

/// A downloaded kernel binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kernel {
    pub id: Id,
    pub version: String,
    pub architecture: String,
    pub path_on_host: String,
    pub sha256: String,
    pub pgp_verified: bool,
    pub file_size: i64,
    pub source_url: String,
    pub downloaded_at: i64,
}

/// Parameters for registering a downloaded kernel.
#[derive(Debug, Clone)]
pub struct RegisterKernelParams {
    pub version: String,
    pub architecture: String,
    pub path_on_host: String,
    pub sha256: String,
    pub pgp_verified: bool,
    pub file_size: i64,
    pub source_url: String,
}

/// A downloaded rootfs image (tarball).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootfsImage {
    pub id: Id,
    pub distro: String,
    pub version: String,
    pub architecture: String,
    pub path_on_host: String,
    pub sha256: String,
    pub file_size: i64,
    pub source_url: String,
    pub downloaded_at: i64,
}

/// Parameters for registering a downloaded rootfs image.
#[derive(Debug, Clone)]
pub struct RegisterRootfsParams {
    pub distro: String,
    pub version: String,
    pub architecture: String,
    pub path_on_host: String,
    pub sha256: String,
    pub file_size: i64,
    pub source_url: String,
}

/// A downloaded Firecracker binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerVersion {
    pub id: Id,
    pub version: String,
    pub architecture: String,
    pub path_on_host: String,
    pub sha256: String,
    pub file_size: i64,
    pub source_url: String,
    pub downloaded_at: i64,
}

/// Parameters for registering a downloaded Firecracker binary.
#[derive(Debug, Clone)]
pub struct RegisterFirecrackerParams {
    pub version: String,
    pub architecture: String,
    pub path_on_host: String,
    pub sha256: String,
    pub file_size: i64,
    pub source_url: String,
}

/// Information about a release version available for download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableVersion {
    pub version: String,
    pub published_at: Option<String>,
    pub download_url: String,
}

// ---------------------------------------------------------------------------
// Provider traits -- focused on the "where" (URLs, filenames, version discovery).
// The "how" (download, verify, decompress) is handled by the PipelineExecutor
// using pipeline stages from the providers table.
// ---------------------------------------------------------------------------

/// Provider for kernel binary downloads. Implementations encapsulate
/// source-specific URL construction, version discovery, and checksum/signature URLs.
/// Pipeline stages (transport, checksum, verify, decompress) come from the database.
#[async_trait::async_trait]
pub trait KernelProvider: Send + Sync {
    /// Provider name (e.g., "github", "archive").
    fn name(&self) -> &str;
    /// List available kernel versions from this provider.
    async fn list_versions(&self, client: &reqwest::Client) -> Result<Vec<AvailableVersion>, Box<dyn std::error::Error + Send + Sync>>;
    /// Build the download URL for a specific version and architecture.
    fn download_url(&self, version: &str, arch: &str) -> String;
    /// Filename for a given version and architecture (compressed, as downloaded).
    fn filename(&self, version: &str, arch: &str) -> String;
    /// Filename for the decompressed kernel on disk.
    fn decompressed_filename(&self, version: &str, arch: &str) -> String;
    /// URL for SHA256SUMS file (if available).
    fn checksums_url(&self, version: &str) -> Option<String>;
    /// URL for PGP signature of checksums (if available).
    fn pgp_signature_url(&self, version: &str) -> Option<String>;
    /// URL for PGP public key (if available).
    fn pgp_public_key_url(&self, version: &str) -> Option<String>;
}

/// GitHub-backed kernel provider. Parameterized by GitHub repo name from provider config.
///
/// Artifact naming follows anvil's format:
/// - `vmlinux-{version}-{arch}.xz`
/// - `SHA256SUMS` (contains hashes for BOTH compressed and decompressed files)
/// - `SHA256SUMS.asc`
/// - `signing-key.asc`
pub struct GitHubKernelProvider {
    pub repo: String,
}

impl GitHubKernelProvider {
    pub fn new(repo: &str) -> Self {
        GitHubKernelProvider { repo: repo.to_string() }
    }
}

#[async_trait::async_trait]
impl KernelProvider for GitHubKernelProvider {
    fn name(&self) -> &str { "github" }

    async fn list_versions(&self, client: &reqwest::Client) -> Result<Vec<AvailableVersion>, Box<dyn std::error::Error + Send + Sync>> {
        let github = crate::github::GitHubReleaseClient::new(client.clone());
        let releases = github.list_releases(&self.repo).await?;
        let arch = current_arch();
        let mut versions = Vec::new();
        for release in releases {
            let kernel_name = self.filename(
                release.tag_name.trim_start_matches('v'),
                arch,
            );
            if let Some(asset) = crate::github::GitHubReleaseClient::find_asset(&release, &kernel_name) {
                versions.push(AvailableVersion {
                    version: release.tag_name.trim_start_matches('v').to_string(),
                    published_at: release.published_at.clone(),
                    download_url: asset.browser_download_url.clone(),
                });
            }
        }
        Ok(versions)
    }

    fn download_url(&self, version: &str, arch: &str) -> String {
        format!(
            "https://github.com/{}/releases/download/v{}/{}",
            self.repo, version, self.filename(version, arch)
        )
    }

    fn filename(&self, version: &str, arch: &str) -> String {
        format!("vmlinux-{}-{}.xz", version, arch)
    }

    fn decompressed_filename(&self, version: &str, arch: &str) -> String {
        format!("vmlinux-{}-{}", version, arch)
    }

    fn checksums_url(&self, version: &str) -> Option<String> {
        Some(format!(
            "https://github.com/{}/releases/download/v{}/SHA256SUMS",
            self.repo, version
        ))
    }

    fn pgp_signature_url(&self, version: &str) -> Option<String> {
        Some(format!(
            "https://github.com/{}/releases/download/v{}/SHA256SUMS.asc",
            self.repo, version
        ))
    }

    fn pgp_public_key_url(&self, version: &str) -> Option<String> {
        Some(format!(
            "https://github.com/{}/releases/download/v{}/signing-key.asc",
            self.repo, version
        ))
    }
}

/// Archive-backed kernel provider. Parameterized by base URL or local path.
/// Reads `index.json` for version discovery. Supports HTTP URLs and local
/// filesystem paths.
pub struct ArchiveKernelProvider {
    pub base: String,
}

impl ArchiveKernelProvider {
    pub fn new(base: &str) -> Self {
        ArchiveKernelProvider { base: base.to_string() }
    }

    pub fn is_local(&self) -> bool {
        !self.base.starts_with("http://") && !self.base.starts_with("https://")
    }
}

#[async_trait::async_trait]
impl KernelProvider for ArchiveKernelProvider {
    fn name(&self) -> &str { "archive" }

    async fn list_versions(&self, client: &reqwest::Client) -> Result<Vec<AvailableVersion>, Box<dyn std::error::Error + Send + Sync>> {
        let arch = current_arch();
        let index_path = format!("{}/{}/index.json", self.base, arch);
        let content = if self.is_local() {
            std::fs::read_to_string(&index_path)?
        } else {
            let resp = client.get(&index_path).send().await?;
            resp.text().await?
        };
        let versions: Vec<AvailableVersion> = serde_json::from_str(&content)?;
        Ok(versions)
    }

    fn download_url(&self, version: &str, arch: &str) -> String {
        format!("{}/{}/{}/vmlinux", self.base, arch, version)
    }

    fn filename(&self, version: &str, arch: &str) -> String {
        format!("vmlinux-{}-{}", version, arch)
    }

    fn decompressed_filename(&self, version: &str, arch: &str) -> String {
        format!("vmlinux-{}-{}", version, arch)
    }

    fn checksums_url(&self, _version: &str) -> Option<String> { None }
    fn pgp_signature_url(&self, _version: &str) -> Option<String> { None }
    fn pgp_public_key_url(&self, _version: &str) -> Option<String> { None }
}

/// Provider for rootfs image downloads. Implementations encapsulate
/// source-specific URL construction and checksum details.
/// Pipeline stages come from the database.
#[async_trait::async_trait]
pub trait RootfsProvider: Send + Sync {
    /// Provider name (e.g., "alpine").
    fn name(&self) -> &str;
    /// Build the download URL for a specific version and architecture.
    fn download_url(&self, version: &str, arch: &str) -> String;
    /// Filename for a given version and architecture.
    fn filename(&self, version: &str, arch: &str) -> String;
    /// URL for checksum file (if available).
    fn checksum_url(&self, version: &str, arch: &str) -> Option<String>;
    /// Parse checksum file content and return the checksum for the given filename.
    fn parse_checksum(&self, checksums_content: &str, filename: &str) -> Option<String>;
}

/// Alpine CDN rootfs provider. Downloads Alpine minirootfs tarballs.
pub struct AlpineProvider {
    pub cdn_base: String,
}

impl AlpineProvider {
    pub fn new(cdn_base: &str) -> Self {
        AlpineProvider { cdn_base: cdn_base.to_string() }
    }
}

impl Default for AlpineProvider {
    fn default() -> Self {
        AlpineProvider { cdn_base: "https://dl-cdn.alpinelinux.org".to_string() }
    }
}

#[async_trait::async_trait]
impl RootfsProvider for AlpineProvider {
    fn name(&self) -> &str { "alpine" }

    fn download_url(&self, version: &str, arch: &str) -> String {
        let major_minor: String = version
            .splitn(3, '.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".");
        format!(
            "{}/alpine/v{}/releases/{}/alpine-minirootfs-{}-{}.tar.gz",
            self.cdn_base, major_minor, arch, version, arch
        )
    }

    fn filename(&self, version: &str, arch: &str) -> String {
        format!("alpine-minirootfs-{}-{}.tar.gz", version, arch)
    }

    fn checksum_url(&self, version: &str, arch: &str) -> Option<String> {
        let major_minor: String = version
            .splitn(3, '.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".");
        Some(format!(
            "{}/alpine/v{}/releases/{}/sha256.txt",
            self.cdn_base, major_minor, arch
        ))
    }

    fn parse_checksum(&self, checksums_content: &str, filename: &str) -> Option<String> {
        crate::pipeline::find_sha256_in_sums(checksums_content, filename)
    }
}

// No FirecrackerProvider trait -- Firecracker is a single project from AWS.
// FirecrackerService reads its config (repo name) from the providers table
// and constructs URLs directly. See Step 7, Task 3.

/// Get the current system architecture as used in asset filenames.
pub(crate) fn current_arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    { "x86_64" }
    #[cfg(target_arch = "aarch64")]
    { "aarch64" }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { "unknown" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_serializes() {
        let kernel = Kernel {
            id: Id::from_i64(1),
            version: "6.18.9".to_string(),
            architecture: "x86_64".to_string(),
            path_on_host: "/home/user/.local/share/nexus/assets/kernels/vmlinux-6.18.9-x86_64".to_string(),
            sha256: "abcdef1234567890".to_string(),
            pgp_verified: true,
            file_size: 10_000_000,
            source_url: "https://github.com/Work-Fort/Anvil/releases/download/v6.18.9/vmlinux-6.18.9-x86_64.xz".to_string(),
            downloaded_at: 1000,
        };
        let json = serde_json::to_string(&kernel).unwrap();
        assert!(json.contains("6.18.9"));
        assert!(json.contains("pgp_verified"));
    }

    #[test]
    fn rootfs_image_serializes() {
        let rootfs = RootfsImage {
            id: Id::from_i64(1),
            distro: "alpine".to_string(),
            version: "3.21.3".to_string(),
            architecture: "x86_64".to_string(),
            path_on_host: "/home/user/.local/share/nexus/assets/rootfs/alpine-minirootfs-3.21.3-x86_64.tar.gz".to_string(),
            sha256: "abcdef1234567890".to_string(),
            file_size: 5_000_000,
            source_url: "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz".to_string(),
            downloaded_at: 1000,
        };
        let json = serde_json::to_string(&rootfs).unwrap();
        assert!(json.contains("alpine"));
        assert!(json.contains("3.21.3"));
    }

    #[test]
    fn firecracker_version_serializes() {
        let fc = FirecrackerVersion {
            id: Id::from_i64(1),
            version: "1.12.0".to_string(),
            architecture: "x86_64".to_string(),
            path_on_host: "/home/user/.local/share/nexus/assets/firecracker/firecracker-v1.12.0-x86_64".to_string(),
            sha256: "abcdef1234567890".to_string(),
            file_size: 3_000_000,
            source_url: "https://github.com/firecracker-microvm/firecracker/releases/download/v1.12.0/firecracker-v1.12.0-x86_64.tgz".to_string(),
            downloaded_at: 1000,
        };
        let json = serde_json::to_string(&fc).unwrap();
        assert!(json.contains("1.12.0"));
        assert!(json.contains("firecracker"));
    }

    #[test]
    fn kernel_deserializes() {
        let id = Id::from_i64(123);
        let json = format!(r#"{{"id":"{}","version":"6.18.9","architecture":"x86_64","path_on_host":"/tmp/k","sha256":"abc","pgp_verified":true,"file_size":100,"source_url":"https://example.com/k","downloaded_at":1000}}"#, id.encode());
        let kernel: Kernel = serde_json::from_str(&json).unwrap();
        assert_eq!(kernel.version, "6.18.9");
        assert!(kernel.pgp_verified);
    }

    #[test]
    fn available_version_serializes() {
        let v = AvailableVersion {
            version: "6.18.9".to_string(),
            published_at: Some("2026-02-15T12:00:00Z".to_string()),
            download_url: "https://example.com/download".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("6.18.9"));
        assert!(json.contains("download_url"));
    }

    #[test]
    fn github_kernel_provider_urls() {
        let provider = GitHubKernelProvider::new("Work-Fort/Anvil");
        assert_eq!(provider.name(), "github");
        assert_eq!(
            provider.filename("6.18.9", "x86_64"),
            "vmlinux-6.18.9-x86_64.xz"
        );
        assert_eq!(
            provider.decompressed_filename("6.18.9", "x86_64"),
            "vmlinux-6.18.9-x86_64"
        );
        assert_eq!(
            provider.download_url("6.18.9", "x86_64"),
            "https://github.com/Work-Fort/Anvil/releases/download/v6.18.9/vmlinux-6.18.9-x86_64.xz"
        );
        assert!(provider.checksums_url("6.18.9").unwrap().contains("SHA256SUMS"));
        assert!(provider.pgp_signature_url("6.18.9").unwrap().contains("SHA256SUMS.asc"));
        assert!(provider.pgp_public_key_url("6.18.9").unwrap().contains("signing-key.asc"));
    }

    #[test]
    fn archive_kernel_provider_urls() {
        let provider = ArchiveKernelProvider::new("https://example.com/kernels");
        assert_eq!(provider.name(), "archive");
        assert_eq!(
            provider.download_url("6.18.9", "x86_64"),
            "https://example.com/kernels/x86_64/6.18.9/vmlinux"
        );
        assert!(provider.checksums_url("6.18.9").is_none());
        assert!(!provider.is_local());
    }

    #[test]
    fn archive_kernel_provider_local_path() {
        let provider = ArchiveKernelProvider::new("/opt/kernels");
        assert!(provider.is_local());
        assert_eq!(
            provider.download_url("6.18.9", "x86_64"),
            "/opt/kernels/x86_64/6.18.9/vmlinux"
        );
    }

    #[test]
    fn alpine_provider_urls() {
        let provider = AlpineProvider::default();
        assert_eq!(provider.name(), "alpine");
        assert_eq!(
            provider.download_url("3.21.3", "x86_64"),
            "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz"
        );
        assert_eq!(
            provider.filename("3.21.3", "x86_64"),
            "alpine-minirootfs-3.21.3-x86_64.tar.gz"
        );
        assert!(provider.checksum_url("3.21.3", "x86_64").unwrap().contains("sha256.txt"));
    }

    #[test]
    fn alpine_provider_custom_cdn() {
        let provider = AlpineProvider::new("https://mirror.example.com");
        assert!(provider.download_url("3.21.3", "x86_64").starts_with("https://mirror.example.com/"));
    }

    #[test]
    fn alpine_provider_parse_checksum() {
        let provider = AlpineProvider::default();
        let sums = "abc123  alpine-minirootfs-3.21.3-x86_64.tar.gz\ndef456  other-file.tar.gz\n";
        assert_eq!(
            provider.parse_checksum(sums, "alpine-minirootfs-3.21.3-x86_64.tar.gz"),
            Some("abc123".to_string())
        );
        assert_eq!(provider.parse_checksum(sums, "nonexistent"), None);
    }
}
