// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/rootfs_service.rs

use crate::asset::{
    current_arch, AlpineProvider, ChecksumSet, Provider, RegisterRootfsParams, RootfsImage,
    RootfsProvider,
};
use crate::pipeline::{PipelineError, PipelineExecutor};
use crate::store::traits::{StateStore, StoreError};
use std::path::PathBuf;

/// Errors from rootfs service operations.
#[derive(Debug)]
pub enum RootfsServiceError {
    Store(StoreError),
    Pipeline(PipelineError),
    Http(String),
    NotFound(String),
    AlreadyExists(String),
    Parse(String),
    Provider(String),
}

impl std::fmt::Display for RootfsServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RootfsServiceError::Store(e) => write!(f, "store error: {e}"),
            RootfsServiceError::Pipeline(e) => write!(f, "pipeline error: {e}"),
            RootfsServiceError::Http(e) => write!(f, "HTTP error: {e}"),
            RootfsServiceError::NotFound(e) => write!(f, "not found: {e}"),
            RootfsServiceError::AlreadyExists(e) => write!(f, "already downloaded: {e}"),
            RootfsServiceError::Parse(e) => write!(f, "parse error: {e}"),
            RootfsServiceError::Provider(e) => write!(f, "provider error: {e}"),
        }
    }
}

impl std::error::Error for RootfsServiceError {}

impl From<StoreError> for RootfsServiceError {
    fn from(e: StoreError) -> Self { RootfsServiceError::Store(e) }
}
impl From<PipelineError> for RootfsServiceError {
    fn from(e: PipelineError) -> Self { RootfsServiceError::Pipeline(e) }
}

/// Service for discovering and downloading rootfs images.
///
/// Uses a `RootfsProvider` trait for URL construction and checksum fetching.
/// Uses the `PipelineExecutor` with pipeline stages from the providers table.
pub struct RootfsService<'a> {
    store: &'a (dyn StateStore + Send + Sync),
    executor: &'a PipelineExecutor,
    assets_dir: PathBuf,
    providers: Vec<Box<dyn RootfsProvider>>,
}

impl<'a> RootfsService<'a> {
    pub fn new(
        store: &'a (dyn StateStore + Send + Sync),
        executor: &'a PipelineExecutor,
        assets_dir: PathBuf,
    ) -> Self {
        let providers: Vec<Box<dyn RootfsProvider>> = vec![
            Box::new(AlpineProvider::default()),
        ];
        RootfsService { store, executor, assets_dir, providers }
    }

    pub fn with_providers(
        store: &'a (dyn StateStore + Send + Sync),
        executor: &'a PipelineExecutor,
        assets_dir: PathBuf,
        providers: Vec<Box<dyn RootfsProvider>>,
    ) -> Self {
        RootfsService { store, executor, assets_dir, providers }
    }

    fn find_provider(&self, distro: &str) -> Result<&dyn RootfsProvider, RootfsServiceError> {
        self.providers.iter()
            .find(|p| p.name() == distro)
            .map(|p| p.as_ref())
            .ok_or_else(|| RootfsServiceError::Provider(
                format!("unknown rootfs provider (distro): {distro}")
            ))
    }

    pub fn available_distros(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Download a specific rootfs version for the given distro.
    /// Pipeline stages come from the providers table.
    pub async fn download(
        &self,
        distro: &str,
        version: &str,
        provider_config: &Provider,
    ) -> Result<RootfsImage, RootfsServiceError> {
        let provider = self.find_provider(distro)?;
        let arch = current_arch();

        let existing = self.store.list_rootfs_images()?;
        if existing.iter().any(|r| r.distro == distro && r.version == version && r.architecture == arch) {
            return Err(RootfsServiceError::AlreadyExists(
                format!("rootfs {distro}-{version} ({arch}) already downloaded")
            ));
        }

        let download_url = provider.download_url(version, arch);
        let filename = provider.filename(version, arch);

        // Fetch checksums if available
        let mut checksums = ChecksumSet::default();
        if let Some(sums_url) = provider.checksum_url(version, arch) {
            if let Ok(resp) = self.executor.client().get(&sums_url).send().await {
                if resp.status().is_success() {
                    let sums_text = resp.text().await.unwrap_or_default();
                    checksums.transport_sha256 = provider.parse_checksum(&sums_text, &filename);
                }
            }
        }

        // Execute the pipeline
        let rootfs_dir = self.assets_dir.join("rootfs");
        let dest = rootfs_dir.join(&filename);
        let result = self.executor.execute(
            &download_url, &dest, &provider_config.pipeline, &checksums, None,
        ).await?;

        let params = RegisterRootfsParams {
            distro: distro.to_string(),
            version: version.to_string(),
            architecture: arch.to_string(),
            path_on_host: result.path.to_string_lossy().to_string(),
            sha256: result.sha256,
            file_size: result.size as i64,
            source_url: download_url,
        };

        let rootfs = self.store.register_rootfs(&params)?;
        Ok(rootfs)
    }

    pub fn installed(&self) -> Result<Vec<RootfsImage>, RootfsServiceError> {
        Ok(self.store.list_rootfs_images()?)
    }

    pub fn remove(&self, distro: &str, version: &str) -> Result<bool, RootfsServiceError> {
        let arch = current_arch();
        let images = self.store.list_rootfs_images()?;
        if let Some(img) = images.iter().find(|r| r.distro == distro && r.version == version && r.architecture == arch) {
            let _ = std::fs::remove_file(&img.path_on_host);
            self.store.delete_rootfs(img.id)?;
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
    fn alpine_provider_url_format() {
        let provider = AlpineProvider::default();
        let url = provider.download_url("3.21.3", "x86_64");
        assert_eq!(
            url,
            "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz"
        );
    }

    #[test]
    fn alpine_provider_checksum_url_format() {
        let provider = AlpineProvider::default();
        let url = provider.checksum_url("3.21.3", "x86_64").unwrap();
        assert_eq!(
            url,
            "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/sha256.txt"
        );
    }

    #[test]
    fn rootfs_service_error_display() {
        let err = RootfsServiceError::AlreadyExists("alpine 3.21 exists".to_string());
        assert!(err.to_string().contains("already downloaded"));

        let err = RootfsServiceError::Provider("unknown distro".to_string());
        assert!(err.to_string().contains("provider error"));
    }
}
