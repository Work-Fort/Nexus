// nexus/nexus-lib/src/kernel_service.rs

use crate::asset::{
    current_arch, AvailableVersion, ChecksumSet, GitHubKernelProvider, Kernel, KernelProvider,
    Provider, RegisterKernelParams,
};
use crate::github::GitHubError;
use crate::pipeline::{self, PipelineError, PipelineExecutor};
use crate::store::traits::{AssetStore, StoreError};
use std::path::{Path, PathBuf};

/// Errors from kernel service operations.
#[derive(Debug)]
pub enum KernelServiceError {
    Store(StoreError),
    Pipeline(PipelineError),
    GitHub(GitHubError),
    Pgp(String),
    NotFound(String),
    AlreadyExists(String),
    Provider(String),
}

impl std::fmt::Display for KernelServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelServiceError::Store(e) => write!(f, "store error: {e}"),
            KernelServiceError::Pipeline(e) => write!(f, "pipeline error: {e}"),
            KernelServiceError::GitHub(e) => write!(f, "GitHub error: {e}"),
            KernelServiceError::Pgp(e) => write!(f, "PGP error: {e}"),
            KernelServiceError::NotFound(e) => write!(f, "not found: {e}"),
            KernelServiceError::AlreadyExists(e) => write!(f, "already downloaded: {e}"),
            KernelServiceError::Provider(e) => write!(f, "provider error: {e}"),
        }
    }
}

impl std::error::Error for KernelServiceError {}

impl From<StoreError> for KernelServiceError {
    fn from(e: StoreError) -> Self { KernelServiceError::Store(e) }
}
impl From<PipelineError> for KernelServiceError {
    fn from(e: PipelineError) -> Self { KernelServiceError::Pipeline(e) }
}
impl From<GitHubError> for KernelServiceError {
    fn from(e: GitHubError) -> Self { KernelServiceError::GitHub(e) }
}

/// Service for discovering and downloading kernels.
///
/// Uses a `KernelProvider` trait for URL construction and version discovery.
/// Uses the `PipelineExecutor` with pipeline stages from the providers table
/// for the actual download/verify/decompress workflow.
///
/// The `kernels.sha256` column stores the hash of the decompressed file on disk
/// (the second checksum stage in the anvil pipeline), enabling later re-verification:
/// `nexusctl kernel verify 6.18.9`
pub struct KernelService<'a> {
    store: &'a (dyn AssetStore + Send + Sync),
    executor: &'a PipelineExecutor,
    assets_dir: PathBuf,
    providers: Vec<Box<dyn KernelProvider>>,
}

impl<'a> KernelService<'a> {
    pub fn new(
        store: &'a (dyn AssetStore + Send + Sync),
        executor: &'a PipelineExecutor,
        assets_dir: PathBuf,
    ) -> Self {
        // Default provider constructed from the providers table config.
        // In practice, the daemon reads the providers table and constructs
        // the appropriate KernelProvider. Here we show the fallback.
        let providers: Vec<Box<dyn KernelProvider>> = vec![
            Box::new(GitHubKernelProvider::new("Work-Fort/Anvil")),
        ];
        KernelService { store, executor, assets_dir, providers }
    }

    /// Create a KernelService with explicit providers (constructed from DB config).
    pub fn with_providers(
        store: &'a (dyn AssetStore + Send + Sync),
        executor: &'a PipelineExecutor,
        assets_dir: PathBuf,
        providers: Vec<Box<dyn KernelProvider>>,
    ) -> Self {
        KernelService { store, executor, assets_dir, providers }
    }

    fn default_provider(&self) -> Result<&dyn KernelProvider, KernelServiceError> {
        self.providers.first()
            .map(|p| p.as_ref())
            .ok_or_else(|| KernelServiceError::Provider("no kernel providers configured".to_string()))
    }

    /// List available kernel versions from the default provider.
    pub async fn list_available(&self) -> Result<Vec<AvailableVersion>, KernelServiceError> {
        let provider = self.default_provider()?;
        provider.list_versions(self.executor.client()).await
            .map_err(|e| KernelServiceError::Provider(e.to_string()))
    }

    /// Download a specific kernel version using the default provider.
    /// Pipeline stages come from the providers table (passed via `provider_config`).
    pub async fn download(
        &self,
        version: &str,
        provider_config: &Provider,
    ) -> Result<Kernel, KernelServiceError> {
        let provider = self.default_provider()?;
        let arch = current_arch();

        // Check if already downloaded
        let existing = self.store.list_kernels()?;
        if existing.iter().any(|k| k.version == version && k.architecture == arch) {
            return Err(KernelServiceError::AlreadyExists(
                format!("kernel {version} ({arch}) already downloaded")
            ));
        }

        let download_url = provider.download_url(version, arch);
        let compressed_filename = provider.filename(version, arch);
        let decompressed_filename = provider.decompressed_filename(version, arch);

        // Fetch SHA256SUMS and build ChecksumSet (both compressed and decompressed hashes)
        let mut checksums = ChecksumSet::default();
        let mut sums_text = String::new();
        if let Some(sums_url) = provider.checksums_url(version) {
            if let Ok(resp) = self.executor.client().get(&sums_url).send().await {
                if resp.status().is_success() {
                    sums_text = resp.text().await.unwrap_or_default();
                    checksums.transport_sha256 =
                        pipeline::find_sha256_in_sums(&sums_text, &compressed_filename);
                    checksums.decompressed_sha256 =
                        pipeline::find_sha256_in_sums(&sums_text, &decompressed_filename);
                }
            }
        }

        // Fetch PGP data if provider supports it
        let pgp_data = self.fetch_pgp_data(provider, version, &sums_text).await;

        // Execute the pipeline from the providers table
        let kernels_dir = self.assets_dir.join("kernels");
        let dest = kernels_dir.join(&decompressed_filename);

        let result = self.executor.execute(
            &download_url,
            &dest,
            &provider_config.pipeline,
            &checksums,
            pgp_data.as_ref().map(|(k, s, d)| (k.as_str(), s.as_str(), d.as_slice())),
        ).await?;

        // Register in database. sha256 = decompressed hash (at-rest, for re-verification).
        let params = RegisterKernelParams {
            version: version.to_string(),
            architecture: arch.to_string(),
            path_on_host: result.path.to_string_lossy().to_string(),
            sha256: result.sha256,
            pgp_verified: result.pgp_verified,
            file_size: result.size as i64,
            source_url: download_url,
        };

        let kernel = self.store.register_kernel(&params)?;
        Ok(kernel)
    }

    /// Fetch PGP key and signature for verification. Returns (key, signature, signed_data).
    async fn fetch_pgp_data(
        &self,
        provider: &dyn KernelProvider,
        version: &str,
        sums_text: &str,
    ) -> Option<(String, String, Vec<u8>)> {
        let sig_url = provider.pgp_signature_url(version)?;
        let key_url = provider.pgp_public_key_url(version)?;
        let client = self.executor.client();

        let sig_text = client.get(&sig_url).send().await.ok()?
            .text().await.ok()?;
        let key_text = client.get(&key_url).send().await.ok()?
            .text().await.ok()?;

        Some((key_text, sig_text, sums_text.as_bytes().to_vec()))
    }

    /// Verify a downloaded kernel's integrity by re-hashing the file on disk
    /// and comparing to the SHA256 stored in the database.
    pub fn verify(&self, version: &str) -> Result<bool, KernelServiceError> {
        let arch = current_arch();
        let kernels = self.store.list_kernels()?;
        let kernel = kernels.iter()
            .find(|k| k.version == version && k.architecture == arch)
            .ok_or_else(|| KernelServiceError::NotFound(
                format!("kernel {version} ({arch}) not found")
            ))?;

        let actual = pipeline::compute_sha256_file(Path::new(&kernel.path_on_host))
            .map_err(|e| KernelServiceError::Pipeline(e))?;

        Ok(actual == kernel.sha256)
    }

    /// List downloaded kernels.
    pub fn installed(&self) -> Result<Vec<Kernel>, KernelServiceError> {
        Ok(self.store.list_kernels()?)
    }

    /// Remove a downloaded kernel.
    pub fn remove(&self, version: &str) -> Result<bool, KernelServiceError> {
        let arch = current_arch();
        let kernels = self.store.list_kernels()?;
        if let Some(kernel) = kernels.iter().find(|k| k.version == version && k.architecture == arch) {
            let _ = std::fs::remove_file(&kernel.path_on_host);
            self.store.delete_kernel(&kernel.id)?;
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
    fn kernel_service_error_display() {
        let err = KernelServiceError::AlreadyExists("kernel 6.18.9 already downloaded".to_string());
        assert!(err.to_string().contains("already downloaded"));

        let err = KernelServiceError::NotFound("not found".to_string());
        assert!(err.to_string().contains("not found"));

        let err = KernelServiceError::Provider("unknown provider".to_string());
        assert!(err.to_string().contains("provider error"));
    }
}
