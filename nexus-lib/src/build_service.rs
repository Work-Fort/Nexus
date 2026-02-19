use crate::backend::traits::WorkspaceBackend;
use crate::pipeline::{ChecksumSet, PipelineExecutor, PipelineStage};
use crate::store::traits::StoreError;
use crate::template::{Build, BuildStatus};
use crate::workspace::ImportImageParams;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing;

/// Errors from build service operations.
#[derive(Debug)]
pub enum BuildServiceError {
    Store(StoreError),
    /// A referenced entity was not found.
    NotFound(String),
    /// Build process failed (download, extraction, packaging).
    BuildFailed(String),
}

impl std::fmt::Display for BuildServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildServiceError::Store(e) => write!(f, "{e}"),
            BuildServiceError::NotFound(e) => write!(f, "not found: {e}"),
            BuildServiceError::BuildFailed(e) => write!(f, "build failed: {e}"),
        }
    }
}

impl std::error::Error for BuildServiceError {}

impl From<StoreError> for BuildServiceError {
    fn from(e: StoreError) -> Self {
        BuildServiceError::Store(e)
    }
}

/// Orchestrates build operations: download, extract, overlay, package, register.
///
/// Uses `PipelineExecutor` from Step 6 to download rootfs tarballs (streaming
/// SHA256 during transport). Uses `WorkspaceBackend` to create btrfs subvolumes
/// for master images. Uses `BuildStore` + `ImageStore` sub-traits for persistence.
pub struct BuildService<'a> {
    store: &'a (dyn crate::store::traits::StateStore + Send + Sync),
    backend: &'a dyn WorkspaceBackend,
    executor: &'a PipelineExecutor,
    workspaces_root: PathBuf,
    builds_dir: PathBuf,
}

impl<'a> BuildService<'a> {
    pub fn new(
        store: &'a (dyn crate::store::traits::StateStore + Send + Sync),
        backend: &'a dyn WorkspaceBackend,
        executor: &'a PipelineExecutor,
        workspaces_root: PathBuf,
        builds_dir: PathBuf,
    ) -> Self {
        BuildService { store, backend, executor, workspaces_root, builds_dir }
    }

    /// Trigger a build: create the build record, return it immediately.
    /// The caller is responsible for spawning execute_build in a background task.
    pub fn trigger_build(&self, template_name: &str) -> Result<Build, BuildServiceError> {
        let template = self.store.get_template(template_name)?
            .ok_or_else(|| BuildServiceError::NotFound(
                format!("template '{}' not found", template_name)
            ))?;
        let build = self.store.create_build(&template)?;
        Ok(build)
    }

    /// Execute the build process. This is an async operation (run in a spawned task).
    ///
    /// 1. Download the rootfs tarball via PipelineExecutor
    /// 2. Extract to a temp directory
    /// 3. Write overlay files
    /// 4. Package as ext4 via mke2fs -d
    /// 5. Import into btrfs subvolume and register as master image
    /// 6. Update build status
    pub async fn execute_build(&self, build: &Build) {
        let build_dir = self.builds_dir.join(&build.id);
        let log_path = self.builds_dir.join(format!("{}.log", build.id));

        let result = self.run_build_steps(build, &build_dir, &log_path).await;

        match result {
            Ok(image_id) => {
                let _ = self.store.update_build_status(
                    &build.id,
                    BuildStatus::Success,
                    Some(&image_id),
                    Some(&log_path.to_string_lossy()),
                );
            }
            Err(e) => {
                tracing::error!(build_id = %build.id, error = %e, "build failed");
                let _ = self.store.update_build_status(
                    &build.id,
                    BuildStatus::Failed,
                    None,
                    Some(&log_path.to_string_lossy()),
                );
            }
        }

        // Clean up temp build directory
        let _ = std::fs::remove_dir_all(&build_dir);
    }

    async fn run_build_steps(
        &self,
        build: &Build,
        build_dir: &Path,
        log_path: &Path,
    ) -> Result<String, BuildServiceError> {
        let mut log = std::fs::File::create(log_path)
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot create log: {e}")))?;

        std::fs::create_dir_all(build_dir)
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot create build dir: {e}")))?;

        let rootfs_dir = build_dir.join("rootfs");
        std::fs::create_dir_all(&rootfs_dir)
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot create rootfs dir: {e}")))?;

        // Step 1: Download tarball via PipelineExecutor (streaming SHA256)
        writeln!(log, "Downloading: {}", build.source_identifier).ok();
        let tarball_path = build_dir.join("rootfs.tar.gz");

        let pipeline_stages = vec![
            PipelineStage::Transport {
                transport: if build.source_identifier.starts_with("http://")
                    || build.source_identifier.starts_with("https://") { "http" } else { "file" }.to_string(),
                credentials: serde_json::Value::Object(Default::default()),
                host: String::new(),
                encrypted: build.source_identifier.starts_with("https://"),
            },
            PipelineStage::Checksum { checksum: "SHA256".to_string() },
            PipelineStage::Verify { verify: "none".to_string() },
            PipelineStage::Decompress { decompress: "none".to_string() },
        ];

        self.executor.execute(
            &build.source_identifier,
            &tarball_path,
            &pipeline_stages,
            &ChecksumSet::default(),
            None,
        ).await.map_err(|e| BuildServiceError::BuildFailed(format!("download failed: {e}")))?;
        writeln!(log, "Download complete").ok();

        // Step 2: Extract tarball
        writeln!(log, "Extracting to: {}", rootfs_dir.display()).ok();
        self.extract_tarball(&tarball_path, &rootfs_dir)?;
        writeln!(log, "Extraction complete").ok();

        // Step 3: Write overlay files
        if let Some(ref overlays) = build.overlays {
            writeln!(log, "Applying {} overlay files", overlays.len()).ok();
            for (path, contents) in overlays {
                let dest = rootfs_dir.join(path.trim_start_matches('/'));
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| BuildServiceError::BuildFailed(
                            format!("cannot create overlay parent dir {}: {e}", parent.display())
                        ))?;
                }
                std::fs::write(&dest, contents)
                    .map_err(|e| BuildServiceError::BuildFailed(
                        format!("cannot write overlay {}: {e}", path)
                    ))?;
                writeln!(log, "  overlay: {}", path).ok();
            }
        }

        // Step 4: Package as ext4 via mke2fs -d
        let ext4_path = build_dir.join("rootfs.ext4");
        writeln!(log, "Packaging ext4: {}", ext4_path.display()).ok();
        self.create_ext4_image(&rootfs_dir, &ext4_path, &mut log)?;
        writeln!(log, "ext4 packaging complete").ok();

        // Step 5: Import as master image (create btrfs subvolume with ext4 inside)
        let image_name = format!("{}-build-{}", build.name, &build.id[..8]);
        writeln!(log, "Creating master image: {}", image_name).ok();

        let staging_dir = build_dir.join("staging");
        std::fs::create_dir_all(&staging_dir)
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot create staging dir: {e}")))?;
        std::fs::copy(&ext4_path, staging_dir.join("rootfs.ext4"))
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot copy ext4 to staging: {e}")))?;

        // Use the workspace backend to create btrfs subvolume + mark read-only
        let subvol_dest = self.workspaces_root.join(format!("@{}", image_name));
        self.backend.import_image(&staging_dir, &subvol_dest)
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot import image: {e}")))?;

        // Register in database via ImageStore::create_image
        let import_params = ImportImageParams {
            name: image_name.clone(),
            source_path: staging_dir.to_string_lossy().to_string(),
        };
        let image = self.store.create_image(&import_params, &subvol_dest.to_string_lossy())?;
        writeln!(log, "Registered master image: {} ({})", image.name, image.id).ok();

        Ok(image.id)
    }

    fn extract_tarball(&self, tarball: &Path, dest: &Path) -> Result<(), BuildServiceError> {
        let file = std::fs::File::open(tarball)
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot open tarball: {e}")))?;
        let gz = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(gz);
        archive.set_preserve_permissions(true);
        archive.unpack(dest)
            .map_err(|e| BuildServiceError::BuildFailed(format!("tarball extraction failed: {e}")))?;
        Ok(())
    }

    fn create_ext4_image(
        &self,
        rootfs_dir: &Path,
        ext4_path: &Path,
        log: &mut std::fs::File,
    ) -> Result<(), BuildServiceError> {
        // Calculate size: directory size + 50% headroom, minimum 64MB
        let dir_size = dir_size(rootfs_dir).unwrap_or(0);
        let image_size = std::cmp::max(dir_size * 3 / 2, 64 * 1024 * 1024);

        writeln!(log, "  rootfs size: {} bytes, image size: {} bytes", dir_size, image_size).ok();

        // mke2fs -d <dir> -t ext4 <output> <size_in_blocks>
        let size_kb = image_size / 1024;
        let output = std::process::Command::new("mke2fs")
            .arg("-d")
            .arg(rootfs_dir)
            .arg("-t")
            .arg("ext4")
            .arg(ext4_path)
            .arg(format!("{}k", size_kb))
            .output()
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("cannot run mke2fs: {e}. Is e2fsprogs installed?")
            ))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            writeln!(log, "mke2fs failed: {}", stderr).ok();
            return Err(BuildServiceError::BuildFailed(
                format!("mke2fs failed: {}", stderr)
            ));
        }

        writeln!(log, "  mke2fs succeeded").ok();
        Ok(())
    }
}

/// Recursively compute the total size of files in a directory.
fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_service_error_display() {
        let err = BuildServiceError::NotFound("template 'foo' not found".to_string());
        assert!(err.to_string().contains("not found"));

        let err = BuildServiceError::BuildFailed("download failed".to_string());
        assert!(err.to_string().contains("build failed"));
    }

    #[test]
    fn dir_size_works_on_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let size = dir_size(tmp.path()).unwrap();
        assert_eq!(size, 0);
    }

    #[test]
    fn dir_size_counts_file_sizes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "hello").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "world!").unwrap();
        let size = dir_size(tmp.path()).unwrap();
        assert_eq!(size, 11); // "hello" (5) + "world!" (6)
    }
}
