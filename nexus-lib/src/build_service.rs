// SPDX-License-Identifier: GPL-2.0-only
use crate::backend::traits::DriveBackend;
use crate::drive::ImportImageParams;
use crate::embedded::{GUEST_AGENT_BINARY, PLACEHOLDER_IMAGE_YAML};
use crate::pipeline::{ChecksumSet, PipelineExecutor, PipelineStage};
use crate::store::traits::StoreError;
use crate::template::{Build, BuildStatus};
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
/// SHA256 during transport). Uses `DriveBackend` to create btrfs subvolumes
/// for master images. Uses `BuildStore` + `ImageStore` sub-traits for persistence.
pub struct BuildService<'a> {
    store: &'a (dyn crate::store::traits::StateStore + Send + Sync),
    backend: &'a dyn DriveBackend,
    executor: &'a PipelineExecutor,
    drives_root: PathBuf,
    builds_dir: PathBuf,
}

impl<'a> BuildService<'a> {
    pub fn new(
        store: &'a (dyn crate::store::traits::StateStore + Send + Sync),
        backend: &'a dyn DriveBackend,
        executor: &'a PipelineExecutor,
        drives_root: PathBuf,
        builds_dir: PathBuf,
    ) -> Self {
        BuildService { store, backend, executor, drives_root, builds_dir }
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
        let build_dir = self.builds_dir.join(build.id.encode());
        let log_path = self.builds_dir.join(format!("{}.log", build.id.encode()));

        let result = self.run_build_steps(build, &build_dir, &log_path).await;

        match result {
            Ok(image_id) => {
                let _ = self.store.update_build_status(
                    build.id,
                    BuildStatus::Success,
                    Some(image_id),
                    Some(&log_path.to_string_lossy()),
                );
            }
            Err(e) => {
                tracing::error!(build_id = %build.id, error = %e, "build failed");
                let _ = self.store.update_build_status(
                    build.id,
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
    ) -> Result<crate::id::Id, BuildServiceError> {
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

        let is_url = build.source_identifier.starts_with("http://")
            || build.source_identifier.starts_with("https://");

        // For local files, resolve the source_identifier to the full asset path
        let source_path = if is_url {
            build.source_identifier.clone()
        } else {
            let images = self.store.list_rootfs_images()
                .map_err(|e| BuildServiceError::BuildFailed(format!("cannot list rootfs images: {e}")))?;
            images.iter()
                .find(|img| img.path_on_host.ends_with(&build.source_identifier))
                .map(|img| img.path_on_host.clone())
                .ok_or_else(|| BuildServiceError::BuildFailed(
                    format!("rootfs asset not found for: {}", build.source_identifier)
                ))?
        };

        let pipeline_stages = vec![
            PipelineStage::Transport {
                transport: if is_url { "http" } else { "file" }.to_string(),
                credentials: serde_json::Value::Object(Default::default()),
                host: String::new(),
                encrypted: build.source_identifier.starts_with("https://"),
            },
            PipelineStage::Checksum { checksum: "SHA256".to_string() },
            PipelineStage::Verify { verify: "none".to_string() },
            PipelineStage::Decompress { decompress: "none".to_string() },
        ];

        self.executor.execute(
            &source_path,
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

        // Write embedded guest-agent binary to rootfs (programmatic, no shell scripts)
        writeln!(log, "Writing embedded guest-agent binary to rootfs").ok();
        let agent_path = rootfs_dir.join("usr/local/bin/guest-agent");
        std::fs::create_dir_all(agent_path.parent().unwrap())
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to create /usr/local/bin directory: {e}")
            ))?;
        std::fs::write(&agent_path, GUEST_AGENT_BINARY)
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to write guest-agent binary: {e}")
            ))?;

        // Set executable permissions (0o755 = rwxr-xr-x)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&agent_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| BuildServiceError::BuildFailed(
                    format!("failed to set guest-agent executable permissions: {e}")
                ))?;
        }

        // Configure init system (BusyBox, OpenRC, or systemd)
        self.configure_init_system(&rootfs_dir, &build.source_identifier, &mut log)?;

        // Write placeholder image metadata (programmatic file write)
        writeln!(log, "Writing placeholder image metadata").ok();
        let metadata_path = rootfs_dir.join("etc/nexus/image.yaml");
        std::fs::create_dir_all(metadata_path.parent().unwrap())
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to create /etc/nexus directory: {e}")
            ))?;
        std::fs::write(&metadata_path, PLACEHOLDER_IMAGE_YAML)
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to write image metadata: {e}")
            ))?;

        // All rootfs modifications complete - fully automated, no user intervention required

        // Step 4: Package as ext4 via mke2fs -d
        let ext4_path = build_dir.join("rootfs.ext4");
        writeln!(log, "Packaging ext4: {}", ext4_path.display()).ok();
        self.create_ext4_image(&rootfs_dir, &ext4_path, &mut log)?;
        writeln!(log, "ext4 packaging complete").ok();

        // Step 5: Import as master image (create btrfs subvolume with ext4 inside)
        let build_id_suffix = build.id.encode();
        let image_name = format!("{}-build-{}", build.name, build_id_suffix);
        writeln!(log, "Creating master image: {}", image_name).ok();

        let staging_dir = build_dir.join("staging");
        std::fs::create_dir_all(&staging_dir)
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot create staging dir: {e}")))?;
        std::fs::copy(&ext4_path, staging_dir.join("rootfs.ext4"))
            .map_err(|e| BuildServiceError::BuildFailed(format!("cannot copy ext4 to staging: {e}")))?;

        // Use the drive backend to create btrfs subvolume + mark read-only
        let subvol_dest = self.drives_root.join(format!("@{}", image_name));
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

    /// Configure init system for guest-agent based on detected init system
    fn configure_init_system(
        &self,
        rootfs_dir: &Path,
        source_identifier: &str,
        log: &mut std::fs::File,
    ) -> Result<(), BuildServiceError> {
        // Phase 1: Filename heuristics
        let init_hint = InitSystem::detect_from_source(source_identifier);
        writeln!(log, "Init system hint from source: {:?}", init_hint).ok();

        // Phase 2: Inspect extracted rootfs
        let init_system = InitSystem::detect_from_rootfs(rootfs_dir);
        writeln!(log, "Init system detected from rootfs: {:?}", init_system).ok();

        match init_system {
            InitSystem::BusyBox => self.configure_busybox_init(rootfs_dir, log),
            InitSystem::OpenRC => self.configure_openrc_init(rootfs_dir, log),
            InitSystem::Systemd => self.configure_systemd_init(rootfs_dir, log),
        }
    }

    /// Configure BusyBox init via /etc/inittab
    fn configure_busybox_init(
        &self,
        rootfs_dir: &Path,
        log: &mut std::fs::File,
    ) -> Result<(), BuildServiceError> {
        writeln!(log, "Configuring BusyBox init system").ok();

        let inittab_path = rootfs_dir.join("etc/inittab");

        // Read existing inittab if it exists
        let existing_inittab = if inittab_path.exists() {
            std::fs::read_to_string(&inittab_path)
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Build appropriate inittab content — always write our complete inittab
        // for purpose-built VM images. Stock distro inittabs (e.g. Alpine's OpenRC
        // references) cause boot errors and slow down guest-agent startup.
        // TODO: Revisit when implementing full OpenRC support — will need to
        // preserve/generate proper OpenRC inittab entries instead of replacing.
        let new_inittab = if existing_inittab.contains("/usr/local/bin/guest-agent") {
            writeln!(log, "  guest-agent entry already in inittab, skipping").ok();
            existing_inittab
        } else {
            writeln!(log, "  writing complete BusyBox inittab (system init + guest-agent)").ok();
            format!("{}{}", crate::embedded::BUSYBOX_SYSTEM_INIT, crate::embedded::GUEST_AGENT_INITTAB_ENTRY)
        };

        std::fs::create_dir_all(inittab_path.parent().unwrap())
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to create /etc directory: {e}")
            ))?;

        std::fs::write(&inittab_path, new_inittab)
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to write /etc/inittab: {e}")
            ))?;

        writeln!(log, "  BusyBox init configured").ok();
        Ok(())
    }

    /// Configure OpenRC init via /etc/init.d/ service script
    fn configure_openrc_init(
        &self,
        rootfs_dir: &Path,
        log: &mut std::fs::File,
    ) -> Result<(), BuildServiceError> {
        writeln!(log, "Configuring OpenRC init system").ok();

        // Write service script to /etc/init.d/nexus-guest-agent
        let service_path = rootfs_dir.join("etc/init.d/nexus-guest-agent");
        std::fs::create_dir_all(service_path.parent().unwrap())
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to create /etc/init.d directory: {e}")
            ))?;

        std::fs::write(&service_path, crate::embedded::GUEST_AGENT_OPENRC_SCRIPT)
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to write OpenRC service script: {e}")
            ))?;

        // Set executable permissions (0o755 = rwxr-xr-x)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&service_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| BuildServiceError::BuildFailed(
                    format!("failed to set OpenRC script executable permissions: {e}")
                ))?;
        }

        writeln!(log, "  wrote OpenRC service script").ok();

        // Enable service by creating symlink in /etc/runlevels/default/
        let runlevel_dir = rootfs_dir.join("etc/runlevels/default");
        std::fs::create_dir_all(&runlevel_dir)
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to create /etc/runlevels/default directory: {e}")
            ))?;

        let symlink_path = runlevel_dir.join("nexus-guest-agent");

        #[cfg(unix)]
        {
            // Remove existing symlink if present
            let _ = std::fs::remove_file(&symlink_path);

            std::os::unix::fs::symlink("/etc/init.d/nexus-guest-agent", &symlink_path)
                .map_err(|e| BuildServiceError::BuildFailed(
                    format!("failed to create OpenRC service symlink: {e}")
                ))?;
        }

        writeln!(log, "  enabled OpenRC service in default runlevel").ok();
        Ok(())
    }

    /// Configure systemd init (existing logic)
    fn configure_systemd_init(
        &self,
        rootfs_dir: &Path,
        log: &mut std::fs::File,
    ) -> Result<(), BuildServiceError> {
        writeln!(log, "Configuring systemd init system").ok();

        // Write systemd service unit
        let service_path = rootfs_dir.join("etc/systemd/system/nexus-guest-agent.service");
        std::fs::create_dir_all(service_path.parent().unwrap())
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to create /etc/systemd/system directory: {e}")
            ))?;

        std::fs::write(&service_path, crate::embedded::GUEST_AGENT_SYSTEMD_UNIT)
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to write guest-agent systemd unit: {e}")
            ))?;

        writeln!(log, "  wrote systemd service unit").ok();

        // Enable service by creating symlink
        let wants_dir = rootfs_dir.join("etc/systemd/system/multi-user.target.wants");
        std::fs::create_dir_all(&wants_dir)
            .map_err(|e| BuildServiceError::BuildFailed(
                format!("failed to create multi-user.target.wants directory: {e}")
            ))?;

        let symlink_path = wants_dir.join("nexus-guest-agent.service");

        #[cfg(unix)]
        {
            // Remove existing symlink if present
            let _ = std::fs::remove_file(&symlink_path);

            std::os::unix::fs::symlink("/etc/systemd/system/nexus-guest-agent.service", &symlink_path)
                .map_err(|e| BuildServiceError::BuildFailed(
                    format!("failed to create systemd service symlink: {e}")
                ))?;
        }

        writeln!(log, "  enabled systemd service").ok();
        Ok(())
    }
}

/// Supported init systems for guest VMs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitSystem {
    BusyBox,
    OpenRC,
    Systemd,
}

impl InitSystem {
    /// Detect init system from source identifier (Phase 1: filename heuristics)
    fn detect_from_source(source: &str) -> Self {
        let source_lower = source.to_lowercase();

        // Alpine minirootfs uses BusyBox init
        if source_lower.contains("alpine-minirootfs") {
            return InitSystem::BusyBox;
        }

        // Full Alpine install uses OpenRC
        if source_lower.contains("alpine") && !source_lower.contains("minirootfs") {
            return InitSystem::OpenRC;
        }

        // Debian and Ubuntu use systemd
        if source_lower.contains("debian") || source_lower.contains("ubuntu") {
            return InitSystem::Systemd;
        }

        // Default to BusyBox (safest minimal option)
        InitSystem::BusyBox
    }

    /// Detect init system by inspecting extracted rootfs (Phase 2: filesystem markers)
    fn detect_from_rootfs(rootfs_dir: &Path) -> Self {
        // Check for systemd
        if rootfs_dir.join("lib/systemd/systemd").exists()
            || rootfs_dir.join("usr/lib/systemd/systemd").exists() {
            return InitSystem::Systemd;
        }

        // Check for OpenRC
        if rootfs_dir.join("sbin/openrc").exists() {
            return InitSystem::OpenRC;
        }

        // Default to pure BusyBox
        InitSystem::BusyBox
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
mod init_system_tests {
    use super::*;

    #[test]
    fn detect_alpine_minirootfs_from_source() {
        assert_eq!(
            InitSystem::detect_from_source("alpine-minirootfs-3.21.3-x86_64.tar.gz"),
            InitSystem::BusyBox
        );
    }

    #[test]
    fn detect_alpine_full_from_source() {
        assert_eq!(
            InitSystem::detect_from_source("alpine-3.21-x86_64.iso"),
            InitSystem::OpenRC
        );
    }

    #[test]
    fn detect_debian_from_source() {
        assert_eq!(
            InitSystem::detect_from_source("debian-12-amd64.tar.gz"),
            InitSystem::Systemd
        );
    }

    #[test]
    fn detect_ubuntu_from_source() {
        assert_eq!(
            InitSystem::detect_from_source("ubuntu-22.04-amd64.tar.gz"),
            InitSystem::Systemd
        );
    }

    #[test]
    fn default_fallback_to_busybox() {
        assert_eq!(
            InitSystem::detect_from_source("custom-rootfs.tar.gz"),
            InitSystem::BusyBox
        );
    }

    #[test]
    fn detect_systemd_from_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("lib/systemd")).unwrap();
        std::fs::write(tmp.path().join("lib/systemd/systemd"), "").unwrap();

        assert_eq!(InitSystem::detect_from_rootfs(tmp.path()), InitSystem::Systemd);
    }

    #[test]
    fn detect_openrc_from_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("sbin")).unwrap();
        std::fs::write(tmp.path().join("sbin/openrc"), "").unwrap();

        assert_eq!(InitSystem::detect_from_rootfs(tmp.path()), InitSystem::OpenRC);
    }

    #[test]
    fn detect_busybox_from_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(InitSystem::detect_from_rootfs(tmp.path()), InitSystem::BusyBox);
    }
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
