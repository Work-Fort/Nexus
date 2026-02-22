use std::path::PathBuf;
use std::fs;
use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

/// Get expected asset paths for kernel, rootfs, firecracker
fn get_asset_paths() -> Result<AssetPaths> {
    let assets_dir = dirs::data_dir()
        .context("Cannot determine XDG_DATA_HOME")?
        .join("nexus")
        .join("assets");

    Ok(AssetPaths {
        kernel: assets_dir.join("kernels"),
        rootfs: assets_dir.join("rootfs"),
        firecracker: assets_dir.join("firecracker"),
    })
}

struct AssetPaths {
    kernel: PathBuf,
    rootfs: PathBuf,
    firecracker: PathBuf,
}

/// Verify clean state - no binaries present before download
pub fn verify_clean_state() -> Result<()> {
    println!("🧹 Verifying clean state...");

    let paths = get_asset_paths()?;

    // Check kernel directory
    if paths.kernel.exists() {
        let entries = fs::read_dir(&paths.kernel)
            .context("Failed to read kernel directory")?;

        if entries.count() > 0 {
            bail!("Kernel directory not empty: {}", paths.kernel.display());
        }
    }

    // Check rootfs directory
    if paths.rootfs.exists() {
        let entries = fs::read_dir(&paths.rootfs)
            .context("Failed to read rootfs directory")?;

        if entries.count() > 0 {
            bail!("Rootfs directory not empty: {}", paths.rootfs.display());
        }
    }

    // Check firecracker directory
    if paths.firecracker.exists() {
        let entries = fs::read_dir(&paths.firecracker)
            .context("Failed to read firecracker directory")?;

        if entries.count() > 0 {
            bail!("Firecracker directory not empty: {}", paths.firecracker.display());
        }
    }

    println!("  ✓ No cached binaries present");
    Ok(())
}

/// Verify downloads present after download
pub fn verify_downloads_present() -> Result<()> {
    println!("📦 Verifying downloads present...");

    let paths = get_asset_paths()?;

    // Verify kernel exists
    if !paths.kernel.exists() || fs::read_dir(&paths.kernel)?.count() == 0 {
        bail!("Kernel not downloaded");
    }
    println!("  ✓ Kernel downloaded");

    // Verify rootfs exists
    if !paths.rootfs.exists() || fs::read_dir(&paths.rootfs)?.count() == 0 {
        bail!("Rootfs not downloaded");
    }
    println!("  ✓ Rootfs downloaded");

    // Verify firecracker exists and is executable
    if !paths.firecracker.exists() || fs::read_dir(&paths.firecracker)?.count() == 0 {
        bail!("Firecracker not downloaded");
    }

    // Find firecracker binary and verify executable
    for entry in fs::read_dir(&paths.firecracker)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.file_name().unwrap().to_str().unwrap().contains("firecracker") {
            // Check executable bit on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = fs::metadata(&path)?;
                let permissions = metadata.permissions();

                if permissions.mode() & 0o111 == 0 {
                    bail!("Firecracker binary not executable: {}", path.display());
                }
            }

            println!("  ✓ Firecracker downloaded and executable");
            return Ok(());
        }
    }

    bail!("Firecracker binary not found in {}", paths.firecracker.display());
}

const DAEMON_URL: &str = "http://localhost:3030";
const ALPINE_VERSION: &str = "3.23.3"; // CRITICAL: Pre-alpha constraint

/// Download kernel via Nexus API
async fn download_kernel(client: &Client) -> Result<()> {
    println!("⬇️  Downloading kernel...");

    let response = client
        .post(format!("{}/v1/kernels/download", DAEMON_URL))
        .json(&json!({
            "provider": "github",
            "repository": "firecracker-microvm/firecracker",
            "ref": "main",
            "kernel_path": "resources/guest_configs/microvm-kernel-ci-x86_64-5.10.223.bin"
        }))
        .timeout(Duration::from_secs(300)) // 5 minute timeout
        .send()
        .await
        .context("Failed to send kernel download request")?;

    if !response.status().is_success() {
        bail!("Kernel download failed: {}", response.status());
    }

    println!("  ✓ Kernel download completed");
    Ok(())
}

/// Download rootfs via Nexus API
async fn download_rootfs(client: &Client) -> Result<()> {
    println!("⬇️  Downloading rootfs...");

    let response = client
        .post(format!("{}/v1/rootfs/download", DAEMON_URL))
        .json(&json!({
            "provider": "alpine",
            "version": ALPINE_VERSION,
            "arch": "x86_64",
            "variant": "standard"
        }))
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .context("Failed to send rootfs download request")?;

    if !response.status().is_success() {
        bail!("Rootfs download failed: {}", response.status());
    }

    println!("  ✓ Rootfs download completed");
    Ok(())
}

/// Download Firecracker via Nexus API
async fn download_firecracker(client: &Client) -> Result<()> {
    println!("⬇️  Downloading Firecracker...");

    let response = client
        .post(format!("{}/v1/firecracker/download", DAEMON_URL))
        .json(&json!({
            "version": "latest"
        }))
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .context("Failed to send Firecracker download request")?;

    if !response.status().is_success() {
        bail!("Firecracker download failed: {}", response.status());
    }

    println!("  ✓ Firecracker download completed");
    Ok(())
}

/// Execute all downloads
pub async fn execute_downloads() -> Result<()> {
    let client = Client::new();

    download_kernel(&client).await?;
    download_rootfs(&client).await?;
    download_firecracker(&client).await?;

    Ok(())
}
