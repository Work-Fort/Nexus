use std::fs;
use std::path::Path;
use std::process::Command;
use anyhow::{Context, Result, bail};

/// Exit code for DNF (Did Not Finish) - prerequisites not met
pub const DNF_EXIT_CODE: i32 = 2;

/// Check all prerequisites required for integration tests
pub fn check_all() -> Result<()> {
    println!("🔍 Checking integration test prerequisites...");

    check_kvm()?;
    check_btrfs()?;
    check_network()?;

    println!("✅ All prerequisites satisfied");
    Ok(())
}

/// Verify /dev/kvm is accessible
fn check_kvm() -> Result<()> {
    let kvm_path = Path::new("/dev/kvm");

    if !kvm_path.exists() {
        eprintln!("DNF: /dev/kvm not found - KVM support required");
        eprintln!("Integration tests require KVM virtualization support");
        eprintln!("Ensure:");
        eprintln!("  1. CPU supports virtualization (Intel VT-x or AMD-V)");
        eprintln!("  2. Virtualization enabled in BIOS");
        eprintln!("  3. KVM kernel modules loaded (kvm_intel or kvm_amd)");
        std::process::exit(DNF_EXIT_CODE);
    }

    // Try to open /dev/kvm to verify permissions
    match fs::OpenOptions::new().read(true).write(true).open(kvm_path) {
        Ok(_) => {
            println!("  ✓ KVM access verified");
            Ok(())
        }
        Err(e) => {
            eprintln!("DNF: Cannot access /dev/kvm - {}", e);
            eprintln!("Ensure current user has permissions (add to 'kvm' group)");
            std::process::exit(DNF_EXIT_CODE);
        }
    }
}

/// Verify current directory is on btrfs filesystem
fn check_btrfs() -> Result<()> {
    // Get current working directory
    let cwd = std::env::current_dir()
        .context("Failed to get current directory")?;

    // Use stat -f to check filesystem type (more reliable than df for subvolumes)
    let output = Command::new("stat")
        .arg("-f")
        .arg("-c")
        .arg("%T")  // Print filesystem type
        .arg(&cwd)
        .output()
        .context("Failed to execute stat command")?;

    if !output.status.success() {
        bail!("stat command failed");
    }

    let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if fs_type != "btrfs" {
        eprintln!("DNF: Current directory not on btrfs filesystem (detected: {})", fs_type);
        eprintln!("Integration tests require btrfs for drive snapshots");
        eprintln!("Current directory: {}", cwd.display());
        std::process::exit(DNF_EXIT_CODE);
    }

    println!("  ✓ btrfs filesystem verified");
    Ok(())
}

/// Verify network connectivity to GitHub (test external service access)
fn check_network() -> Result<()> {
    let test_url = "https://github.com";

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to create HTTP client")?;

    match client.head(test_url).send() {
        Ok(response) => {
            let status = response.status();
            if status.is_success() || status.is_redirection() {
                println!("  ✓ Network connectivity verified");
                Ok(())
            } else {
                eprintln!("DNF: GitHub returned unexpected status: {}", status);
                eprintln!("Integration tests require network access to external services");
                std::process::exit(DNF_EXIT_CODE);
            }
        }
        Err(e) => {
            eprintln!("DNF: Network connectivity check failed - {}", e);
            eprintln!("Integration tests require network access to:");
            eprintln!("  - GitHub (kernels, Firecracker releases)");
            eprintln!("  - Alpine CDN (rootfs images)");
            std::process::exit(DNF_EXIT_CODE);
        }
    }
}
