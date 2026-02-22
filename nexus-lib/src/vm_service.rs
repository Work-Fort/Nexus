// SPDX-License-Identifier: GPL-2.0-only
use crate::config;
use crate::store::traits::StoreError;
use crate::vm::Vm;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Errors from VM service operations.
#[derive(Debug)]
pub enum VmServiceError {
    Store(StoreError),
    /// VM not found
    NotFound(String),
    /// Operation not allowed in current state
    Conflict(String),
    /// Firecracker binary not found or cannot execute
    FirecrackerError(String),
    /// I/O error (creating dirs, writing config, etc.)
    Io(std::io::Error),
}

impl std::fmt::Display for VmServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmServiceError::Store(e) => write!(f, "{e}"),
            VmServiceError::NotFound(e) => write!(f, "not found: {e}"),
            VmServiceError::Conflict(e) => write!(f, "conflict: {e}"),
            VmServiceError::FirecrackerError(e) => write!(f, "firecracker error: {e}"),
            VmServiceError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for VmServiceError {}

impl From<StoreError> for VmServiceError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Conflict(msg) => VmServiceError::Conflict(msg),
            other => VmServiceError::Store(other),
        }
    }
}

impl From<std::io::Error> for VmServiceError {
    fn from(e: std::io::Error) -> Self {
        VmServiceError::Io(e)
    }
}

/// Generates the Firecracker JSON config for a VM.
pub fn firecracker_config(
    vm: &Vm,
    kernel_path: &str,
    rootfs_path: &str,
    vsock_uds_path: &str,
    tap_device: Option<&str>,
    guest_ip: Option<&str>,
    gateway_ip: Option<&str>,
) -> serde_json::Value {
    let mut config = json!({
        "boot-source": {
            "kernel_image_path": kernel_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/init"
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": rootfs_path,
                "is_root_device": true,
                "is_read_only": false,
                "cache_type": "Unsafe"
            }
        ],
        "machine-config": {
            "vcpu_count": vm.vcpu_count,
            "mem_size_mib": vm.mem_size_mib,
            "smt": false
        },
        "vsock": {
            "guest_cid": vm.cid,
            "uds_path": vsock_uds_path
        }
    });

    // Add network interface if tap device provided
    if let (Some(tap), Some(ip), Some(gw)) = (tap_device, guest_ip, gateway_ip) {
        config["network-interfaces"] = json!([
            {
                "iface_id": "eth0",
                "host_dev_name": tap,
                "guest_mac": format!("02:FC:00:00:00:{:02x}", vm.cid % 256),
            }
        ]);

        // Update boot args to include IP configuration
        let mut boot_args = config["boot-source"]["boot_args"].as_str().unwrap().to_string();
        boot_args.push_str(&format!(" ip={}::{}:255.240.0.0::eth0:off", ip, gw));
        config["boot-source"]["boot_args"] = json!(boot_args);
    }

    config
}

/// Returns the runtime directory for a VM: $XDG_RUNTIME_DIR/nexus/vms/<id>
pub fn vm_runtime_dir(vm_id: &crate::id::Id) -> PathBuf {
    config::default_runtime_path().join("vms").join(vm_id.encode())
}

/// Spawn a Firecracker process for a VM.
///
/// 1. Creates the VM runtime directory
/// 2. Writes the Firecracker config JSON
/// 3. Spawns Firecracker with --api-sock and --config-file
/// 4. Returns the child process
///
/// The caller is responsible for updating the store with the PID and
/// monitoring the process for exit.
pub fn spawn_firecracker(
    fc_binary: &str,
    vm: &Vm,
    kernel_path: &str,
    rootfs_path: &str,
    tap_device: Option<&str>,
    guest_ip: Option<&str>,
    gateway_ip: Option<&str>,
) -> Result<(std::process::Child, PathBuf), VmServiceError> {
    let runtime_dir = vm_runtime_dir(&vm.id);
    fs::create_dir_all(&runtime_dir)?;

    let api_sock = runtime_dir.join("firecracker.sock");
    let vsock_uds = runtime_dir.join("firecracker.vsock");
    let console_log = runtime_dir.join("console.log");
    let config_path = runtime_dir.join("config.json");

    // Clean up stale sockets from previous runs
    let _ = fs::remove_file(&api_sock);
    let _ = fs::remove_file(&vsock_uds);

    let config = firecracker_config(
        vm,
        kernel_path,
        rootfs_path,
        &vsock_uds.to_string_lossy(),
        tap_device,
        guest_ip,
        gateway_ip,
    );
    let config_str = serde_json::to_string_pretty(&config)
        .map_err(|e| VmServiceError::FirecrackerError(format!("cannot serialize config: {e}")))?;
    fs::write(&config_path, &config_str)?;

    // Open console log file for stdout/stderr capture
    let log_file = fs::File::create(&console_log)?;
    let log_file_err = log_file.try_clone()?;

    let child = Command::new(fc_binary)
        .arg("--api-sock")
        .arg(&api_sock)
        .arg("--config-file")
        .arg(&config_path)
        .stdout(log_file)
        .stderr(log_file_err)
        .spawn()
        .map_err(|e| VmServiceError::FirecrackerError(format!(
            "cannot spawn firecracker at '{}': {e}", fc_binary
        )))?;

    Ok((child, runtime_dir))
}

/// Clean up a VM's runtime directory (sockets, logs, config).
pub fn cleanup_runtime_dir(vm_id: &crate::id::Id) {
    let runtime_dir = vm_runtime_dir(vm_id);
    let _ = fs::remove_dir_all(&runtime_dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{Vm, VmRole, VmState};

    fn test_vm() -> Vm {
        Vm {
            id: crate::id::Id::from_i64(1),
            name: "test-vm".to_string(),
            role: VmRole::Work,
            state: VmState::Created,
            cid: 3,
            vcpu_count: 2,
            mem_size_mib: 512,
            created_at: 1000,
            updated_at: 1000,
            started_at: None,
            stopped_at: None,
            pid: None,
            socket_path: None,
            uds_path: None,
            console_log_path: None,
            config_json: None,
            agent_connected_at: None,
        }
    }

    #[test]
    fn firecracker_config_has_correct_structure() {
        let vm = test_vm();
        let config = firecracker_config(
            &vm,
            "/path/vmlinux",
            "/path/rootfs.ext4",
            "/run/vsock",
            None,  // no tap device
            None,  // no guest IP
            None,  // no gateway IP
        );

        assert_eq!(config["boot-source"]["kernel_image_path"], "/path/vmlinux");
        assert_eq!(config["drives"][0]["drive_id"], "rootfs");
        assert_eq!(config["drives"][0]["path_on_host"], "/path/rootfs.ext4");
        assert_eq!(config["drives"][0]["is_root_device"], true);
        assert_eq!(config["drives"][0]["cache_type"], "Unsafe");
        assert_eq!(config["machine-config"]["vcpu_count"], 2);
        assert_eq!(config["machine-config"]["mem_size_mib"], 512);
        assert_eq!(config["vsock"]["guest_cid"], 3);
        assert_eq!(config["vsock"]["uds_path"], "/run/vsock");
    }

    #[test]
    fn firecracker_config_with_network() {
        let vm = test_vm();
        let config = firecracker_config(
            &vm,
            "/path/vmlinux",
            "/path/rootfs.ext4",
            "/run/vsock",
            Some("tap0"),
            Some("172.16.0.2"),
            Some("172.16.0.1"),
        );

        // Verify network interface is added
        assert_eq!(config["network-interfaces"][0]["iface_id"], "eth0");
        assert_eq!(config["network-interfaces"][0]["host_dev_name"], "tap0");
        assert_eq!(config["network-interfaces"][0]["guest_mac"], "02:FC:00:00:00:03");

        // Verify boot args include IP configuration
        let boot_args = config["boot-source"]["boot_args"].as_str().unwrap();
        assert!(boot_args.contains("ip=172.16.0.2::172.16.0.1:255.240.0.0::eth0:off"));
    }

    #[test]
    fn vm_runtime_dir_includes_vm_id() {
        let id = crate::id::Id::from_i64(123);
        let dir = vm_runtime_dir(&id);
        assert!(dir.to_string_lossy().contains("nexus/vms/"));
        assert!(dir.to_string_lossy().contains(&id.encode()));
    }

    #[test]
    fn spawn_firecracker_fails_with_nonexistent_binary() {
        let vm = test_vm();
        let result = spawn_firecracker(
            "/nonexistent/firecracker",
            &vm,
            "/nonexistent/vmlinux",
            "/nonexistent/rootfs.ext4",
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }
}
