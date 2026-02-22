// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/network_service.rs

use crate::config::NetworkConfig;
use crate::store::traits::{NetworkStore, StoreError};
use ipnetwork::Ipv4Network;
use std::process::Command;

/// Errors from network service operations.
#[derive(Debug)]
pub enum NetworkError {
    Store(StoreError),
    IpAllocation(String),
    Bridge(String),
    Tap(String),
    Nftables(String),
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::Store(e) => write!(f, "store error: {e}"),
            NetworkError::IpAllocation(e) => write!(f, "IP allocation error: {e}"),
            NetworkError::Bridge(e) => write!(f, "bridge error: {e}"),
            NetworkError::Tap(e) => write!(f, "tap device error: {e}"),
            NetworkError::Nftables(e) => write!(f, "nftables error: {e}"),
        }
    }
}

impl std::error::Error for NetworkError {}

impl From<StoreError> for NetworkError {
    fn from(e: StoreError) -> Self {
        NetworkError::Store(e)
    }
}

/// Service for managing VM networking (bridge, tap, IP allocation, NAT).
pub struct NetworkService<'a> {
    store: &'a (dyn NetworkStore + Send + Sync),
    config: NetworkConfig,
}

impl<'a> NetworkService<'a> {
    pub fn new(
        store: &'a (dyn NetworkStore + Send + Sync),
        config: NetworkConfig,
    ) -> Self {
        NetworkService { store, config }
    }

    /// Ensure the bridge exists (create if needed, configure IP).
    /// Requires CAP_NET_ADMIN.
    pub fn ensure_bridge(&self) -> Result<(), NetworkError> {
        let bridge_name = &self.config.bridge_name;

        // Check if bridge already exists
        let check = Command::new("ip")
            .args(["link", "show", bridge_name])
            .output();

        if check.is_ok() && check.unwrap().status.success() {
            // Bridge already exists
            return Ok(());
        }

        // Create the bridge
        let create = Command::new("ip")
            .args(["link", "add", "name", bridge_name, "type", "bridge"])
            .output()
            .map_err(|e| NetworkError::Bridge(format!("failed to create bridge: {e}")))?;

        if !create.status.success() {
            let stderr = String::from_utf8_lossy(&create.stderr);
            return Err(NetworkError::Bridge(format!("ip link add failed: {stderr}")));
        }

        // Assign IP to bridge
        let network: Ipv4Network = self.config.subnet.parse()
            .map_err(|e| NetworkError::Bridge(format!("invalid subnet: {e}")))?;
        let gateway = network.nth(1).ok_or_else(|| {
            NetworkError::Bridge("subnet too small".to_string())
        })?;
        let prefix_len = network.prefix();

        let addr = Command::new("ip")
            .args(["addr", "add", &format!("{}/{}", gateway, prefix_len), "dev", bridge_name])
            .output()
            .map_err(|e| NetworkError::Bridge(format!("failed to assign IP: {e}")))?;

        if !addr.status.success() {
            let stderr = String::from_utf8_lossy(&addr.stderr);
            // Ignore "file exists" error (IP already assigned)
            if !stderr.contains("File exists") {
                return Err(NetworkError::Bridge(format!("ip addr add failed: {stderr}")));
            }
        }

        // Bring the bridge up
        let up = Command::new("ip")
            .args(["link", "set", bridge_name, "up"])
            .output()
            .map_err(|e| NetworkError::Bridge(format!("failed to bring bridge up: {e}")))?;

        if !up.status.success() {
            let stderr = String::from_utf8_lossy(&up.stderr);
            return Err(NetworkError::Bridge(format!("ip link set up failed: {stderr}")));
        }

        // Store bridge in database
        let network: Ipv4Network = self.config.subnet.parse().unwrap();
        let gateway = network.nth(1).unwrap();
        self.store.create_bridge(
            bridge_name,
            &self.config.subnet,
            &gateway.to_string(),
            bridge_name,
        )?;

        Ok(())
    }

    /// Allocate an IP for a VM and return the assigned IP.
    pub fn allocate_ip(&self, vm_id: i64) -> Result<String, NetworkError> {
        // Parse the subnet to get available IP range
        let network: Ipv4Network = self.config.subnet.parse()
            .map_err(|e| NetworkError::IpAllocation(format!("invalid subnet: {e}")))?;

        // Get the gateway IP (first host IP, e.g., 172.16.0.1)
        let gateway = network.nth(1).ok_or_else(|| {
            NetworkError::IpAllocation("subnet too small".to_string())
        })?;

        // Get already allocated IPs for this bridge
        let bridge = self.store.get_bridge(&self.config.bridge_name)?;
        if bridge.is_none() {
            // Bridge doesn't exist yet, create it
            self.store.create_bridge(
                &self.config.bridge_name,
                &self.config.subnet,
                &gateway.to_string(),
                &self.config.bridge_name,
            )?;
        }

        let allocated = self.store.list_allocated_ips(&self.config.bridge_name)?;

        // Find first available IP (skip network address and gateway)
        for i in 2..network.size() {
            if let Some(ip) = network.nth(i) {
                let ip_str = ip.to_string();
                // Skip gateway IP explicitly (in case bridge was deleted/recreated)
                if ip_str == gateway.to_string() {
                    continue;
                }
                if !allocated.contains(&ip_str) {
                    // Found an available IP, assign it
                    self.store.assign_vm_ip(vm_id, &ip_str, &self.config.bridge_name)?;
                    return Ok(ip_str);
                }
            }
        }

        Err(NetworkError::IpAllocation("no available IPs in subnet".to_string()))
    }

    /// Create a tap device for a VM and attach it to the bridge.
    /// Returns the tap device name (e.g., "tap1").
    /// Requires CAP_NET_ADMIN.
    pub fn create_tap(&self, vm_id: i64) -> Result<String, NetworkError> {
        let tap_name = format!("tap{}", vm_id);
        let bridge_name = &self.config.bridge_name;

        // Create tap device
        let create = Command::new("ip")
            .args(["tuntap", "add", "dev", &tap_name, "mode", "tap"])
            .output()
            .map_err(|e| NetworkError::Tap(format!("failed to create tap: {e}")))?;

        if !create.status.success() {
            let stderr = String::from_utf8_lossy(&create.stderr);
            return Err(NetworkError::Tap(format!("ip tuntap add failed: {stderr}")));
        }

        // Attach tap to bridge
        let attach = Command::new("ip")
            .args(["link", "set", &tap_name, "master", bridge_name])
            .output()
            .map_err(|e| NetworkError::Tap(format!("failed to attach tap to bridge: {e}")))?;

        if !attach.status.success() {
            let stderr = String::from_utf8_lossy(&attach.stderr);
            return Err(NetworkError::Tap(format!("ip link set master failed: {stderr}")));
        }

        // Bring tap up
        let up = Command::new("ip")
            .args(["link", "set", &tap_name, "up"])
            .output()
            .map_err(|e| NetworkError::Tap(format!("failed to bring tap up: {e}")))?;

        if !up.status.success() {
            let stderr = String::from_utf8_lossy(&up.stderr);
            return Err(NetworkError::Tap(format!("ip link set up failed: {stderr}")));
        }

        Ok(tap_name)
    }

    /// Destroy a tap device and release the VM's IP.
    /// Requires CAP_NET_ADMIN.
    pub fn destroy_tap(&self, vm_id: i64) -> Result<(), NetworkError> {
        let tap_name = format!("tap{}", vm_id);

        // Delete tap device (this also detaches it from the bridge)
        let delete = Command::new("ip")
            .args(["link", "delete", &tap_name])
            .output();

        if let Ok(output) = delete {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Ignore "cannot find device" error (already deleted)
                if !stderr.contains("Cannot find device") {
                    tracing::warn!("ip link delete failed: {}", stderr);
                }
            }
        }

        // Release IP from database
        self.store.release_vm_ip(vm_id)?;

        Ok(())
    }

    /// Get the gateway IP for the bridge.
    pub fn gateway_ip(&self) -> Result<String, NetworkError> {
        let bridge = self.store.get_bridge(&self.config.bridge_name)?
            .ok_or_else(|| NetworkError::Bridge("bridge not found".to_string()))?;
        Ok(bridge.gateway)
    }

    /// Get DNS servers as a comma-separated string.
    pub fn dns_servers(&self) -> String {
        self.config.dns_servers.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;
    use crate::store::traits::VmStore;
    use crate::vm::{CreateVmParams, VmRole};
    use tempfile::tempdir;

    fn test_store() -> SqliteStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("test.db");
        SqliteStore::open_and_init(&db_path).unwrap()
    }

    fn test_service(store: &SqliteStore) -> NetworkService {
        NetworkService::new(
            store,
            NetworkConfig {
                bridge_name: "testbr0".to_string(),
                subnet: "192.168.100.0/24".to_string(),
                dns_servers: vec!["1.1.1.1".to_string()],
            },
        )
    }

    #[test]
    fn allocate_ip_returns_first_available_ip() {
        let store = test_store();
        let service = test_service(&store);

        // Create a VM to satisfy foreign key constraint
        let vm = store.create_vm(&CreateVmParams {
            name: "test-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        let result = service.allocate_ip(vm.id.as_i64());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "192.168.100.2");
    }

    #[test]
    fn allocate_ip_skips_already_assigned_ips() {
        let store = test_store();
        let service = test_service(&store);

        // Create VMs
        let vm1 = store.create_vm(&CreateVmParams {
            name: "vm1".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();
        let vm2 = store.create_vm(&CreateVmParams {
            name: "vm2".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        }).unwrap();

        // Pre-assign an IP
        store.create_bridge("testbr0", "192.168.100.0/24", "192.168.100.1", "testbr0").unwrap();
        store.assign_vm_ip(vm1.id.as_i64(), "192.168.100.2", "testbr0").unwrap();

        let result = service.allocate_ip(vm2.id.as_i64());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "192.168.100.3");
    }

    #[test]
    fn gateway_ip_returns_first_ip_in_subnet() {
        let store = test_store();
        let service = test_service(&store);
        store.create_bridge("testbr0", "192.168.100.0/24", "192.168.100.1", "testbr0").unwrap();

        let result = service.gateway_ip();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "192.168.100.1");
    }

    #[test]
    fn dns_servers_joins_with_comma() {
        let store = test_store();
        let service = NetworkService::new(
            &store,
            NetworkConfig {
                bridge_name: "testbr0".to_string(),
                subnet: "192.168.100.0/24".to_string(),
                dns_servers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            },
        );

        assert_eq!(service.dns_servers(), "8.8.8.8,1.1.1.1");
    }
}
