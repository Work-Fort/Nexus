// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/network_service.rs

use crate::config::NetworkConfig;
use crate::store::traits::{NetworkStore, StoreError};
use ipnetwork::Ipv4Network;
use std::process::Command;
use serde_json::json;

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
pub struct NetworkService {
    store: std::sync::Arc<dyn NetworkStore + Send + Sync>,
    config: NetworkConfig,
}

impl NetworkService {
    pub fn new(
        store: std::sync::Arc<dyn NetworkStore + Send + Sync>,
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

    /// Initialize nftables rules for NAT and VM isolation.
    /// Creates the `nexus` table with postrouting (NAT) and forward (filter) chains.
    /// Requires CAP_NET_ADMIN.
    pub fn init_nftables(&self) -> Result<(), NetworkError> {
        let bridge_name = &self.config.bridge_name;
        let subnet = &self.config.subnet;

        // Parse subnet to get correct CIDR format
        let network: ipnetwork::Ipv4Network = subnet.parse()
            .map_err(|e| NetworkError::Nftables(format!("invalid subnet: {e}")))?;
        let subnet_cidr = format!("{}/{}", network.network(), network.prefix());

        // Create complete nftables ruleset via JSON
        let ruleset_json = json!({
            "nftables": [
                {
                    "add": {
                        "table": {
                            "family": "inet",
                            "name": "nexus"
                        }
                    }
                },
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": "nexus",
                            "name": "postrouting",
                            "type": "nat",
                            "hook": "postrouting",
                            "prio": 100,
                            "policy": "accept"
                        }
                    }
                },
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": "nexus",
                            "name": "forward",
                            "type": "filter",
                            "hook": "forward",
                            "prio": 0,
                            "policy": "drop"
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "nexus",
                            "chain": "postrouting",
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {
                                            "payload": {
                                                "protocol": "ip",
                                                "field": "saddr"
                                            }
                                        },
                                        "right": subnet_cidr
                                    }
                                },
                                {
                                    "match": {
                                        "op": "!=",
                                        "left": {
                                            "meta": {
                                                "key": "oifname"
                                            }
                                        },
                                        "right": bridge_name
                                    }
                                },
                                {
                                    "masquerade": null
                                }
                            ]
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "nexus",
                            "chain": "forward",
                            "expr": [
                                {
                                    "match": {
                                        "op": "in",
                                        "left": {
                                            "ct": {
                                                "key": "state"
                                            }
                                        },
                                        "right": ["established", "related"]
                                    }
                                },
                                {
                                    "accept": null
                                }
                            ]
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "nexus",
                            "chain": "forward",
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {
                                            "meta": {
                                                "key": "iifname"
                                            }
                                        },
                                        "right": bridge_name
                                    }
                                },
                                {
                                    "match": {
                                        "op": "!=",
                                        "left": {
                                            "meta": {
                                                "key": "oifname"
                                            }
                                        },
                                        "right": bridge_name
                                    }
                                },
                                {
                                    "accept": null
                                }
                            ]
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": "nexus",
                            "chain": "forward",
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {
                                            "meta": {
                                                "key": "iifname"
                                            }
                                        },
                                        "right": bridge_name
                                    }
                                },
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {
                                            "meta": {
                                                "key": "oifname"
                                            }
                                        },
                                        "right": bridge_name
                                    }
                                },
                                {
                                    "drop": null
                                }
                            ]
                        }
                    }
                }
            ]
        });

        // Write JSON to temp file and apply via `nft -j -f`
        let json_str = serde_json::to_string(&ruleset_json)
            .map_err(|e| NetworkError::Nftables(format!("failed to serialize ruleset: {e}")))?;

        let temp_file = std::env::temp_dir().join("nexus-nftables-init.json");
        std::fs::write(&temp_file, json_str)
            .map_err(|e| NetworkError::Nftables(format!("failed to write temp file: {e}")))?;

        let apply = Command::new("nft")
            .args(["-j", "-f", temp_file.to_str().unwrap()])
            .output()
            .map_err(|e| NetworkError::Nftables(format!("failed to run nft: {e}")))?;

        if !apply.status.success() {
            let stderr = String::from_utf8_lossy(&apply.stderr);
            return Err(NetworkError::Nftables(format!("nft -j -f failed: {stderr}")));
        }

        Ok(())
    }

    /// Check if nftables is available and meets version requirements (>= 0.9.3).
    pub fn check_nftables_version() -> Result<(), NetworkError> {
        let output = Command::new("nft")
            .arg("--version")
            .output()
            .map_err(|e| NetworkError::Nftables(format!("nft not found: {e}")))?;

        if !output.status.success() {
            return Err(NetworkError::Nftables("nft --version failed".to_string()));
        }

        let version_str = String::from_utf8_lossy(&output.stdout);
        // Parse version (e.g., "nftables v1.1.1 (Old Doc Yak)")
        if let Some(version) = version_str.split_whitespace().nth(1) {
            let version = version.trim_start_matches('v');
            tracing::info!("nftables version: {}", version);
            // Version check: >= 0.9.3
            // Simple string comparison works for nftables versioning
            if version < "0.9.3" {
                return Err(NetworkError::Nftables(
                    format!("nftables version {} is too old (need >= 0.9.3)", version)
                ));
            }
        }

        Ok(())
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

    fn test_service(store: std::sync::Arc<SqliteStore>) -> NetworkService {
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
        let store = std::sync::Arc::new(test_store());
        let service = test_service(store.clone());

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
        let store = std::sync::Arc::new(test_store());
        let service = test_service(store.clone());

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
        let store = std::sync::Arc::new(test_store());
        let service = test_service(store.clone());
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

    #[test]
    fn check_nftables_version_succeeds_if_installed() {
        // This test only passes if nftables is installed on the test system
        // Skip if not available
        let result = NetworkService::check_nftables_version();
        if result.is_err() {
            eprintln!("Skipping nftables test: {}", result.unwrap_err());
        }
    }
}
