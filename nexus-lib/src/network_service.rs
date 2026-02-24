// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/network_service.rs

use crate::store::traits::{NetworkStore, SettingsStore, StoreError};
use ipnetwork::Ipv4Network;
use rtnetlink::{new_connection, Handle, LinkUnspec};
use futures::stream::TryStreamExt;
use tun_tap::{Iface, Mode};
use rtnetlink::packet_route::link::{
    InfoBridgePort, InfoPortData, InfoPortKind, LinkAttribute,
};
use std::os::fd::AsRawFd;

#[derive(Debug, Default, serde::Serialize)]
pub struct CleanupReport {
    pub taps_deleted: u32,
    pub bridge_deleted: bool,
    pub nftables_flushed: bool,
}

/// Set IFF_PERSIST flag on a tap device to prevent kernel from destroying it when the fd closes.
/// This allows Firecracker to attach to the pre-created tap device.
fn set_tap_persistent(iface: &Iface) -> Result<(), std::io::Error> {
    const TUNSETPERSIST: nix::libc::c_ulong = 0x400454cb; // ioctl number for TUNSETPERSIST
    let fd = iface.as_raw_fd();
    let ret = unsafe { nix::libc::ioctl(fd, TUNSETPERSIST, 1) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}


/// Helper to execute async netlink operations in a sync context.
struct NetlinkHelper {
    handle: Handle,
}

impl NetlinkHelper {
    fn new() -> Result<Self, NetworkError> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| NetworkError::Bridge(format!("failed to create netlink connection: {e}")))?;

        // Spawn connection handler on current tokio runtime
        tokio::spawn(connection);

        Ok(NetlinkHelper { handle })
    }

    async fn get_link_index(&self, name: &str) -> Result<u32, NetworkError> {
        let mut links = self.handle.link().get().match_name(name.to_string()).execute();
        let link = links.try_next().await
            .map_err(|e| NetworkError::Bridge(format!("failed to query link {}: {}", name, e)))?
            .ok_or_else(|| NetworkError::Bridge(format!("link {} not found", name)))?;
        Ok(link.header.index)
    }
}

/// Send a finalized nftables batch to the kernel via netlink.
fn send_nftables_batch(batch: &nftnl::FinalizedBatch) -> std::io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let portid = socket.portid();
    socket.send_all(batch)?;
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let mut expected_seqs = batch.sequence_numbers();
    while !expected_seqs.is_empty() {
        for message in socket.recv(&mut buffer[..])? {
            let message = message?;
            let expected_seq = expected_seqs.next().expect("unexpected netlink ACK");
            mnl::cb_run(message, expected_seq, portid)?;
        }
    }
    Ok(())
}

/// Pad an interface name with null terminator and align to 4 bytes for nftables comparison.
fn pad_iface_name(name: &str) -> Vec<u8> {
    let mut buf = name.as_bytes().to_vec();
    buf.push(0); // null terminator
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
    buf
}

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
    settings_store: std::sync::Arc<dyn SettingsStore + Send + Sync>,
}

impl NetworkService {
    pub fn new(
        store: std::sync::Arc<dyn NetworkStore + Send + Sync>,
        settings_store: std::sync::Arc<dyn SettingsStore + Send + Sync>,
    ) -> Self {
        NetworkService { store, settings_store }
    }

    /// Get bridge name from settings table.
    fn bridge_name(&self) -> Result<String, NetworkError> {
        self.settings_store
            .get_setting("bridge_name")
            .map_err(NetworkError::Store)?
            .ok_or_else(|| NetworkError::Bridge("bridge_name setting not found".to_string()))
    }

    /// Get VM subnet from settings table.
    fn vm_subnet(&self) -> Result<String, NetworkError> {
        self.settings_store
            .get_setting("vm_subnet")
            .map_err(NetworkError::Store)?
            .ok_or_else(|| NetworkError::Bridge("vm_subnet setting not found".to_string()))
    }

    /// Get DNS servers from settings table (JSON array or "from-host" string).
    fn get_dns_servers_vec(&self) -> Result<Vec<String>, NetworkError> {
        let dns_value = self
            .settings_store
            .get_setting("dns_servers")
            .map_err(NetworkError::Store)?
            .ok_or_else(|| NetworkError::Bridge("dns_servers setting not found".to_string()))?;

        // Handle special "from-host" value
        if dns_value == "from-host" {
            return self.read_host_dns_servers();
        }

        // Otherwise, parse as JSON
        let json: serde_json::Value = serde_json::from_str(&dns_value)
            .map_err(|e| NetworkError::Bridge(format!("invalid dns_servers JSON: {}", e)))?;

        let servers = json["servers"]
            .as_array()
            .ok_or_else(|| NetworkError::Bridge("dns_servers missing 'servers' array".to_string()))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        Ok(servers)
    }

    /// Read DNS nameservers from host's /etc/resolv.conf.
    fn read_host_dns_servers(&self) -> Result<Vec<String>, NetworkError> {
        let resolv_conf = std::fs::read_to_string("/etc/resolv.conf")
            .map_err(|e| NetworkError::Bridge(format!("cannot read /etc/resolv.conf: {}", e)))?;

        let nameservers: Vec<String> = resolv_conf
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with("nameserver ") {
                    line.strip_prefix("nameserver ").map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
            .collect();

        if nameservers.is_empty() {
            return Err(NetworkError::Bridge(
                "no nameservers found in /etc/resolv.conf".to_string()
            ));
        }

        Ok(nameservers)
    }

    /// Ensure the bridge exists (create if needed, configure IP).
    /// Requires CAP_NET_ADMIN.
    pub fn ensure_bridge(&self) -> Result<(), NetworkError> {
        let bridge_name = self.bridge_name()?;
        let subnet = self.vm_subnet()?;

        // Use block_in_place to run async rtnetlink in sync context
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let helper = NetlinkHelper::new()?;

                // Check if bridge already exists
                let existing_index = helper.get_link_index(&bridge_name).await.ok();

                if let Some(bridge_index) = existing_index {
                    tracing::info!("Bridge {} already exists at index {}, ensuring it's up", bridge_name, bridge_index);

                    // Bring bridge up
                    helper.handle
                        .link()
                        .set(LinkUnspec::new_with_index(bridge_index).up().build())
                        .execute()
                        .await
                        .map_err(|e| NetworkError::Bridge(format!("failed to bring bridge up: {e}")))?;

                    return Ok(());
                }

                // Create the bridge
                use rtnetlink::LinkBridge;

                helper.handle
                    .link()
                    .add(LinkBridge::new(&bridge_name).build())
                    .execute()
                    .await
                    .map_err(|e| NetworkError::Bridge(format!("failed to create bridge: {e}")))?;

                tracing::info!("Bridge {} created", bridge_name);

                // Get bridge index for IP assignment
                let bridge_index = helper.get_link_index(&bridge_name).await?;

                // Parse subnet and gateway IP
                let network: Ipv4Network = subnet.parse()
                    .map_err(|e| NetworkError::Bridge(format!("invalid subnet: {e}")))?;
                let gateway = network.nth(1).ok_or_else(|| {
                    NetworkError::Bridge("subnet too small".to_string())
                })?;
                let prefix_len = network.prefix();

                // Assign IP to bridge
                let result = helper.handle
                    .address()
                    .add(bridge_index, gateway.into(), prefix_len)
                    .execute()
                    .await;

                match result {
                    Ok(_) => {
                        tracing::info!("Assigned IP {}/{} to bridge {}", gateway, prefix_len, bridge_name);
                    }
                    Err(e) => {
                        let err_str = format!("{}", e);
                        if err_str.contains("File exists") || err_str.contains("EEXIST") {
                            tracing::debug!("IP already assigned to bridge (EEXIST), continuing");
                        } else {
                            return Err(NetworkError::Bridge(format!("failed to assign IP: {e}")));
                        }
                    }
                }

                // Bring bridge up
                helper.handle
                    .link()
                    .set(LinkUnspec::new_with_index(bridge_index).up().build())
                    .execute()
                    .await
                    .map_err(|e| NetworkError::Bridge(format!("failed to bring bridge up: {e}")))?;

                // Store bridge in database
                self.store.create_bridge(
                    &bridge_name,
                    &subnet,
                    &gateway.to_string(),
                    &bridge_name,
                )?;

                tracing::info!("Bridge {} is up and configured", bridge_name);
                Ok(())
            })
        })
    }

    /// Allocate an IP for a VM and return the assigned IP.
    pub fn allocate_ip(&self, vm_id: i64) -> Result<String, NetworkError> {
        let bridge_name = self.bridge_name()?;
        let subnet = self.vm_subnet()?;

        // Parse the subnet to get available IP range
        let network: Ipv4Network = subnet.parse()
            .map_err(|e| NetworkError::IpAllocation(format!("invalid subnet: {e}")))?;

        // Get the gateway IP (first host IP, e.g., 172.16.0.1)
        let gateway = network.nth(1).ok_or_else(|| {
            NetworkError::IpAllocation("subnet too small".to_string())
        })?;

        // Get already allocated IPs for this bridge
        let bridge = self.store.get_bridge(&bridge_name)?;
        if bridge.is_none() {
            // Bridge doesn't exist yet, create it
            self.store.create_bridge(
                &bridge_name,
                &subnet,
                &gateway.to_string(),
                &bridge_name,
            )?;
        }

        let allocated = self.store.list_allocated_ips(&bridge_name)?;

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
                    self.store.assign_vm_ip(vm_id, &ip_str, &bridge_name)?;
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
        let bridge_name = self.bridge_name()?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Create tap device via ioctl (tun-tap crate)
                let iface = Iface::without_packet_info(&tap_name, Mode::Tap)
                    .map_err(|e| NetworkError::Tap(format!("failed to create tap device: {e}")))?;

                // Get the actual device name (may differ from requested name)
                let actual_tap_name = iface.name().to_string();
                tracing::info!("Created tap device {} (requested: {})", actual_tap_name, tap_name);

                // Configure tap device with rtnetlink
                let helper = NetlinkHelper::new()?;

                // Get bridge index
                let bridge_index = helper.get_link_index(&bridge_name).await?;

                // Get tap device index (use actual name, not requested)
                let tap_index = helper.get_link_index(&actual_tap_name).await?;

                // Attach tap to bridge
                helper.handle
                    .link()
                    .set(LinkUnspec::new_with_index(tap_index)
                        .append_extra_attribute(LinkAttribute::Controller(bridge_index))
                        .build())
                    .execute()
                    .await
                    .map_err(|e| NetworkError::Tap(format!("failed to attach tap to bridge: {e}")))?;

                tracing::info!("Attached tap {} to bridge {}", actual_tap_name, bridge_name);

                // Isolate tap port — prevents L2 traffic between VMs on the same bridge.
                // Must use set_port() not set() — bridge port config needs RTM_NEWLINK.
                helper.handle
                    .link()
                    .set_port(LinkUnspec::new_with_index(tap_index)
                        .set_port_kind(InfoPortKind::Bridge)
                        .set_port_data(InfoPortData::BridgePort(vec![
                            InfoBridgePort::Isolated(true),
                        ]))
                        .build())
                    .execute()
                    .await
                    .map_err(|e| NetworkError::Tap(format!("failed to set bridge port isolation: {e}")))?;

                tracing::info!("Bridge port isolation enabled for tap {}", actual_tap_name);

                // Bring tap up
                helper.handle
                    .link()
                    .set(LinkUnspec::new_with_index(tap_index).up().build())
                    .execute()
                    .await
                    .map_err(|e| NetworkError::Tap(format!("failed to bring tap up: {e}")))?;

                tracing::info!("Tap device {} is up", actual_tap_name);

                // Make tap device persistent so it survives when we drop the iface.
                // This allows Firecracker to attach to the pre-created tap device.
                set_tap_persistent(&iface)
                    .map_err(|e| NetworkError::Tap(format!("failed to set tap persistent: {e}")))?;

                tracing::info!("Tap device {} is now persistent", actual_tap_name);

                // Drop iface - the tap device will persist
                drop(iface);

                Ok(actual_tap_name)
            })
        })
    }

    /// Destroy a tap device and release the VM's IP.
    /// Requires CAP_NET_ADMIN.
    pub fn destroy_tap(&self, vm_id: i64) -> Result<(), NetworkError> {
        let tap_name = format!("tap{}", vm_id);

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let helper = NetlinkHelper::new()?;

                // Get tap device index
                if let Ok(tap_index) = helper.get_link_index(&tap_name).await {
                    // Delete tap device
                    if let Err(e) = helper.handle.link().del(tap_index).execute().await {
                        tracing::warn!("Failed to delete tap device {}: {}", tap_name, e);
                        // Continue to release IP even if tap deletion fails
                    } else {
                        tracing::info!("Deleted tap device {}", tap_name);
                    }
                } else {
                    tracing::warn!("Tap device {} not found, skipping deletion", tap_name);
                }

                // Release IP from database
                self.store.release_vm_ip(vm_id)?;

                Ok(())
            })
        })
    }

    /// Get the gateway IP for the bridge.
    pub fn gateway_ip(&self) -> Result<String, NetworkError> {
        let bridge_name = self.bridge_name()?;
        let bridge = self.store.get_bridge(&bridge_name)?
            .ok_or_else(|| NetworkError::Bridge("bridge not found".to_string()))?;
        Ok(bridge.gateway)
    }

    /// Get DNS servers as a comma-separated string.
    pub fn dns_servers(&self) -> Result<String, NetworkError> {
        let servers = self.get_dns_servers_vec()?;
        Ok(servers.join(","))
    }

    /// Tear down all network state: tap devices on the bridge, nftables rules, and the bridge.
    /// Used by the cleanup endpoint to reset networking without sudo.
    pub fn cleanup_network(&self) -> Result<CleanupReport, NetworkError> {
        let bridge_name = self.bridge_name()?;

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let helper = NetlinkHelper::new()?;
                let mut report = CleanupReport::default();

                // Delete all tap devices attached to the bridge
                let bridge_index = helper.get_link_index(&bridge_name).await.ok();

                if let Some(bridge_idx) = bridge_index {
                    // List all links and find taps mastered to our bridge
                    let mut links = helper.handle.link().get().execute();
                    while let Ok(Some(msg)) = links.try_next().await {
                        let mut name = None;
                        let mut is_our_tap = false;
                        for attr in &msg.attributes {
                            match attr {
                                LinkAttribute::IfName(n) if n.starts_with("tap") => name = Some(n.clone()),
                                LinkAttribute::Controller(idx) if *idx == bridge_idx => is_our_tap = true,
                                _ => {}
                            }
                        }
                        if let (Some(tap_name), true) = (name, is_our_tap) {
                            let tap_idx = msg.header.index;
                            if let Err(e) = helper.handle.link().del(tap_idx).execute().await {
                                tracing::warn!("Failed to delete tap {}: {}", tap_name, e);
                            } else {
                                tracing::info!("Deleted tap device {}", tap_name);
                                report.taps_deleted += 1;
                            }
                        }
                    }

                    // Delete the bridge
                    if let Err(e) = helper.handle.link().del(bridge_idx).execute().await {
                        tracing::warn!("Failed to delete bridge {}: {}", bridge_name, e);
                    } else {
                        tracing::info!("Deleted bridge {}", bridge_name);
                        report.bridge_deleted = true;
                    }
                }

                // Flush nftables table
                report.nftables_flushed = self.flush_nftables().is_ok();

                Ok(report)
            })
        })
    }

    /// Delete the nexus nftables table entirely.
    fn flush_nftables(&self) -> Result<(), NetworkError> {
        let mut batch = nftnl::Batch::new();
        let table = nftnl::Table::new(c"nexus", nftnl::ProtoFamily::Inet);
        batch.add(&table, nftnl::MsgType::Del);
        let finalized = batch.finalize();
        send_nftables_batch(&finalized)
            .map_err(|e| NetworkError::Nftables(format!("failed to flush nftables: {e}")))?;
        tracing::info!("Flushed nftables table nexus");
        Ok(())
    }

    /// Initialize nftables rules for NAT and VM isolation.
    /// Creates the `nexus` table with postrouting (NAT) and forward (filter) chains.
    /// Uses nftnl batch API via netlink (in-process, inherits CAP_NET_ADMIN).
    pub fn init_nftables(&self) -> Result<(), NetworkError> {
        use ipnetwork::IpNetwork;
        use nftnl::{nft_expr, nftnl_sys::libc as nftnl_libc};

        let bridge_name = self.bridge_name()?;
        let subnet = self.vm_subnet()?;

        let network: ipnetwork::Ipv4Network = subnet.parse()
            .map_err(|e| NetworkError::Nftables(format!("invalid subnet: {e}")))?;
        let network = IpNetwork::V4(network);
        let iface_buf = pad_iface_name(&bridge_name);

        let mut batch = nftnl::Batch::new();

        // Table: inet nexus
        let table = nftnl::Table::new(c"nexus", nftnl::ProtoFamily::Inet);
        batch.add(&table, nftnl::MsgType::Add);

        // Chain: postrouting (nat, hook postrouting, prio 100, accept)
        let mut postrouting = nftnl::Chain::new(c"postrouting", &table);
        postrouting.set_type(nftnl::ChainType::Nat);
        postrouting.set_hook(nftnl::Hook::PostRouting, 100);
        postrouting.set_policy(nftnl::Policy::Accept);
        batch.add(&postrouting, nftnl::MsgType::Add);

        // Chain: forward (filter, hook forward, prio 0, drop)
        let mut forward = nftnl::Chain::new(c"forward", &table);
        forward.set_type(nftnl::ChainType::Filter);
        forward.set_hook(nftnl::Hook::Forward, 0);
        forward.set_policy(nftnl::Policy::Drop);
        batch.add(&forward, nftnl::MsgType::Add);

        // Rule 1 (postrouting): ip saddr in subnet, oifname != bridge → masquerade
        let mut masq_rule = nftnl::Rule::new(&postrouting);
        masq_rule.add_expr(&nft_expr!(meta nfproto));
        masq_rule.add_expr(&nft_expr!(cmp == nftnl_libc::NFPROTO_IPV4 as u8));
        masq_rule.add_expr(&nft_expr!(payload ipv4 saddr));
        masq_rule.add_expr(&nft_expr!(bitwise mask network.mask(), xor 0u32));
        masq_rule.add_expr(&nft_expr!(cmp == network.ip()));
        masq_rule.add_expr(&nft_expr!(meta oifname));
        masq_rule.add_expr(&nft_expr!(cmp != iface_buf.as_slice()));
        masq_rule.add_expr(&nft_expr!(masquerade));
        batch.add(&masq_rule, nftnl::MsgType::Add);

        // Rule 2 (forward): ct state established,related → accept
        let mut est_rule = nftnl::Rule::new(&forward);
        est_rule.add_expr(&nft_expr!(ct state));
        // CT state bitmask: established=2, related=4
        est_rule.add_expr(&nft_expr!(bitwise mask 6u32, xor 0u32));
        est_rule.add_expr(&nft_expr!(cmp != 0u32));
        est_rule.add_expr(&nft_expr!(verdict accept));
        batch.add(&est_rule, nftnl::MsgType::Add);

        // Rule 3 (forward): iifname == bridge, oifname != bridge → accept
        let mut fwd_rule = nftnl::Rule::new(&forward);
        fwd_rule.add_expr(&nft_expr!(meta iifname));
        fwd_rule.add_expr(&nft_expr!(cmp == iface_buf.as_slice()));
        fwd_rule.add_expr(&nft_expr!(meta oifname));
        fwd_rule.add_expr(&nft_expr!(cmp != iface_buf.as_slice()));
        fwd_rule.add_expr(&nft_expr!(verdict accept));
        batch.add(&fwd_rule, nftnl::MsgType::Add);

        // TODO: VM-to-VM communication (post-alpha). Same-bridge traffic is switched
        // at L2 and never hits the inet forward chain, so nftables can't filter it.
        // VM isolation is enforced via IFLA_BRPORT_ISOLATED on each tap instead.
        // When we need selective VM-to-VM traffic (work↔service, work↔work), consider
        // nftables bridge family rules or bridge groups/VLANs for fine-grained control.
        //
        // let mut iso_rule = nftnl::Rule::new(&forward);
        // iso_rule.add_expr(&nft_expr!(meta iifname));
        // iso_rule.add_expr(&nft_expr!(cmp == iface_buf.as_slice()));
        // iso_rule.add_expr(&nft_expr!(meta oifname));
        // iso_rule.add_expr(&nft_expr!(cmp == iface_buf.as_slice()));
        // iso_rule.add_expr(&nft_expr!(verdict drop));
        // batch.add(&iso_rule, nftnl::MsgType::Add);

        // Send batch via netlink
        let finalized = batch.finalize();
        send_nftables_batch(&finalized)
            .map_err(|e| NetworkError::Nftables(format!("failed to send nftables batch: {e}")))?;

        tracing::info!("nftables rules initialized for bridge {}", bridge_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;
    use crate::store::traits::VmStore;
    use crate::vm::{CreateVmParams, VmRole};
    use std::sync::Arc;
    use tempfile::tempdir;

    fn test_store() -> SqliteStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("test.db");
        SqliteStore::open_and_init(&db_path).unwrap()
    }

    fn test_service(store: std::sync::Arc<SqliteStore>) -> NetworkService {
        // Update settings to match test expectations
        store.set_setting("bridge_name", "testbr0", "string").unwrap();
        store.set_setting("vm_subnet", "192.168.100.0/24", "string").unwrap();
        store.set_setting("dns_servers", r#"{"version": 1, "servers": ["1.1.1.1"]}"#, "json").unwrap();

        NetworkService::new(
            store.clone(),
            store.clone(), // StateStore implements both NetworkStore and SettingsStore
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
        let store = Arc::new(test_store());
        let service = test_service(store.clone());

        assert_eq!(service.dns_servers().unwrap(), "1.1.1.1");
    }

}
