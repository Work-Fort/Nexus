# Networking Setup

## Architecture

Nexus uses native Linux APIs for network configuration:

- **Bridge management**: rtnetlink crate (RTM_NEWLINK/RTM_DELLINK messages, IP address assignment)
- **Tap device creation**: tun-tap crate (ioctl on `/dev/net/tun`)
- **Tap device configuration**: rtnetlink crate (bridge attachment, link state management)
- **Firewall rules**: nftables JSON API (`nft -j -f`)

All operations except nftables rules are performed in-process without child processes,
ensuring that `CAP_NET_ADMIN` capability is not inherited to external commands.

**Why tun-tap crate instead of rtnetlink for tap creation?**

Linux tap devices MUST be created via `/dev/net/tun` ioctl, not rtnetlink. This is a
kernel requirement documented in the [Linux tuntap documentation](https://docs.kernel.org/networking/tuntap.html).
The tun-tap crate provides a safe Rust wrapper around this ioctl interface. After tap
creation, rtnetlink is used for all configuration operations (bridge attachment, bringing
link up/down, deletion).

## Requirements

Nexus requires `CAP_NET_ADMIN` capability for network bridge and tap device management.
The `nft` command must be available in PATH for firewall rule configuration.

### System Dependencies

- nftables >= 0.9.3 installed and `nft` command available
- Linux kernel with netlink support (all modern kernels)
- Linux kernel with tun module loaded (`modprobe tun` if not built-in)
- No `ip` command required (uses native netlink and ioctl)

### Option 1: setcap (recommended for development)

Grant the capability to the nexusd binary:

```bash
sudo setcap cap_net_admin=+ep ~/.local/bin/nexusd
```

Verify:

```bash
getcap ~/.local/bin/nexusd
# Should output: /home/user/.local/bin/nexusd cap_net_admin=ep
```

**Note:** You must re-run `setcap` after every rebuild of nexusd.

### Option 2: Systemd AmbientCapabilities (recommended for production)

For systemd user services, add `AmbientCapabilities=CAP_NET_ADMIN` to the unit file:

```ini
[Service]
ExecStart=/home/user/.local/bin/nexusd
AmbientCapabilities=CAP_NET_ADMIN
```

Reload systemd and restart the service:

```bash
systemctl --user daemon-reload
systemctl --user restart nexusd
```

### Verification

Check that nftables is installed and meets version requirements:

```bash
nft --version
# Should output: nftables v1.0.0 or higher (need >= 0.9.3)
```

## Network Configuration

Default configuration (`~/.config/nexus/nexus.yaml`):

```yaml
network:
  bridge_name: "nexbr0"
  subnet: "172.16.0.0/12"
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"
```

## Troubleshooting

### Bridge creation fails

- Verify `CAP_NET_ADMIN` is granted (see above)
- Check dmesg for kernel errors: `sudo dmesg | grep nexbr`

### VMs can't access internet

- Verify nftables rules are applied: `sudo nft list ruleset | grep nexus`
- Check IP forwarding is enabled: `sysctl net.ipv4.ip_forward`
- If forwarding is disabled, enable it: `sudo sysctl -w net.ipv4.ip_forward=1`

### DNS not working in VMs

- Check `/etc/resolv.conf` inside the VM: `nexusctl mcp file_read --vm <name> --path /etc/resolv.conf`
- Verify DNS servers are reachable from the VM
