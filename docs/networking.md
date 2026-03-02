# Networking

## Architecture

Nexus uses CNI (Container Network Interface) plugins for VM networking. Each
VM gets its own network namespace with a veth pair connecting it to a shared
bridge on the host.

```
 Host                          VM netns
┌─────────────────────┐      ┌──────────────┐
│  nexus0 (bridge)    │      │              │
│  172.16.0.1/12      │      │  eth0        │
│       │             │      │  172.16.0.x  │
│    veth-host-side ──┼──────┼─ veth-vm     │
│       │             │      │              │
│  iptables MASQ      │      └──────────────┘
│  (ipMasq: true)     │
└─────────────────────┘
```

### Components

| Binary | Capabilities | Purpose |
|--------|-------------|---------|
| `nexus` | None | Daemon — orchestrates networking via helper binaries |
| `nexus-netns` | `CAP_SYS_ADMIN` | Creates/deletes persistent network namespaces (unshare + bind mount) |
| `nexus-cni-exec` | `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` | Multi-call wrapper that execs CNI plugins with elevated caps |

`nexus` itself runs unprivileged. All privileged operations are delegated to
minimal helper binaries with only the capabilities they need.

### How CNI plugin execution works

CNI plugins in `/opt/cni/bin` (e.g., `bridge`, `host-local`) require
capabilities to configure network interfaces. Nexus solves this without
running as root:

1. At startup, Nexus creates a temp directory with symlinks for each plugin
   (e.g., `bridge` → `nexus-cni-exec`)
2. When libcni invokes a plugin, it follows the symlink to `nexus-cni-exec`
3. `nexus-cni-exec` reads `argv[0]` to determine the real plugin name
4. It raises `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` as ambient capabilities
5. It execs the real plugin from `/opt/cni/bin` (configurable via
   `NEXUS_CNI_REAL_BIN_DIR`)

### Why libcni instead of go-cni

The `go-cni` library hardcodes its result cache to `/var/lib/cni`, which
requires root. Using `containernetworking/cni/libcni` directly with
`NewCNIConfigWithCacheDir` lets us use a user-writable cache location under
`$XDG_RUNTIME_DIR`.

## CNI Configuration

Nexus generates its own CNI conflist at startup (not read from
`/etc/cni/net.d`). The generated config uses:

- **bridge** plugin — creates `nexus0`, acts as gateway, enables IP masquerading
- **host-local** IPAM — assigns IPs from the configured subnet

```json
{
  "cniVersion": "1.0.0",
  "name": "nexus",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "nexus0",
      "isGateway": true,
      "ipMasq": true,
      "ipam": {
        "type": "host-local",
        "subnet": "172.16.0.0/12",
        "dataDir": "$XDG_RUNTIME_DIR/nexus/netns/.ipam"
      }
    }
  ]
}
```

## VM Lifecycle

### Setup (on VM create)

1. `nexus-netns create <path>` — creates a new network namespace via
   `unshare(CLONE_NEWNET)` and bind-mounts it for persistence
2. `libcni.AddNetworkList` — invokes the bridge plugin chain to create a
   veth pair, attach it to `nexus0`, and assign an IP via host-local IPAM
3. The assigned IP and gateway are stored in the VM record

### Teardown (on VM delete)

1. `libcni.DelNetworkList` — removes veth pair and releases the IP allocation
2. `nexus-netns delete <path>` — unmounts and removes the namespace file

### Reset (on subnet config change)

When the subnet changes (e.g., `10.88.0.0/16` → `172.16.0.0/12`), the
existing bridge retains its old IP and the bridge plugin refuses to
reconfigure it.

```bash
curl -X POST http://127.0.0.1:9600/v1/network/reset
```

This endpoint:
- Refuses if VMs exist (409 Conflict — delete VMs first)
- Deletes the `nexus0` bridge via `nexus-cni-exec delete-bridge nexus0`
- Clears IPAM allocation and CNI cache directories
- Is idempotent (succeeds if bridge already gone)

The next VM creation rebuilds the bridge with the new subnet.

## Requirements

### System dependencies

- CNI plugins installed at `/opt/cni/bin` (bridge, host-local at minimum)
- `ip` command available in PATH (used by `delete-bridge` subcommand)
- IP forwarding enabled: `sysctl net.ipv4.ip_forward=1`

### Capabilities (set via `setcap` or systemd)

```bash
# Run by the dev-setcap-loop.sh script during development:
sudo setcap cap_sys_admin+ep build/nexus-netns
sudo setcap cap_net_admin,cap_sys_admin+ep build/nexus-cni-exec
```

Capabilities must be re-applied after every rebuild. The `scripts/dev-setcap-loop.sh`
script automates this during development:

```bash
sudo scripts/dev-setcap-loop.sh
```

### User-writable directories

Nexus stores networking state under `$XDG_RUNTIME_DIR/nexus/netns/`:

| Directory | Purpose |
|-----------|---------|
| `$XDG_RUNTIME_DIR/nexus/netns/` | Network namespace bind-mount files |
| `$XDG_RUNTIME_DIR/nexus/netns/.ipam/` | host-local IPAM allocation data |
| `$XDG_RUNTIME_DIR/nexus/netns/.cache/` | CNI result cache |

## Configuration

All options can be set via CLI flags, config file (`~/.config/nexus/config.yaml`),
or environment variables (`NEXUS_` prefix).

| Flag | Default | Description |
|------|---------|-------------|
| `--network-enabled` | `true` | Enable CNI networking |
| `--network-subnet` | `172.16.0.0/12` | CIDR subnet for the bridge |
| `--cni-bin-dir` | `/opt/cni/bin` | Directory containing CNI plugins |
| `--netns-helper` | `nexus-netns` | Path to netns helper binary |
| `--cni-exec-bin` | `nexus-cni-exec` | Path to CNI exec wrapper binary |

Config file example:

```yaml
network-enabled: true
network-subnet: "172.16.0.0/12"
cni-bin-dir: "/opt/cni/bin"
netns-helper: "nexus-netns"
cni-exec-bin: "nexus-cni-exec"
```

## Troubleshooting

### Bridge creation fails

- Verify capabilities are set: `getcap build/nexus-cni-exec build/nexus-netns`
- Check that CNI plugins exist: `ls /opt/cni/bin/bridge /opt/cni/bin/host-local`

### VMs can't reach the internet

- Check IP forwarding: `sysctl net.ipv4.ip_forward` (must be `1`)
- Verify the bridge has IP masquerading: `sudo iptables -t nat -L POSTROUTING`

### Stale bridge after subnet change

- Delete all VMs, then `POST /v1/network/reset`
- Or manually: `sudo ip link delete nexus0`

### "netns helper not found" at startup

- Ensure `nexus-netns` is in PATH, or set `--netns-helper` to its absolute path
- When using `mise run`, the `build/` directory is added to PATH automatically
