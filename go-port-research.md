# Nexus Go Port Research

## Overview

This document captures the research for porting WorkFort Nexus from Rust to Go. The
primary goals are fully static binaries (CGO_ENABLED=0) and a clean monorepo structure
with reusable packages.

Module path: `github.com/Work-Fort/Nexus`

## Current Rust Architecture

Nexus is a Firecracker microVM orchestrator. Cargo workspace with 6 crates:

| Crate | Role |
|---|---|
| `nexusd` | Daemon (axum HTTP server on 127.0.0.1:9600, MCP JSON-RPC at /mcp) |
| `nexusctl` | CLI (`nxc`) communicating with nexusd via HTTP |
| `nexus-lib` | Core library (all domain logic) |
| `nexus-protocol` | Shared JSON-RPC 2.0 wire types |
| `guest-agent` | In-VM agent (musl static binary, vsock communication) |
| `integration-tests` | Full e2e suite (requires KVM + btrfs + network) |

## btrfs Usage

The btrfs layer is narrow. Only subvolume/snapshot operations are used — no send/receive,
no qgroups, no balance/scrub, no device management.

### Operations (from nexus-lib/src/backend/btrfs.rs)

| Operation | Rust Call | Kernel Mechanism |
|---|---|---|
| Create subvolume | `libbtrfsutil::create_subvolume()` | `BTRFS_IOC_SUBVOL_CREATE_V2` (ioctl 0x50009418) |
| Create snapshot | `libbtrfsutil::CreateSnapshotOptions::new().create()` | `BTRFS_IOC_SNAP_CREATE_V2` (ioctl 0x50009417) |
| Get read-only flag | `libbtrfsutil::subvolume_read_only()` | `BTRFS_IOC_SUBVOL_GETFLAGS` (ioctl 0x80089419) |
| Set read-only flag | `libbtrfsutil::set_subvolume_read_only()` | `BTRFS_IOC_SUBVOL_SETFLAGS` (ioctl 0x4008941a) |
| Check if subvolume | `libbtrfsutil::is_subvolume()` | `stat()` — inode == 256 on btrfs |
| Delete subvolume | VFS-based (rm contents + rmdir) | No ioctl — unprivileged since kernel 4.18 |

### Privilege Model

All operations run fully unprivileged. `BTRFS_IOC_SUBVOL_SETFLAGS` works without
`CAP_SYS_ADMIN` when the calling user owns the subvolume (kernel checks uid match).
The daemon only needs `CAP_NET_ADMIN` for networking.

### ioctl Struct Layouts

Both arg structs are exactly 4096 bytes (kernel enforces via BUILD_BUG_ON):

```c
// btrfs_ioctl_vol_args_v2 — used by all V2 ioctls
struct btrfs_ioctl_vol_args_v2 {
    __s64 fd;           // offset 0,  size 8
    __u64 transid;      // offset 8,  size 8
    __u64 flags;        // offset 16, size 8
    __u64 unused[4];    // offset 24, size 32 (covers qgroup union)
    char  name[4040];   // offset 56, size 4040 (BTRFS_SUBVOL_NAME_MAX + 1)
};                      // total: 4096
```

Go mapping (no packing issues — all fields naturally aligned):

```go
type ioctlVolArgsV2 struct {
    Fd      int64
    Transid uint64
    Flags   uint64
    Unused  [4]uint64
    Name    [4040]byte
}
```

### ioctl Constants

```go
const (
    iocSubvolCreateV2 = 0x50009418 // _IOW(0x94, 24, vol_args_v2)
    iocSnapCreateV2   = 0x50009417 // _IOW(0x94, 23, vol_args_v2)
    iocSubvolGetflags = 0x80089419 // _IOR(0x94, 25, uint64)
    iocSubvolSetflags = 0x4008941a // _IOW(0x94, 26, uint64)

    subvolRdonly   = uint64(1 << 1) // BTRFS_SUBVOL_RDONLY
    superMagic     = 0x9123683e     // BTRFS_SUPER_MAGIC
    firstFreeObjID = 256            // BTRFS_FIRST_FREE_OBJECTID
)
```

## Go Dependency Map (all pure Go, CGO_ENABLED=0)

| Rust Dependency | Go Replacement | Notes |
|---|---|---|
| `libbtrfsutil` | Custom `pkg/btrfs` (~200 LOC) | 3 ioctls + VFS deletion |
| `rusqlite` (bundled) | `modernc.org/sqlite` | Pure Go SQLite transpilation |
| `axum` | `net/http` + `go-chi/chi` | Chi has zero external deps |
| `nftnl` + `mnl` | `google/nftables` | Pure Go netlink, used by Tailscale |
| `rtnetlink` | `vishvananda/netlink` | Used by Docker/K8s CNI |
| `tun-tap` | `golang.org/x/sys/unix` ioctls | ~30 lines |
| `tokio-vsock` | `mdlayher/vsock` | Stable v1, net.Conn compatible |
| `pgp` | `ProtonMail/go-crypto/openpgp` | Maintained fork of x/crypto |
| `xz2` | `ulikunitz/xz` | Pure Go, immune to CVE-2024-3094 |
| `flate2` / `tar` | `compress/gzip` / `archive/tar` | stdlib |
| `nix` (signals) | `os/exec`, `syscall`, `os/signal` | stdlib |
| `include_bytes!` | `//go:embed` | stdlib since Go 1.16 |
| `clap` | `spf13/cobra` + `spf13/viper` | Standard Go CLI stack |
| `reqwest` | `net/http` | stdlib |
| `serde` / `serde_json` | `encoding/json` | stdlib |
| `tracing` | `log/slog` | stdlib since Go 1.21 |
| `uuid` | `google/uuid` | Pure Go |
| `chrono` | `time` | stdlib |
| `tempfile` | `os.MkdirTemp` / `t.TempDir()` | stdlib |
| `dirs` | `os.UserConfigDir()` etc. | stdlib |

## Existing Test Portability

All Rust tests interact through external interfaces (HTTP REST, CLI subprocess, MCP
JSON-RPC, stdio). No test imports internal Rust structs. The `TestDaemon` fixture just
spawns a `nexusd` binary, polls `/v1/health`, and sends SIGTERM on cleanup.

The Go port will have a standalone e2e test harness (modeled on sharkfin's `tests/e2e/`)
that exercises the daemon as a black-box binary. This allows the same test scenarios to
validate both Rust and Go implementations during migration.

## Port Order

1. `pkg/btrfs` — pure Go ioctl wrapper (this is first)
2. E2E test harness for the full daemon
3. Core domain types and SQLite store
4. Backend interface + btrfs implementation
5. Drive/VM/build services
6. HTTP API (nexusd)
7. CLI (nexusctl)
8. Guest agent
9. Full e2e test migration
