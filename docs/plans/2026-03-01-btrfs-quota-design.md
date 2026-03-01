# Design: pkg/btrfs Quota Extension

## Context

Extends the existing `pkg/btrfs` package with btrfs qgroup quota support for
per-agent disk limits on containerd's btrfs snapshotter. Each agent VM's writable
layer is a btrfs subvolume; quotas cap how much disk each agent can consume on a
shared EBS volume.

All qgroup ioctls require `CAP_SYS_ADMIN`.

## API

```go
func EnableQuota(path string) error
func SetQuota(path string, maxBytes uint64) error
func GetQuotaUsage(path string) (QuotaUsage, error)

type QuotaUsage struct {
    Referenced    uint64 // total bytes referenced by this subvolume
    Exclusive     uint64 // bytes exclusive to this subvolume (not shared via CoW)
    MaxReferenced uint64 // quota limit (0 = unlimited)
    MaxExclusive  uint64 // exclusive limit (0 = unlimited)
}

var ErrQuotaNotEnabled = errors.New("btrfs: quotas not enabled")
```

- **EnableQuota**: `BTRFS_IOC_QUOTA_CTL` with `cmd=1`. Idempotent (EEXIST → nil).
- **SetQuota**: `BTRFS_IOC_QGROUP_LIMIT` with `qgroupid=0` (auto-detect from fd).
  Pass `maxBytes=0` to clear the limit (`max_rfer = ^uint64(0)`).
- **GetQuotaUsage**: `BTRFS_IOC_INO_LOOKUP` to get subvolume ID, then
  `BTRFS_IOC_TREE_SEARCH` on quota tree for info (type 242) and limit (type 244).

## Internals

### New ioctl constants

| Ioctl | Hex | Nr | Struct size |
|-------|-----|----|-------------|
| `BTRFS_IOC_QUOTA_CTL` | `0xC0109428` | 40 | 16 bytes |
| `BTRFS_IOC_QGROUP_LIMIT` | `0x8030942B` | 43 | 48 bytes |
| `BTRFS_IOC_TREE_SEARCH` | `0xD0009411` | 17 | 4096 bytes |
| `BTRFS_IOC_INO_LOOKUP` | `0xD0009412` | 18 | 4096 bytes |

### New structs

```go
type ioctlQuotaCtlArgs struct {    // 16 bytes
    Cmd    uint64
    Status uint64
}

type ioctlQgroupLimitArgs struct {  // 48 bytes
    Qgroupid uint64
    Lim      qgroupLimit
}

type qgroupLimit struct {           // 40 bytes
    Flags   uint64
    MaxRfer uint64
    MaxExcl uint64
    RsvRfer uint64
    RsvExcl uint64
}

type ioctlSearchArgs struct {       // 4096 bytes
    Key searchKey
    Buf [3992]byte
}

type searchKey struct {             // 104 bytes
    TreeID       uint64
    MinObjectid  uint64
    MaxObjectid  uint64
    MinOffset    uint64
    MaxOffset    uint64
    MinTransid   uint64
    MaxTransid   uint64
    MinType      uint32
    MaxType      uint32
    NrItems      uint32
    Unused       uint32
    Unused1      uint64
    Unused2      uint64
    Unused3      uint64
    Unused4      uint64
}

type searchHeader struct {          // 32 bytes
    Transid  uint64
    Objectid uint64
    Offset   uint64
    Type     uint32
    Len      uint32
}

type ioctlInoLookupArgs struct {    // 4096 bytes
    Treeid   uint64
    Objectid uint64
    Name     [4080]byte
}
```

On-disk quota items (little-endian packed, parsed from TREE_SEARCH results):

```go
type qgroupInfoItem struct {        // 40 bytes, LE
    Generation uint64
    Rfer       uint64
    RferCmpr   uint64
    Excl       uint64
    ExclCmpr   uint64
}

type qgroupLimitItem struct {       // 40 bytes, LE
    Flags   uint64
    MaxRfer uint64
    MaxExcl uint64
    RsvRfer uint64
    RsvExcl uint64
}
```

### Key constants

```go
quotaCtlEnable       = uint64(1)
qgroupLimitMaxRfer   = uint64(1 << 0)
quotaTreeObjectid    = uint64(8)
qgroupInfoKey        = uint32(242)
qgroupLimitKey       = uint32(244)
firstFreeObjID       = uint64(256)  // already exists
```

## Testing

Tests require `CAP_SYS_ADMIN` on the test binary. The implementation plan
includes a pause point for the user to set the capability.

### Unit tests
- EnableQuota — enable, verify no error; call again, verify idempotent
- SetQuota — create subvolume, set limit, verify no error
- SetQuota(0) — set then clear limit
- GetQuotaUsage — create subvolume, write data, check Referenced > 0
- GetQuotaUsage with limit — set limit, verify MaxReferenced matches

### E2E tests
- EnableQuota → `btrfs qgroup show` confirms enabled
- SetQuota → `btrfs qgroup show` shows limit
- Write data → GetQuotaUsage shows Referenced increasing
