# Design: pkg/btrfs — Pure Go btrfs ioctl package

## Context

First step of the Nexus Rust-to-Go port. This package wraps the Linux btrfs kernel
ioctls needed for subvolume and snapshot management. It will be reusable across projects
as `github.com/Work-Fort/Nexus/pkg/btrfs`.

Goals: zero CGo, zero external dependencies beyond `golang.org/x/sys/unix`, fully
static-linkable with `CGO_ENABLED=0`.

## API (mirrors libbtrfsutil)

```go
package btrfs

func CreateSubvolume(path string) error
func CreateSnapshot(source, dest string, readOnly bool) error
func DeleteSubvolume(path string) error
func IsSubvolume(path string) (bool, error)
func GetReadOnly(path string) (bool, error)
func SetReadOnly(path string, readOnly bool) error
func IsBtrfs(path string) (bool, error)
```

Path-based API — callers pass filesystem paths, the package handles fd lifecycle
internally. This matches libbtrfsutil's calling convention.

### Errors

```go
var (
    ErrNotBtrfs     = errors.New("btrfs: not a btrfs filesystem")
    ErrNotSubvolume = errors.New("btrfs: not a subvolume")
    ErrExists       = errors.New("btrfs: already exists")
)
```

Ioctl failures wrap errno: `fmt.Errorf("btrfs: create subvolume: %w", errno)`.

## Internals

### ioctls Used

| ioctl | Constant | Used by |
|---|---|---|
| `BTRFS_IOC_SUBVOL_CREATE_V2` | `0x50009418` | `CreateSubvolume` |
| `BTRFS_IOC_SNAP_CREATE_V2` | `0x50009417` | `CreateSnapshot` |
| `BTRFS_IOC_SUBVOL_GETFLAGS` | `0x80089419` | `GetReadOnly` |
| `BTRFS_IOC_SUBVOL_SETFLAGS` | `0x4008941a` | `SetReadOnly` |

### Struct

Single ioctl arg struct (4096 bytes, naturally aligned in Go):

```go
type ioctlVolArgsV2 struct {
    Fd      int64
    Transid uint64
    Flags   uint64
    Unused  [4]uint64
    Name    [4040]byte
}
```

Compile-time size check via `var _ [4096]byte = [unsafe.Sizeof(ioctlVolArgsV2{})]byte{}`.

### fd Handling

- `CreateSubvolume`: open parent dir → ioctl with leaf name
- `CreateSnapshot`: open source subvol + open dest parent dir → ioctl
- `GetReadOnly`/`SetReadOnly`: open subvolume dir → ioctl
- All fds opened with `unix.Open(path, O_RDONLY|O_DIRECTORY, 0)` and closed with
  `unix.Close` (not `os.File` to avoid goroutine pinning)

### DeleteSubvolume

VFS-based (same as Rust impl and containers/storage):
1. `GetReadOnly` — if true, `SetReadOnly(false)`
2. `os.ReadDir` + `os.RemoveAll` each entry
3. `os.Remove` (rmdir) on the empty subvolume

No `BTRFS_IOC_SNAP_DESTROY` — this requires `CAP_SYS_ADMIN`. VFS rmdir on an empty
subvolume works unprivileged since kernel 4.18.

## File Layout

```
pkg/btrfs/
  btrfs.go       — public API
  ioctl.go       — ioctl constants, struct, syscall wrapper
  btrfs_test.go  — unit tests (assertions via package's own functions)
  e2e_test.go    — e2e tests (assertions via btrfs CLI as ground truth)
```

## Testing

### Unit tests (btrfs_test.go)

Assertions use the package's own API. Skip if not on btrfs.

Test cases:
- CreateSubvolume — create, verify IsSubvolume returns true
- CreateSubvolume already exists — returns ErrExists
- CreateSnapshot — writable snapshot, verify both exist
- CreateSnapshot read-only — verify GetReadOnly returns true
- DeleteSubvolume — create then delete, verify gone
- DeleteSubvolume read-only — tests clear-ro-then-rmdir path
- GetReadOnly / SetReadOnly — toggle flag, verify each state
- IsSubvolume — true for subvolume, false for regular directory
- IsBtrfs — true on btrfs filesystem
- CreateSubvolume on non-btrfs — returns ErrNotBtrfs

### E2E tests (e2e_test.go)

Assertions shell out to `btrfs` CLI as an independent oracle. Skip if not on btrfs or
if `btrfs` binary not in PATH.

Test cases:
- Create subvolume → `btrfs subvolume show <path>` exits 0
- Set read-only → `btrfs property get <path> ro` shows `ro=true`
- Clear read-only → `btrfs property get <path> ro` shows `ro=false`
- Create snapshot → `btrfs subvolume show <path>` shows parent UUID matching source UUID
- Delete subvolume → `btrfs subvolume show <path>` fails (exit non-zero)
- Create with content → snapshot preserves files (write file, snapshot, verify via ls)

## Verification

```bash
# Run all tests (must be on btrfs filesystem, btrfs CLI in PATH)
go test -v -race ./pkg/btrfs/

# Run only unit tests (btrfs filesystem required, CLI not required)
go test -v -race -run 'Test[^E]' ./pkg/btrfs/

# Run only e2e tests
go test -v -race -run 'TestE2E' ./pkg/btrfs/
```
