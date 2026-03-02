# Drives — Persistent Data Volumes for VMs

## Context

VMs currently have only ephemeral container storage. The architecture doc
(`docs/architecture.md`) describes a third storage layer: **data volumes** backed
by btrfs subvolumes. These give VMs persistent, quota-able storage that survives
container recreation. The `pkg/btrfs` package already provides unprivileged
subvolume CRUD via pure-Go ioctls.

This plan covers the full drive lifecycle: create, get, list, delete, attach to
VM, detach from VM. Quota enforcement (which requires a privileged helper with
CAP_SYS_ADMIN) is deferred to a follow-up plan — the `size` field is stored as
metadata now and will be enforced later.

## Design Decisions

- **Drives are named, independent resources** — they exist outside any VM, like
  EBS volumes. One drive per VM for now; the schema supports many-to-many later.
- **Attach/detach requires the VM to be stopped** — containerd bakes mounts into
  the OCI spec at container creation time. Attaching a drive means recreating the
  containerd container with the new mount. No hot-plug.
- **Auto-detach on VM delete** — deleting a VM detaches its drive but does not
  delete it. Drives hold persistent data.
- **Caller-specified mount path** — the API caller decides where the drive
  appears inside the VM (e.g. `/data`, `/workspace`).
- **K8s-style size strings** — `1G`, `500M`, `1Ti` etc., parsed to bytes.
  Stored in the database; enforced by btrfs quotas in a future plan.
- **`oci.WithMounts` for both runc and Kata** — the Kata shim translates OCI
  bind mounts to virtio-fs shares transparently.

## Implementation

### 1. Size parsing utility — `pkg/bytesize/bytesize.go`

Parse K8s-style size strings to uint64 bytes:
- Decimal: `K` (10³), `M` (10⁶), `G` (10⁹), `T` (10¹²)
- Binary: `Ki` (2¹⁰), `Mi` (2²⁰), `Gi` (2³⁰), `Ti` (2⁴⁰)
- Plain integers treated as bytes
- Return error for negative, zero, overflow, or unparseable values

### 2. Domain types — `internal/domain/drive.go`

```go
type Drive struct {
    ID        string
    Name      string
    SizeBytes uint64
    MountPath string     // where it mounts inside the VM
    VMID      string     // attached VM ID, empty if detached
    CreatedAt time.Time
}

type CreateDriveParams struct {
    Name      string
    Size      string // "1G", "500Mi", raw bytes
    MountPath string // e.g. "/data"
}
```

### 3. Domain ports — `internal/domain/ports.go`

```go
type DriveStore interface {
    CreateDrive(ctx context.Context, d *Drive) error
    GetDrive(ctx context.Context, id string) (*Drive, error)
    GetDriveByName(ctx context.Context, name string) (*Drive, error)
    ListDrives(ctx context.Context) ([]*Drive, error)
    AttachDrive(ctx context.Context, driveID, vmID string) error
    DetachDrive(ctx context.Context, driveID string) error
    DetachAllDrives(ctx context.Context, vmID string) error
    GetDrivesByVM(ctx context.Context, vmID string) ([]*Drive, error)
    DeleteDrive(ctx context.Context, id string) error
}

type Storage interface {
    CreateVolume(ctx context.Context, name string, sizeBytes uint64) (path string, err error)
    DeleteVolume(ctx context.Context, name string) error
    VolumePath(name string) string
}

var ErrDriveAttached = errors.New("drive is attached to a VM")
```

### 4. Extend `CreateConfig` — `internal/domain/ports.go`

```go
type CreateConfig struct {
    NetNSPath string
    Mounts    []Mount
}

type Mount struct {
    HostPath      string
    ContainerPath string
}

func WithMounts(mounts []Mount) CreateOpt {
    return func(c *CreateConfig) { c.Mounts = mounts }
}
```

### 5. Runtime mounts — `internal/infra/containerd/runtime.go`

In `Create()`, after processing NetNSPath, handle `createCfg.Mounts`:
```go
if len(createCfg.Mounts) > 0 {
    var ociMounts []specs.Mount
    for _, m := range createCfg.Mounts {
        ociMounts = append(ociMounts, specs.Mount{
            Destination: m.ContainerPath,
            Type:        "bind",
            Source:      m.HostPath,
            Options:     []string{"rbind", "rw"},
        })
    }
    specOpts = append(specOpts, oci.WithMounts(ociMounts))
}
```

### 6. SQLite migration — `internal/infra/sqlite/migrations/003_add_drives.sql`

```sql
-- +goose Up
CREATE TABLE drives (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    size_bytes INTEGER NOT NULL,
    mount_path TEXT NOT NULL,
    vm_id      TEXT REFERENCES vms(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_drives_vm_id ON drives(vm_id);

-- +goose Down
DROP INDEX IF EXISTS idx_drives_vm_id;
DROP TABLE IF EXISTS drives;
```

### 7. SQLite queries — `internal/infra/sqlite/queries.sql`

Add drive queries following existing sqlc annotation patterns:
- `InsertDrive :exec`
- `GetDrive :one`
- `GetDriveByName :one`
- `ListDrives :many`
- `AttachDrive :exec` (UPDATE SET vm_id = ? WHERE id = ?)
- `DetachDrive :exec` (UPDATE SET vm_id = NULL WHERE id = ?)
- `DetachAllDrives :exec` (UPDATE SET vm_id = NULL WHERE vm_id = ?)
- `GetDrivesByVM :many` (WHERE vm_id = ?)
- `DeleteDrive :exec`

Then `sqlc generate` to regenerate Go types.

### 8. Store implementation — `internal/infra/sqlite/store.go`

Implement `DriveStore` on the existing `Store` struct (same as VMStore).
Add `driveFromRow` helper mirroring `vmFromRow`.

### 9. Storage adapter — `internal/infra/storage/`

**`btrfs.go`** — `BtrfsStorage` struct:
- `basePath` = configurable drives directory (default: `$XDG_STATE_HOME/nexus/drives`)
- `CreateVolume(name, sizeBytes)` → `btrfs.CreateSubvolume(basePath/name)`, returns path
- `DeleteVolume(name)` → `btrfs.DeleteSubvolume(basePath/name)`
- `VolumePath(name)` → `filepath.Join(basePath, name)`
- Ensures `basePath` parent is btrfs at construction time
- Size is stored in DB only (quota enforcement deferred)

**`noop.go`** — `NoopStorage` for tests:
- `CreateVolume` creates a temp dir, returns path
- `DeleteVolume` removes it
- `VolumePath` returns temp dir path

### 10. Config — `internal/config/config.go`

Add `DefaultDrivesDir` = `""` (auto-detect: `$XDG_STATE_HOME/nexus/drives`).
Add viper default and CLI flag `--drives-dir`.

### 11. App service — `internal/app/vm_service.go`

Add `storage` and `driveStore` fields to `VMService`. Add functional option
`WithStorage(storage, driveStore)`.

New methods on `VMService`:

- **`CreateDrive(ctx, params)`** — parse size, validate name, create btrfs
  subvolume, persist to store
- **`GetDrive(ctx, id)`** — fetch from store
- **`ListDrives(ctx)`** — list all
- **`DeleteDrive(ctx, id)`** — refuse if attached (`ErrDriveAttached`), delete
  subvolume, delete from store
- **`AttachDrive(ctx, driveID, vmID)`** — VM must be stopped, drive must be
  detached, update store, recreate containerd container with drive mount
- **`DetachDrive(ctx, driveID)`** — VM must be stopped, update store, recreate
  containerd container without drive mount

The `recreateContainer` helper:
1. Load VM from store
2. Get all drives attached to this VM (`GetDrivesByVM`)
3. Build `[]domain.Mount` from attached drives
4. `runtime.Delete(ctx, vmID)` — remove old container
5. `runtime.Create(ctx, vmID, image, runtime, WithNetNS(...), WithMounts(...))`
6. Keep VM state as-is (stopped); caller can start after

### 12. HTTP handlers — `internal/infra/httpapi/handler.go`

Routes:
- `POST /v1/drives` — create drive (name, size, mount_path)
- `GET /v1/drives` — list drives
- `GET /v1/drives/{id}` — get drive
- `DELETE /v1/drives/{id}` — delete drive
- `POST /v1/drives/{id}/attach` — body: `{"vm_id": "..."}`
- `POST /v1/drives/{id}/detach` — no body

Response type:
```go
type driveResponse struct {
    ID        string  `json:"id"`
    Name      string  `json:"name"`
    SizeBytes uint64  `json:"size_bytes"`
    MountPath string  `json:"mount_path"`
    VMID      *string `json:"vm_id,omitempty"`
    CreatedAt string  `json:"created_at"`
}
```

Add `ErrDriveAttached` to `mapError` → 409 Conflict.

### 13. Daemon wiring — `cmd/daemon.go`

- Read `--drives-dir` from viper
- Create `BtrfsStorage` (or `NoopStorage` if dir not on btrfs)
- Pass to `VMService` via `WithStorage(...)`
- Store already implements both `VMStore` and `DriveStore`

### 14. Auto-detach on VM delete — `internal/app/vm_service.go`

In `DeleteVM`, before deleting from store:
```go
if s.driveStore != nil {
    s.driveStore.DetachAllDrives(ctx, id)
}
```

## Files Modified

| File | Change |
|------|--------|
| `pkg/bytesize/bytesize.go` | **NEW** — size parser + tests |
| `internal/domain/drive.go` | **NEW** — Drive type, CreateDriveParams |
| `internal/domain/ports.go` | DriveStore + Storage interfaces, Mount type, WithMounts, ErrDriveAttached |
| `internal/infra/sqlite/migrations/003_add_drives.sql` | **NEW** — drives table |
| `internal/infra/sqlite/queries.sql` | Drive queries |
| `internal/infra/sqlite/store.go` | DriveStore impl, driveFromRow |
| `internal/infra/containerd/runtime.go` | Handle Mounts in Create |
| `internal/infra/storage/btrfs.go` | **NEW** — BtrfsStorage adapter |
| `internal/infra/storage/noop.go` | **NEW** — NoopStorage for tests |
| `internal/config/config.go` | DefaultDrivesDir, viper default |
| `internal/app/vm_service.go` | Drive methods, recreateContainer, auto-detach |
| `internal/infra/httpapi/handler.go` | 6 new routes + handlers |
| `cmd/daemon.go` | Storage wiring, --drives-dir flag |

## Verification

1. `go build ./...` — all packages compile
2. `go test ./...` — unit tests pass (bytesize parsing, drive CRUD, attach/detach, auto-detach on VM delete)
3. Build, setcap, start daemon with `--drives-dir` pointing to a btrfs directory
4. `POST /v1/drives` with `{"name":"test-data","size":"1G","mount_path":"/data"}` — 201
5. `POST /v1/vms` to create a VM — 201
6. `POST /v1/drives/{id}/attach` with the VM ID — 200
7. Start VM, exec `ls /data` — mount visible
8. Stop VM, `POST /v1/drives/{id}/detach` — 200
9. Start VM, exec `ls /data` — mount gone
10. Delete VM — drive still exists, detached
11. `DELETE /v1/drives/{id}` — 204
