# Live VM Snapshots — Design

## Goal

Enable point-in-time snapshots of running VMs (drives + rootfs) using btrfs
COW snapshots. Snapshots support rollback (restore in-place), cloning (fork to
new VM), and live export (no longer requires stopping the VM).

## Architecture

Btrfs COW snapshots at both layers — data drives and container rootfs. Both
are instant, zero-copy, and safe while the VM is running (crash-consistent,
equivalent to a power failure — journaled guest filesystems recover
automatically).

## Domain Model

New `Snapshot` entity:

```go
type Snapshot struct {
    ID        string
    VMID      string
    Name      string    // unique per VM
    CreatedAt time.Time
}
```

Snapshots are immutable once created. No state machine.

## Storage Layout

### Data Drives

Btrfs subvolumes under `$STATE_DIR/drives/`. Snapshots stored as read-only
subvolumes at:

```
$STATE_DIR/drives/.snapshots/<drive-name>@<snapshot-name>
```

Created via `btrfs.CreateSnapshot(source, dest, readOnly=true)`.

### Container Rootfs

Containerd's btrfs snapshotter manages rootfs as subvolumes. The active
writable layer is named `<vmid>-snap`. We get its path via
`snapshotter.Mounts()`, then snapshot to:

```
$STATE_DIR/snapshots/<vmid>@<snapshot-name>
```

### Restore (Rollback)

Requires VM to be stopped.

1. Delete current drive subvolumes and rootfs writable layer
2. Create new writable snapshots from the saved read-only ones
3. Recreate containerd container pointing at restored rootfs
4. VM is ready to start

### Clone

Works regardless of VM state.

1. Create new writable snapshots from read-only ones with new names
2. Create new VM record (new ID, new name, new network)
3. Create new containerd container
4. New VM is ready to start

### Export Integration

`ExportVM` no longer requires a stopped VM. If a snapshot ref is provided,
exports from that snapshot. If omitted, creates a temporary snapshot, exports
via `btrfs send`, then cleans up the temporary snapshot.

## Interface Changes

### SnapshotStore (new port)

```go
type SnapshotStore interface {
    CreateSnapshot(ctx context.Context, s *Snapshot) error
    GetSnapshot(ctx context.Context, id string) (*Snapshot, error)
    GetSnapshotByName(ctx context.Context, vmID, name string) (*Snapshot, error)
    ListSnapshots(ctx context.Context, vmID string) ([]*Snapshot, error)
    DeleteSnapshot(ctx context.Context, id string) error
}
```

### Storage (extended)

```go
SnapshotVolume(ctx context.Context, volumeName, snapshotName string) error
RestoreVolume(ctx context.Context, snapshotName, volumeName string) error
```

### Runtime (extended)

```go
SnapshotRootfs(ctx context.Context, containerID, snapshotName string) error
RestoreRootfs(ctx context.Context, snapshotName, containerID string) error
DeleteSnapshot(ctx context.Context, snapshotName string) error
```

### VMService methods

```go
CreateSnapshot(ctx context.Context, vmRef, name string) (*Snapshot, error)
ListSnapshots(ctx context.Context, vmRef string) ([]*Snapshot, error)
DeleteSnapshot(ctx context.Context, vmRef, snapRef string) error
RestoreSnapshot(ctx context.Context, vmRef, snapRef string) error
CloneSnapshot(ctx context.Context, vmRef, snapRef, newName string) (*VM, error)
```

## API Endpoints

### HTTP

```
POST   /vms/{id}/snapshots               {name: "before-upgrade"}
GET    /vms/{id}/snapshots
DELETE /vms/{id}/snapshots/{snap}
POST   /vms/{id}/snapshots/{snap}/restore
POST   /vms/{id}/snapshots/{snap}/clone   {name: "my-clone"}
```

### MCP Tools

`snapshot_create`, `snapshot_list`, `snapshot_delete`, `snapshot_restore`,
`snapshot_clone`.

### Export Change

Existing `POST /vms/{id}/export` gains optional `snapshot` query param. If
set, exports from that snapshot. If omitted, creates a temporary snapshot and
exports from it (removing the stopped-VM requirement).

## Error Cases

- Snapshot on VM with noop storage backend → `"snapshots require btrfs"`
- Restore on running VM → `"stop VM before restore"`
- Snapshot name conflict → 409
- Snapshot not found → 404

## Testing

### Unit Tests

- SnapshotStore CRUD (SQLite + Postgres)
- VMService.CreateSnapshot / RestoreSnapshot / CloneSnapshot with mock
  runtime and storage — verify correct calls and ordering
- Restore requires stopped state — verify error on running VM
- Delete cleans up both drive and rootfs snapshots
- Export from snapshot vs. export with temp snapshot

### E2E Tests (btrfs + containerd)

- Create VM → start → create snapshot → verify listed
- Create snapshot → stop → restore → start → verify VM works
- Create snapshot → clone → start clone → verify independent VM
- Create snapshot → delete → verify subvolumes cleaned up
- Export running VM (uses snapshot) → import → verify
