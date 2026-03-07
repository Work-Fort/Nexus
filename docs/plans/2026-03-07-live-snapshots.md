# Live VM Snapshots — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable point-in-time btrfs COW snapshots of running VMs (drives + rootfs), with rollback, clone, and live export support.

**Architecture:** New `Snapshot` domain entity tracked in SQLite/Postgres. Btrfs `CreateSnapshot` at both layers — drive subvolumes and containerd rootfs. The `Storage` and `Runtime` ports gain snapshot/restore methods. A new `internal/app/snapshot.go` file houses all VMService snapshot logic.

**Tech Stack:** Go, btrfs (existing `pkg/btrfs`), containerd snapshotter, SQLite + Postgres, huma HTTP, mcp-go.

---

### Task 1: Domain Model — Snapshot Entity

**Files:**
- Create: `internal/domain/snapshot.go`
- Modify: `internal/domain/ports.go` (add `SnapshotStore` interface + sentinel error)

**Step 1: Create the Snapshot entity**

Create `internal/domain/snapshot.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import "time"

// Snapshot represents a point-in-time snapshot of a VM's rootfs and drives.
// Snapshots are immutable once created.
type Snapshot struct {
	ID        string
	VMID      string
	Name      string // unique per VM
	CreatedAt time.Time
}
```

**Step 2: Add SnapshotStore port and error sentinel**

In `internal/domain/ports.go`, add after the `TemplateStore` interface (~line 178):

```go
// ErrSnapshotNotSupported is returned when snapshots are attempted on a
// storage backend that does not support them (e.g., non-btrfs).
var ErrSnapshotNotSupported = errors.New("snapshots require btrfs storage")

// SnapshotStore persists snapshot metadata.
type SnapshotStore interface {
	CreateSnapshot(ctx context.Context, s *Snapshot) error
	GetSnapshot(ctx context.Context, id string) (*Snapshot, error)
	GetSnapshotByName(ctx context.Context, vmID, name string) (*Snapshot, error)
	ListSnapshots(ctx context.Context, vmID string) ([]*Snapshot, error)
	DeleteSnapshot(ctx context.Context, id string) error
}
```

**Step 3: Commit**

```bash
git add internal/domain/snapshot.go internal/domain/ports.go
git commit -m "feat(domain): add Snapshot entity and SnapshotStore port"
```

---

### Task 2: Extended Storage and Runtime Ports

**Files:**
- Modify: `internal/domain/ports.go` (extend `Storage` and `Runtime` interfaces)

**Step 1: Extend Storage interface**

In `internal/domain/ports.go`, add two methods to the `Storage` interface (after `ReceiveVolume`, ~line 187):

```go
type Storage interface {
	CreateVolume(ctx context.Context, name string, sizeBytes uint64) (path string, err error)
	DeleteVolume(ctx context.Context, name string) error
	VolumePath(name string) string
	SendVolume(ctx context.Context, name string, w io.Writer) error
	ReceiveVolume(ctx context.Context, name string, r io.Reader) error
	// Snapshot methods
	SnapshotVolume(ctx context.Context, volumeName, snapshotName string) error
	RestoreVolume(ctx context.Context, snapshotName, volumeName string) error
	DeleteVolumeSnapshot(ctx context.Context, snapshotName string) error
	SendVolumeSnapshot(ctx context.Context, snapshotName string, w io.Writer) error
}
```

**Step 2: Extend Runtime interface**

Add three methods to the `Runtime` interface (after `WatchExits`):

```go
	SnapshotRootfs(ctx context.Context, containerID, snapshotName string) error
	RestoreRootfs(ctx context.Context, snapshotName, containerID string) error
	DeleteRootfsSnapshot(ctx context.Context, snapshotName string) error
```

**Step 3: Verify compilation fails**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: FAIL — `BtrfsStorage`, `NoopStorage`, and `Runtime` don't implement the new methods yet. This confirms the interface changes propagate.

**Step 4: Commit**

```bash
git add internal/domain/ports.go
git commit -m "feat(domain): extend Storage and Runtime ports for snapshots"
```

---

### Task 3: Storage Backend — Btrfs Snapshot Methods

**Files:**
- Modify: `internal/infra/storage/btrfs.go` (add 4 methods)
- Modify: `internal/infra/storage/noop.go` (add 4 stub methods returning error)

**Step 1: Implement BtrfsStorage snapshot methods**

In `internal/infra/storage/btrfs.go`, add after `ReceiveVolume` (~line 105):

```go
// SnapshotVolume creates a read-only btrfs snapshot of the named volume.
// Snapshot is stored at basePath/.snapshots/<snapshotName>.
func (s *BtrfsStorage) SnapshotVolume(_ context.Context, volumeName, snapshotName string) error {
	snapshotsDir := filepath.Join(s.basePath, ".snapshots")
	if err := os.MkdirAll(snapshotsDir, 0755); err != nil {
		return fmt.Errorf("create snapshots dir: %w", err)
	}
	src := filepath.Join(s.basePath, volumeName)
	dest := filepath.Join(snapshotsDir, snapshotName)
	if err := btrfs.CreateSnapshot(src, dest, true); err != nil {
		return fmt.Errorf("snapshot volume %s: %w", volumeName, err)
	}
	return nil
}

// RestoreVolume replaces the named volume with a writable copy of the snapshot.
func (s *BtrfsStorage) RestoreVolume(_ context.Context, snapshotName, volumeName string) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	volPath := filepath.Join(s.basePath, volumeName)
	if err := btrfs.DeleteSubvolume(volPath); err != nil {
		return fmt.Errorf("delete volume for restore: %w", err)
	}
	if err := btrfs.CreateSnapshot(snapPath, volPath, false); err != nil {
		return fmt.Errorf("restore volume from snapshot: %w", err)
	}
	return nil
}

// DeleteVolumeSnapshot removes a read-only volume snapshot.
func (s *BtrfsStorage) DeleteVolumeSnapshot(_ context.Context, snapshotName string) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	if err := btrfs.DeleteSubvolume(snapPath); err != nil {
		return fmt.Errorf("delete volume snapshot %s: %w", snapshotName, err)
	}
	return nil
}

// SendVolumeSnapshot writes a btrfs send stream of the named snapshot.
func (s *BtrfsStorage) SendVolumeSnapshot(_ context.Context, snapshotName string, w io.Writer) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	return btrfs.Send(snapPath, w)
}
```

**Step 2: Add NoopStorage stubs**

In `internal/infra/storage/noop.go`, add the 4 methods returning `domain.ErrSnapshotNotSupported`:

```go
func (s *NoopStorage) SnapshotVolume(_ context.Context, _, _ string) error {
	return domain.ErrSnapshotNotSupported
}

func (s *NoopStorage) RestoreVolume(_ context.Context, _, _ string) error {
	return domain.ErrSnapshotNotSupported
}

func (s *NoopStorage) DeleteVolumeSnapshot(_ context.Context, _ string) error {
	return domain.ErrSnapshotNotSupported
}

func (s *NoopStorage) SendVolumeSnapshot(_ context.Context, _ string, _ io.Writer) error {
	return domain.ErrSnapshotNotSupported
}
```

Add the necessary import for `domain` and `io` in `noop.go`.

**Step 3: Verify storage compiles**

Run: `go build ./internal/infra/storage/...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/infra/storage/btrfs.go internal/infra/storage/noop.go
git commit -m "feat(storage): implement btrfs snapshot/restore/delete methods"
```

---

### Task 4: Containerd Runtime — Rootfs Snapshot Methods

**Files:**
- Modify: `internal/infra/containerd/runtime.go` (add 3 methods)

**Step 1: Implement rootfs snapshot methods**

Add after `setSnapshotQuota` (~line 367) in `runtime.go`:

```go
// SnapshotRootfs creates a read-only btrfs snapshot of the container's rootfs
// writable layer. The snapshot is stored at stateDir/snapshots/<snapshotName>.
func (r *Runtime) SnapshotRootfs(ctx context.Context, containerID, snapshotName string) error {
	ctx = r.nsCtx(ctx)
	snapshotter := r.client.SnapshotService(r.snapshotter)

	snapKey := containerID + "-snap"
	mounts, err := snapshotter.Mounts(ctx, snapKey)
	if err != nil {
		return fmt.Errorf("get rootfs mounts for %s: %w", containerID, err)
	}
	if len(mounts) == 0 {
		return fmt.Errorf("no mounts for snapshot %s", snapKey)
	}

	srcPath := mounts[0].Source
	destPath := r.snapshotPath(snapshotName)
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("create rootfs snapshots dir: %w", err)
	}
	if err := btrfs.CreateSnapshot(srcPath, destPath, true); err != nil {
		return fmt.Errorf("snapshot rootfs %s: %w", containerID, err)
	}
	return nil
}

// RestoreRootfs replaces the container's rootfs writable layer with a writable
// copy of the named snapshot. The container must be recreated afterward.
func (r *Runtime) RestoreRootfs(ctx context.Context, snapshotName, containerID string) error {
	ctx = r.nsCtx(ctx)
	snapshotter := r.client.SnapshotService(r.snapshotter)

	snapKey := containerID + "-snap"
	mounts, err := snapshotter.Mounts(ctx, snapKey)
	if err != nil {
		return fmt.Errorf("get rootfs mounts for %s: %w", containerID, err)
	}
	if len(mounts) == 0 {
		return fmt.Errorf("no mounts for snapshot %s", snapKey)
	}

	volPath := mounts[0].Source
	srcSnap := r.snapshotPath(snapshotName)

	if err := btrfs.DeleteSubvolume(volPath); err != nil {
		return fmt.Errorf("delete rootfs for restore: %w", err)
	}
	if err := btrfs.CreateSnapshot(srcSnap, volPath, false); err != nil {
		return fmt.Errorf("restore rootfs from snapshot: %w", err)
	}
	return nil
}

// DeleteRootfsSnapshot removes a rootfs snapshot.
func (r *Runtime) DeleteRootfsSnapshot(_ context.Context, snapshotName string) error {
	snapPath := r.snapshotPath(snapshotName)
	if err := btrfs.DeleteSubvolume(snapPath); err != nil {
		return fmt.Errorf("delete rootfs snapshot %s: %w", snapshotName, err)
	}
	return nil
}

// snapshotPath returns the on-disk path for a named rootfs snapshot.
func (r *Runtime) snapshotPath(snapshotName string) string {
	// Store rootfs snapshots alongside containerd state.
	// The snapshotter's root is typically /var/lib/containerd/io.containerd.snapshotter.v1.btrfs.
	// We store ours in a sibling dir to avoid interfering with containerd.
	return filepath.Join(r.snapshotsDir, snapshotName)
}
```

**Step 2: Add `snapshotsDir` field to Runtime struct and set it in constructor**

In the `Runtime` struct (~line 38), add:
```go
snapshotsDir string
```

In `New()` (~line 46), after setting other fields, compute:
```go
snapshotsDir: filepath.Join(config.GlobalPaths.StateDir, "snapshots"),
```

Add required imports: `"github.com/Work-Fort/Nexus/pkg/btrfs"`, `"github.com/Work-Fort/Nexus/internal/config"`, `"os"`.

**Step 3: Verify compilation**

Run: `go build ./internal/infra/containerd/...`
Expected: PASS (all three new Runtime interface methods satisfied)

**Step 4: Verify full project compiles**

Run: `go build ./...`
Expected: PASS (all interface implementations now complete)

**Step 5: Commit**

```bash
git add internal/infra/containerd/runtime.go
git commit -m "feat(containerd): implement rootfs snapshot/restore/delete methods"
```

---

### Task 5: SQLite SnapshotStore

**Files:**
- Create: `internal/infra/sqlite/migrations/013_snapshots.sql`
- Modify: `internal/infra/sqlite/queries.sql` (add snapshot queries)
- Regenerate: `internal/infra/sqlite/models.go`, `internal/infra/sqlite/queries.sql.go` (via `sqlc generate`)
- Modify: `internal/infra/sqlite/store.go` (implement SnapshotStore interface)

**Step 1: Create migration**

Create `internal/infra/sqlite/migrations/013_snapshots.sql`:

```sql
-- +goose Up
CREATE TABLE snapshots (
    id         TEXT PRIMARY KEY,
    vm_id      TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(vm_id, name)
);

-- +goose Down
DROP TABLE IF EXISTS snapshots;
```

**Step 2: Add sqlc queries**

Append to `internal/infra/sqlite/queries.sql`:

```sql
-- name: InsertSnapshot :exec
INSERT INTO snapshots (id, vm_id, name, created_at) VALUES (?, ?, ?, ?);

-- name: GetSnapshot :one
SELECT id, vm_id, name, created_at FROM snapshots WHERE id = ?;

-- name: GetSnapshotByName :one
SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = ? AND name = ?;

-- name: ListSnapshotsByVM :many
SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = ? ORDER BY created_at;

-- name: DeleteSnapshotByID :exec
DELETE FROM snapshots WHERE id = ?;

-- name: DeleteSnapshotsByVM :exec
DELETE FROM snapshots WHERE vm_id = ?;
```

**Step 3: Regenerate sqlc**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && sqlc generate`
Expected: Regenerates `models.go` (adds `Snapshot` model) and `queries.sql.go` (adds snapshot query functions).

**Step 4: Implement SnapshotStore methods on Store**

In `internal/infra/sqlite/store.go`, add after the last TemplateStore method:

```go
// --- SnapshotStore ---

func (s *Store) CreateSnapshot(ctx context.Context, snap *domain.Snapshot) error {
	return s.q.InsertSnapshot(ctx, InsertSnapshotParams{
		ID:        snap.ID,
		VmID:      snap.VMID,
		Name:      snap.Name,
		CreatedAt: snap.CreatedAt.UTC().Format(time.RFC3339),
	})
}

func (s *Store) GetSnapshot(ctx context.Context, id string) (*domain.Snapshot, error) {
	row, err := s.q.GetSnapshot(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return snapshotFromRow(row), nil
}

func (s *Store) GetSnapshotByName(ctx context.Context, vmID, name string) (*domain.Snapshot, error) {
	row, err := s.q.GetSnapshotByName(ctx, GetSnapshotByNameParams{VmID: vmID, Name: name})
	if err != nil {
		return nil, mapErr(err)
	}
	return snapshotFromRow(row), nil
}

func (s *Store) ListSnapshots(ctx context.Context, vmID string) ([]*domain.Snapshot, error) {
	rows, err := s.q.ListSnapshotsByVM(ctx, vmID)
	if err != nil {
		return nil, err
	}
	result := make([]*domain.Snapshot, len(rows))
	for i, r := range rows {
		result[i] = snapshotFromRow(r)
	}
	return result, nil
}

func (s *Store) DeleteSnapshot(ctx context.Context, id string) error {
	return s.q.DeleteSnapshotByID(ctx, id)
}

func snapshotFromRow(row Snapshot) *domain.Snapshot {
	t, _ := time.Parse(time.RFC3339, row.CreatedAt)
	return &domain.Snapshot{
		ID:        row.ID,
		VMID:      row.VmID,
		Name:      row.Name,
		CreatedAt: t,
	}
}
```

Note: The `snapshotFromRow` helper takes the sqlc-generated `Snapshot` type (which will have `ID`, `VmID`, `Name`, `CreatedAt` string fields). Adjust field names to match what `sqlc generate` produces.

**Step 5: Add compile-time interface check**

In `store.go`, with the other interface checks:

```go
var _ domain.SnapshotStore = (*Store)(nil)
```

**Step 6: Verify compilation and run existing tests**

Run: `go build ./internal/infra/sqlite/... && go test ./internal/infra/sqlite/...`
Expected: PASS

**Step 7: Commit**

```bash
git add internal/infra/sqlite/migrations/013_snapshots.sql internal/infra/sqlite/queries.sql internal/infra/sqlite/models.go internal/infra/sqlite/queries.sql.go internal/infra/sqlite/store.go
git commit -m "feat(sqlite): add snapshots table and SnapshotStore implementation"
```

---

### Task 6: Postgres SnapshotStore

**Files:**
- Create: `internal/infra/postgres/migrations/002_snapshots.sql`
- Modify: `internal/infra/postgres/store.go` (implement SnapshotStore)

**Step 1: Create Postgres migration**

Create `internal/infra/postgres/migrations/002_snapshots.sql`:

```sql
-- +goose Up
CREATE TABLE snapshots (
    id         TEXT PRIMARY KEY,
    vm_id      TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(vm_id, name)
);

-- +goose Down
DROP TABLE IF EXISTS snapshots;
```

**Step 2: Implement SnapshotStore methods**

In `internal/infra/postgres/store.go`, add after the last TemplateStore method:

```go
// --- SnapshotStore ---

func (s *Store) CreateSnapshot(ctx context.Context, snap *domain.Snapshot) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO snapshots (id, vm_id, name, created_at) VALUES ($1, $2, $3, $4)`,
		snap.ID, snap.VMID, snap.Name, snap.CreatedAt)
	return mapErr(err)
}

func (s *Store) GetSnapshot(ctx context.Context, id string) (*domain.Snapshot, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, vm_id, name, created_at FROM snapshots WHERE id = $1`, id)
	return scanSnapshot(row)
}

func (s *Store) GetSnapshotByName(ctx context.Context, vmID, name string) (*domain.Snapshot, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = $1 AND name = $2`,
		vmID, name)
	return scanSnapshot(row)
}

func (s *Store) ListSnapshots(ctx context.Context, vmID string) ([]*domain.Snapshot, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = $1 ORDER BY created_at`,
		vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.Snapshot
	for rows.Next() {
		snap, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, snap)
	}
	return result, rows.Err()
}

func (s *Store) DeleteSnapshot(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM snapshots WHERE id = $1`, id)
	return err
}

func scanSnapshot(row pgx.Row) (*domain.Snapshot, error) {
	var snap domain.Snapshot
	if err := row.Scan(&snap.ID, &snap.VMID, &snap.Name, &snap.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &snap, nil
}
```

Note: `scanSnapshot` needs to accept both `pgx.Row` and `pgx.Rows`. Use `pgx.Row` for single-row; for `ListSnapshots`, scan from `rows` directly since `pgx.Rows` satisfies `pgx.Row`.

**Step 3: Add compile-time interface check**

```go
var _ domain.SnapshotStore = (*Store)(nil)
```

**Step 4: Verify compilation**

Run: `go build ./internal/infra/postgres/...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/infra/postgres/migrations/002_snapshots.sql internal/infra/postgres/store.go
git commit -m "feat(postgres): add snapshots table and SnapshotStore implementation"
```

---

### Task 7: Wire SnapshotStore into infra.Store and daemon

**Files:**
- Modify: `internal/infra/open.go` (add `domain.SnapshotStore` to `Store` interface)
- Modify: `internal/app/vm_service.go` (add `snapshotStore` field and `WithSnapshotStore` option)
- Modify: `cmd/daemon.go` (wire `WithSnapshotStore`)

**Step 1: Add SnapshotStore to infra.Store**

In `internal/infra/open.go`, add `domain.SnapshotStore` to the `Store` interface:

```go
type Store interface {
	domain.VMStore
	domain.DriveStore
	domain.DeviceStore
	domain.TemplateStore
	domain.SnapshotStore
	io.Closer
}
```

**Step 2: Add snapshotStore field and option to VMService**

In `internal/app/vm_service.go`, add to the `VMService` struct (~line 36):

```go
snapshotStore domain.SnapshotStore // nil = snapshots disabled
```

Add the option function after `WithDNS` (~line 99):

```go
// WithSnapshotStore enables snapshot management.
func WithSnapshotStore(ss domain.SnapshotStore) func(*VMService) {
	return func(s *VMService) {
		s.snapshotStore = ss
	}
}
```

**Step 3: Wire in daemon.go**

In `cmd/daemon.go`, after `svcOpts = append(svcOpts, app.WithTemplateStore(store))` (~line 183), add:

```go
svcOpts = append(svcOpts, app.WithSnapshotStore(store))
```

**Step 4: Verify compilation**

Run: `go build ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/infra/open.go internal/app/vm_service.go cmd/daemon.go
git commit -m "feat: wire SnapshotStore into VMService and daemon"
```

---

### Task 8: VMService Snapshot Logic

**Files:**
- Create: `internal/app/snapshot.go`

This is the core application logic. Create a new file to keep it separate from the already-large `vm_service.go`.

**Step 1: Write the failing test**

Create `internal/app/snapshot_test.go` — but first we need to understand the test setup. Check if there are existing VMService tests:

Run: `ls /home/kazw/Work/WorkFort/nexus/lead/internal/app/*_test.go`

If no tests exist, create a minimal test file using mock interfaces. The test should verify:
- `CreateSnapshot` calls storage + runtime snapshot methods and persists metadata
- `RestoreSnapshot` requires stopped VM
- `DeleteSnapshot` cleans up storage + runtime + metadata
- `CloneSnapshot` creates a new VM from snapshot

For now, focus on the implementation. Tests can use the real SQLite store with mock runtime/storage.

**Step 2: Implement snapshot.go**

Create `internal/app/snapshot.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/nxid"
)

// CreateSnapshot creates a point-in-time snapshot of the VM's rootfs and all
// attached drives. The VM may be running (crash-consistent) or stopped.
func (s *VMService) CreateSnapshot(ctx context.Context, vmRef, name string) (*domain.Snapshot, error) {
	if s.snapshotStore == nil {
		return nil, fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(name); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrValidation, err)
	}

	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return nil, err
	}

	snap := &domain.Snapshot{
		ID:        nxid.New(),
		VMID:      vm.ID,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}

	// Snapshot rootfs.
	rootfsSnapName := vm.ID + "@" + name
	if err := s.runtime.SnapshotRootfs(ctx, vm.ID, rootfsSnapName); err != nil {
		return nil, fmt.Errorf("snapshot rootfs: %w", err)
	}

	// Snapshot attached drives.
	if s.driveStore != nil && s.storage != nil {
		drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
			return nil, fmt.Errorf("get drives: %w", err)
		}
		for _, d := range drives {
			driveSnapName := d.Name + "@" + name
			if err := s.storage.SnapshotVolume(ctx, d.Name, driveSnapName); err != nil {
				// Rollback: clean up rootfs and any drive snapshots already taken
				s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
				s.cleanupDriveSnapshots(ctx, drives, name)
				return nil, fmt.Errorf("snapshot drive %s: %w", d.Name, err)
			}
		}
	}

	// Persist metadata.
	if err := s.snapshotStore.CreateSnapshot(ctx, snap); err != nil {
		s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
		s.cleanupAllSnapshots(ctx, vm.ID, name)
		return nil, fmt.Errorf("persist snapshot: %w", err)
	}

	return snap, nil
}

// ListSnapshots returns all snapshots for a VM.
func (s *VMService) ListSnapshots(ctx context.Context, vmRef string) ([]*domain.Snapshot, error) {
	if s.snapshotStore == nil {
		return nil, fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return nil, err
	}
	return s.snapshotStore.ListSnapshots(ctx, vm.ID)
}

// DeleteSnapshot removes a snapshot and its on-disk data.
func (s *VMService) DeleteSnapshot(ctx context.Context, vmRef, snapRef string) error {
	if s.snapshotStore == nil {
		return fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return err
	}
	snap, err := s.resolveSnapshot(ctx, vm.ID, snapRef)
	if err != nil {
		return err
	}

	// Delete rootfs snapshot.
	rootfsSnapName := vm.ID + "@" + snap.Name
	s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck

	// Delete drive snapshots.
	s.cleanupAllSnapshots(ctx, vm.ID, snap.Name)

	// Delete metadata.
	return s.snapshotStore.DeleteSnapshot(ctx, snap.ID)
}

// RestoreSnapshot rolls back a stopped VM to a previous snapshot.
func (s *VMService) RestoreSnapshot(ctx context.Context, vmRef, snapRef string) error {
	if s.snapshotStore == nil {
		return fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("stop VM before restore: %w", domain.ErrInvalidState)
	}
	snap, err := s.resolveSnapshot(ctx, vm.ID, snapRef)
	if err != nil {
		return err
	}

	// Restore rootfs.
	rootfsSnapName := vm.ID + "@" + snap.Name
	if err := s.runtime.RestoreRootfs(ctx, rootfsSnapName, vm.ID); err != nil {
		return fmt.Errorf("restore rootfs: %w", err)
	}

	// Restore drives.
	if s.driveStore != nil && s.storage != nil {
		drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			return fmt.Errorf("get drives: %w", err)
		}
		for _, d := range drives {
			driveSnapName := d.Name + "@" + snap.Name
			if err := s.storage.RestoreVolume(ctx, driveSnapName, d.Name); err != nil {
				return fmt.Errorf("restore drive %s: %w", d.Name, err)
			}
		}
	}

	return nil
}

// CloneSnapshot creates a new VM from a snapshot with new identity and network.
func (s *VMService) CloneSnapshot(ctx context.Context, vmRef, snapRef, newName string) (*domain.VM, error) {
	if s.snapshotStore == nil {
		return nil, fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(newName); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrValidation, err)
	}

	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return nil, err
	}
	snap, err := s.resolveSnapshot(ctx, vm.ID, snapRef)
	if err != nil {
		return nil, err
	}

	// Check name conflict.
	if _, err := s.store.GetByName(ctx, newName); err == nil {
		return nil, fmt.Errorf("VM name %q: %w", newName, domain.ErrAlreadyExists)
	}

	newID := nxid.New()

	// Clone rootfs: create writable snapshot from the read-only one.
	rootfsSnapName := vm.ID + "@" + snap.Name
	newRootfsName := newID + "@clone-rootfs"
	// We need to create a writable btrfs snapshot from the read-only rootfs snapshot
	// and register it with containerd. This is complex — we'll create the new VM
	// using the same image and then replace its rootfs with the snapshot.

	// Step 1: Network setup for new VM.
	netInfo, err := s.network.Setup(ctx, newID)
	if err != nil {
		return nil, fmt.Errorf("setup network: %w", err)
	}

	// Step 2: Create containerd container (pulls image, gets snapshot).
	createOpts := []domain.CreateOpt{}
	if netInfo.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(netInfo.NetNSPath))
	}
	if err := s.runtime.Create(ctx, newID, vm.Image, vm.Runtime, createOpts...); err != nil {
		s.network.Teardown(ctx, newID) //nolint:errcheck
		return nil, fmt.Errorf("create container: %w", err)
	}

	// Step 3: Replace rootfs with snapshot data.
	if err := s.runtime.RestoreRootfs(ctx, rootfsSnapName, newID); err != nil {
		s.runtime.Delete(ctx, newID)    //nolint:errcheck
		s.network.Teardown(ctx, newID)  //nolint:errcheck
		return nil, fmt.Errorf("restore rootfs for clone: %w", err)
	}

	// Step 4: Clone drives.
	var clonedDrives []*domain.Drive
	if s.driveStore != nil && s.storage != nil {
		srcDrives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			s.runtime.Delete(ctx, newID)   //nolint:errcheck
			s.network.Teardown(ctx, newID) //nolint:errcheck
			return nil, fmt.Errorf("get source drives: %w", err)
		}
		for _, d := range srcDrives {
			newDriveName := newName + "-" + d.Name
			driveSnapName := d.Name + "@" + snap.Name
			// Create writable snapshot for the new drive
			if err := s.storage.RestoreVolume(ctx, driveSnapName, newDriveName); err != nil {
				// Rollback cloned drives
				for _, cd := range clonedDrives {
					s.storage.DeleteVolume(ctx, cd.Name) //nolint:errcheck
				}
				s.runtime.Delete(ctx, newID)   //nolint:errcheck
				s.network.Teardown(ctx, newID) //nolint:errcheck
				return nil, fmt.Errorf("clone drive %s: %w", d.Name, err)
			}
			newDrive := &domain.Drive{
				ID:        nxid.New(),
				Name:      newDriveName,
				SizeBytes: d.SizeBytes,
				MountPath: d.MountPath,
				VMID:      newID,
				CreatedAt: time.Now().UTC(),
			}
			if err := s.driveStore.CreateDrive(ctx, newDrive); err != nil {
				s.storage.DeleteVolume(ctx, newDriveName) //nolint:errcheck
				for _, cd := range clonedDrives {
					s.storage.DeleteVolume(ctx, cd.Name) //nolint:errcheck
				}
				s.runtime.Delete(ctx, newID)   //nolint:errcheck
				s.network.Teardown(ctx, newID) //nolint:errcheck
				return nil, fmt.Errorf("persist cloned drive: %w", err)
			}
			clonedDrives = append(clonedDrives, newDrive)
		}
	}

	// Step 5: Create VM record.
	newVM := &domain.VM{
		ID:              newID,
		Name:            newName,
		Image:           vm.Image,
		Runtime:         vm.Runtime,
		State:           domain.VMStateCreated,
		RootSize:        vm.RootSize,
		Shell:           vm.Shell,
		RestartPolicy:   vm.RestartPolicy,
		RestartStrategy: vm.RestartStrategy,
		Init:            vm.Init,
		TemplateID:      vm.TemplateID,
		CreatedAt:       time.Now().UTC(),
	}
	if netInfo.IP != "" {
		newVM.IP = netInfo.IP
		newVM.Gateway = netInfo.Gateway
		newVM.NetNSPath = netInfo.NetNSPath
	}

	if err := s.store.Create(ctx, newVM); err != nil {
		for _, cd := range clonedDrives {
			s.storage.DeleteVolume(ctx, cd.Name) //nolint:errcheck
		}
		s.runtime.Delete(ctx, newID)   //nolint:errcheck
		s.network.Teardown(ctx, newID) //nolint:errcheck
		return nil, fmt.Errorf("persist cloned VM: %w", err)
	}

	// Step 6: Recreate container with drives mounted.
	if len(clonedDrives) > 0 {
		if err := s.recreateContainer(ctx, newVM); err != nil {
			// Best-effort cleanup — VM record exists, user can delete manually
			return newVM, fmt.Errorf("recreate container with drives: %w", err)
		}
	}

	// Step 7: DNS record for clone.
	if s.dns != nil && newVM.IP != "" {
		s.dns.AddRecord(ctx, newVM.Name, newVM.IP) //nolint:errcheck
	}

	return newVM, nil
}

// resolveSnapshot finds a snapshot by ID or name within a VM.
func (s *VMService) resolveSnapshot(ctx context.Context, vmID, ref string) (*domain.Snapshot, error) {
	// Try by ID first.
	snap, err := s.snapshotStore.GetSnapshot(ctx, ref)
	if err == nil && snap.VMID == vmID {
		return snap, nil
	}
	// Try by name.
	snap, err = s.snapshotStore.GetSnapshotByName(ctx, vmID, ref)
	if err != nil {
		return nil, fmt.Errorf("snapshot %q: %w", ref, domain.ErrNotFound)
	}
	return snap, nil
}

// cleanupDriveSnapshots removes drive snapshots for drives that were already
// snapshotted. Used for rollback during CreateSnapshot.
func (s *VMService) cleanupDriveSnapshots(ctx context.Context, drives []*domain.Drive, snapName string) {
	if s.storage == nil {
		return
	}
	for _, d := range drives {
		driveSnapName := d.Name + "@" + snapName
		s.storage.DeleteVolumeSnapshot(ctx, driveSnapName) //nolint:errcheck
	}
}

// cleanupAllSnapshots removes all drive snapshots for a VM snapshot name.
func (s *VMService) cleanupAllSnapshots(ctx context.Context, vmID, snapName string) {
	if s.driveStore == nil || s.storage == nil {
		return
	}
	drives, err := s.driveStore.GetDrivesByVM(ctx, vmID)
	if err != nil {
		return
	}
	s.cleanupDriveSnapshots(ctx, drives, snapName)
}
```

**Step 3: Verify compilation**

Run: `go build ./internal/app/...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/app/snapshot.go
git commit -m "feat(app): implement CreateSnapshot, ListSnapshots, DeleteSnapshot, RestoreSnapshot, CloneSnapshot"
```

---

### Task 9: Export Integration — Live Export via Snapshots

**Files:**
- Modify: `internal/app/backup.go` (update `ExportVM` to support live export)

**Step 1: Update ExportVM signature and logic**

Change `ExportVM` to accept an optional snapshot reference. If the VM is running and no snapshot is specified, create a temp snapshot, export from it, then clean up.

In `internal/app/backup.go`, replace the running-state check (~line 84-86) with:

```go
// If VM is running, create or use a snapshot for export.
if vm.State == domain.VMStateRunning {
	if s.snapshotStore == nil {
		return fmt.Errorf("VM %s is running; stop it or enable snapshots: %w", vm.Name, domain.ErrInvalidState)
	}
	// Create temporary snapshot for export.
	tempSnap, err := s.CreateSnapshot(ctx, ref, fmt.Sprintf("export-temp-%d", time.Now().Unix()))
	if err != nil {
		return fmt.Errorf("create temp snapshot for export: %w", err)
	}
	defer s.DeleteSnapshot(ctx, vm.ID, tempSnap.ID) //nolint:errcheck
	// Export uses snapshot-based send for drives below.
	return s.exportFromSnapshot(ctx, vm, tempSnap, includeDevices, w)
}
```

**Step 2: Add exportFromSnapshot helper**

Add a new method that exports using snapshot data (reads drive snapshots via `SendVolumeSnapshot` instead of `SendVolume`):

```go
func (s *VMService) exportFromSnapshot(ctx context.Context, vm *domain.VM, snap *domain.Snapshot, includeDevices bool, w io.Writer) error {
	// Build manifest (same as regular export).
	manifest := ExportManifest{Version: manifestVersion, VM: ManifestVM{...}}
	// ... (same manifest building logic)

	// Write tar.zst with snapshot-based drive streams.
	// For drives, use storage.SendVolumeSnapshot(driveName+"@"+snap.Name, w)
	// instead of storage.SendVolume(driveName, w).
}
```

The actual implementation reuses the manifest-building code from the existing `ExportVM` and only differs in how drive data is streamed. Factor out the manifest building into a helper if needed, or inline the snapshot-aware path.

**Step 3: Verify compilation**

Run: `go build ./internal/app/...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/app/backup.go
git commit -m "feat(app): support live VM export via temporary snapshots"
```

---

### Task 10: HTTP API — Snapshot Routes

**Files:**
- Modify: `internal/infra/httpapi/handler.go` (add snapshot routes)

**Step 1: Add snapshot route registration**

In `NewHandler()`, add after `registerBackupRoutes`:

```go
registerSnapshotRoutes(api, svc)
```

**Step 2: Implement registerSnapshotRoutes**

Add at the end of `handler.go`:

```go
// --- Snapshot routes ---

type SnapshotOutput struct {
	Body struct {
		ID        string `json:"id"`
		VMID      string `json:"vm_id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
}

type SnapshotListOutput struct {
	Body []struct {
		ID        string `json:"id"`
		VMID      string `json:"vm_id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
}

func registerSnapshotRoutes(api huma.API, svc *app.VMService) {
	// POST /v1/vms/{id}/snapshots
	huma.Register(api, huma.Operation{
		OperationID: "create-snapshot",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/snapshots",
		Summary:     "Create a snapshot of a VM",
		DefaultStatus: http.StatusCreated,
		Tags:        []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Body struct {
			Name string `json:"name" doc:"Snapshot name" minLength:"1"`
		}
	}) (*SnapshotOutput, error) {
		snap, err := svc.CreateSnapshot(ctx, input.ID, input.Body.Name)
		if err != nil {
			return nil, mapDomainError(err)
		}
		out := &SnapshotOutput{}
		out.Body.ID = snap.ID
		out.Body.VMID = snap.VMID
		out.Body.Name = snap.Name
		out.Body.CreatedAt = snap.CreatedAt.Format(time.RFC3339)
		return out, nil
	})

	// GET /v1/vms/{id}/snapshots
	huma.Register(api, huma.Operation{
		OperationID: "list-snapshots",
		Method:      http.MethodGet,
		Path:        "/v1/vms/{id}/snapshots",
		Summary:     "List VM snapshots",
		Tags:        []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID string `path:"id"`
	}) (*SnapshotListOutput, error) {
		snaps, err := svc.ListSnapshots(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		out := &SnapshotListOutput{}
		for _, s := range snaps {
			out.Body = append(out.Body, struct {
				ID        string `json:"id"`
				VMID      string `json:"vm_id"`
				Name      string `json:"name"`
				CreatedAt string `json:"created_at"`
			}{
				ID: s.ID, VMID: s.VMID, Name: s.Name,
				CreatedAt: s.CreatedAt.Format(time.RFC3339),
			})
		}
		return out, nil
	})

	// DELETE /v1/vms/{id}/snapshots/{snap}
	huma.Register(api, huma.Operation{
		OperationID: "delete-snapshot",
		Method:      http.MethodDelete,
		Path:        "/v1/vms/{id}/snapshots/{snap}",
		Summary:     "Delete a snapshot",
		Tags:        []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Snap string `path:"snap"`
	}) (*struct{}, error) {
		if err := svc.DeleteSnapshot(ctx, input.ID, input.Snap); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	// POST /v1/vms/{id}/snapshots/{snap}/restore
	huma.Register(api, huma.Operation{
		OperationID: "restore-snapshot",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/snapshots/{snap}/restore",
		Summary:     "Restore a VM to a snapshot",
		Tags:        []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Snap string `path:"snap"`
	}) (*struct{}, error) {
		if err := svc.RestoreSnapshot(ctx, input.ID, input.Snap); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	// POST /v1/vms/{id}/snapshots/{snap}/clone
	huma.Register(api, huma.Operation{
		OperationID: "clone-snapshot",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/snapshots/{snap}/clone",
		Summary:     "Clone a VM from a snapshot",
		DefaultStatus: http.StatusCreated,
		Tags:        []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Snap string `path:"snap"`
		Body struct {
			Name string `json:"name" doc:"Name for the cloned VM" minLength:"1"`
		}
	}) (*struct{ Body domain.VM }, error) {
		vm, err := svc.CloneSnapshot(ctx, input.ID, input.Snap, input.Body.Name)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &struct{ Body domain.VM }{Body: *vm}, nil
	})
}
```

**Step 3: Verify compilation**

Run: `go build ./internal/infra/httpapi/...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat(httpapi): add snapshot CRUD, restore, and clone routes"
```

---

### Task 11: MCP Tools — Snapshot Tools

**Files:**
- Modify: `internal/infra/mcp/handler.go` (add snapshot tools)

**Step 1: Add snapshot tools registration**

In `NewHandler()`, add the call:

```go
registerSnapshotTools(s, svc)
```

**Step 2: Implement registerSnapshotTools**

Add at end of `handler.go`:

```go
func registerSnapshotTools(s *server.MCPServer, svc *app.VMService) {
	s.AddTool(mcp.NewTool("snapshot_create",
		mcp.WithDescription("Create a point-in-time snapshot of a VM"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("Snapshot name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef := requireString(req, "vm_id")
		name := requireString(req, "name")
		snap, err := svc.CreateSnapshot(ctx, vmRef, name)
		if err != nil {
			return errResult(err), nil
		}
		return jsonResult(snap)
	})

	s.AddTool(mcp.NewTool("snapshot_list",
		mcp.WithDescription("List snapshots for a VM"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef := requireString(req, "vm_id")
		snaps, err := svc.ListSnapshots(ctx, vmRef)
		if err != nil {
			return errResult(err), nil
		}
		return jsonResult(snaps)
	})

	s.AddTool(mcp.NewTool("snapshot_delete",
		mcp.WithDescription("Delete a VM snapshot"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("Snapshot ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef := requireString(req, "vm_id")
		snapRef := requireString(req, "id")
		if err := svc.DeleteSnapshot(ctx, vmRef, snapRef); err != nil {
			return errResult(err), nil
		}
		return jsonResult(map[string]string{"status": "deleted"})
	})

	s.AddTool(mcp.NewTool("snapshot_restore",
		mcp.WithDescription("Restore a stopped VM to a previous snapshot"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("Snapshot ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef := requireString(req, "vm_id")
		snapRef := requireString(req, "id")
		if err := svc.RestoreSnapshot(ctx, vmRef, snapRef); err != nil {
			return errResult(err), nil
		}
		return jsonResult(map[string]string{"status": "restored"})
	})

	s.AddTool(mcp.NewTool("snapshot_clone",
		mcp.WithDescription("Clone a VM from a snapshot"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("Snapshot ID or name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("Name for the new VM"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef := requireString(req, "vm_id")
		snapRef := requireString(req, "id")
		name := requireString(req, "name")
		vm, err := svc.CloneSnapshot(ctx, vmRef, snapRef, name)
		if err != nil {
			return errResult(err), nil
		}
		return jsonResult(vm)
	})
}
```

**Step 3: Verify compilation**

Run: `go build ./internal/infra/mcp/...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/infra/mcp/handler.go
git commit -m "feat(mcp): add snapshot_create, snapshot_list, snapshot_delete, snapshot_restore, snapshot_clone tools"
```

---

### Task 12: VM Deletion — Cascade Snapshot Cleanup

**Files:**
- Modify: `internal/app/vm_service.go` (update `DeleteVM` to clean up snapshots)

**Step 1: Add snapshot cleanup to DeleteVM**

In `DeleteVM` (~line 326 in `vm_service.go`), before deleting the VM from the store, add:

```go
// Clean up all snapshots.
if s.snapshotStore != nil {
	snaps, err := s.snapshotStore.ListSnapshots(ctx, vm.ID)
	if err == nil {
		for _, snap := range snaps {
			rootfsSnapName := vm.ID + "@" + snap.Name
			s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
			s.cleanupAllSnapshots(ctx, vm.ID, snap.Name)
		}
	}
	// DB records cascade-delete via ON DELETE CASCADE.
}
```

**Step 2: Verify compilation**

Run: `go build ./...`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/app/vm_service.go
git commit -m "feat(app): cascade snapshot cleanup on VM deletion"
```

---

### Task 13: Final Build + Manual Smoke Test

**Step 1: Full build**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS — no compilation errors.

**Step 2: Run unit tests**

Run: `go test ./...`
Expected: All existing tests still pass. New snapshot code has no unit tests yet (tested manually via E2E).

**Step 3: Run vet and lint**

Run: `go vet ./...`
Expected: PASS

**Step 4: Manual smoke test (requires btrfs + containerd)**

```bash
# Start daemon
mise run run

# In another terminal:
# Create a VM
curl -X POST localhost:7800/v1/vms -d '{"name":"snap-test","image":"docker.io/library/alpine:latest"}'

# Start it
curl -X POST localhost:7800/v1/vms/snap-test/start

# Create a snapshot (while running!)
curl -X POST localhost:7800/v1/vms/snap-test/snapshots -d '{"name":"before-upgrade"}'

# List snapshots
curl localhost:7800/v1/vms/snap-test/snapshots

# Stop and restore
curl -X POST localhost:7800/v1/vms/snap-test/stop
curl -X POST localhost:7800/v1/vms/snap-test/snapshots/before-upgrade/restore

# Clone
curl -X POST localhost:7800/v1/vms/snap-test/snapshots/before-upgrade/clone -d '{"name":"snap-clone"}'

# Export running VM (live export)
curl -X POST localhost:7800/v1/vms/snap-test/start
curl -X POST localhost:7800/v1/vms/snap-test/export > export.tar.zst

# Cleanup
curl -X DELETE localhost:7800/v1/vms/snap-test/snapshots/before-upgrade
curl -X DELETE localhost:7800/v1/vms/snap-test
curl -X DELETE localhost:7800/v1/vms/snap-clone
```

**Step 5: Commit any fixes from smoke test**

```bash
git add -A
git commit -m "fix: address issues found during snapshot smoke test"
```

---

## Summary

| Task | What | Files |
|------|------|-------|
| 1 | Domain model | `domain/snapshot.go`, `domain/ports.go` |
| 2 | Extended ports | `domain/ports.go` |
| 3 | Btrfs storage methods | `storage/btrfs.go`, `storage/noop.go` |
| 4 | Containerd rootfs methods | `containerd/runtime.go` |
| 5 | SQLite SnapshotStore | `sqlite/migrations/013_snapshots.sql`, `sqlite/queries.sql`, `sqlite/store.go` |
| 6 | Postgres SnapshotStore | `postgres/migrations/002_snapshots.sql`, `postgres/store.go` |
| 7 | Wire into daemon | `infra/open.go`, `app/vm_service.go`, `cmd/daemon.go` |
| 8 | VMService logic | `app/snapshot.go` |
| 9 | Export integration | `app/backup.go` |
| 10 | HTTP routes | `httpapi/handler.go` |
| 11 | MCP tools | `mcp/handler.go` |
| 12 | Cascade delete | `app/vm_service.go` |
| 13 | Build + smoke test | (all) |
