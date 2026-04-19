---
type: plan
step: "1"
title: "Nexus CloneDrive — CSI-shaped REST + MCP"
status: approved
assessment_status: complete
provenance:
  source: roadmap
  issue_id: null
  roadmap_step: null
dates:
  created: "2026-04-19"
  approved: "2026-04-19"
  completed: null
related_plans:
  - docs/2026-04-18-vm-pool-and-clone.md
---

# Nexus CloneDrive — CSI-Shaped REST + MCP

**Goal:** Expose a drive-only clone-from-snapshot operation on Nexus
that maps 1:1 to k8s CSI primitives (VolumeSnapshot + PVC clone-from-
snapshot). Flow's `RuntimeDriver.CloneWorkItemVolume` is the consumer;
its k8s impl will use the same wire shape against a k8s API server.

The btrfs primitive `s.storage.SnapshotVolume` already exists. The
related `s.storage.RestoreVolume` does NOT work for a fresh clone
target — it unconditionally deletes the destination subvolume first
(`internal/infra/storage/btrfs.go:170-172` → `pkg/btrfs/btrfs.go:184`
errors with `lstat ... no such file or directory` when the path does
not exist). Because of this, the plan adds a **new primitive**
`Storage.CloneVolume(snapshotName, newVolumeName)` that materialises
a snapshot into a new (non-existent) subvolume *without* the
destructive pre-delete. This same primitive is the right shape for
the latent `CloneSnapshot` defect that `internal/app/snapshot.go:206`
exhibits when a VM has attached drives — a fix the plan calls out
but does not ship (out of scope per the boundary list below).

## Hard architectural constraints

The public API (REST request/response, MCP tool input/output) MUST
use CSI vocabulary, NOT Nexus-internal btrfs terminology:

| Use (CSI shape) | Do NOT expose |
|-----------------|---------------|
| `source_volume_ref` | `subvol`, `parent_subvol_path`, `src_drive_id_or_name` |
| `snapshot_name` (intermediate, optional) | `btrfs_snapshot_id`, `subvol@snap` |
| `name` (new clone drive name) | `clone_path`, `target_subvol` |

This matches `flow/lead/internal/domain/ports.go::CloneWorkItemVolume`
and `flow/lead/internal/domain/types.go::VolumeRef`. The Flow Nexus
driver impl (separate plan) will translate `VolumeRef{Kind: "nexus-
drive", ID: <drive-id>}` to/from these REST/MCP fields.

**`mount_path` is OPTIONAL on the wire**, defaulting to the source
drive's `mount_path` when omitted. This matches Flow's port signature
(`CloneWorkItemVolume(ctx, projectMaster VolumeRef, workItemID string)
(VolumeRef, error)` — no mount-path parameter) and matches CSI: in
k8s, `dataSource` produces a PVC; the mount target is declared on the
consuming Pod, not on the PVC itself. Nexus stores `mount_path` per
drive because attach-time uses it; cloning inherits the source's value
unless the caller overrides.

**Internals stay btrfs.** The wrapper service may name internal
variables `subvolName`, `snapshotName`, etc. Those names are private
to the package. Only the exported surface is CSI-shaped.

**Provenance echo is request-scoped only.** The REST response echoes
`source_volume_ref` (and `snapshot_name` when retained) so the
immediate caller has a complete record. The values are NOT persisted
on `domain.Drive` — `GET /v1/drives/{id}` returns the standard drive
shape only. This is documented in the OpenAPI description for the
endpoint and as a comment in the response struct.

## Scope boundaries

In scope:
1. New `Storage.CloneVolume(snapshotName, newVolumeName)` primitive
   on `domain.Storage`, implemented for `BtrfsStorage` and `NoopStorage`.
2. `CloneDrive` use-case in `internal/app` wrapping
   `s.storage.SnapshotVolume` + `s.storage.CloneVolume` +
   (conditionally) `s.storage.DeleteVolumeSnapshot`.
3. REST endpoint `POST /v1/drives/clone` with CSI request/response shape.
4. MCP tool `drive_clone` with the same input/output as REST.
5. Domain error sentinel additions where needed (none expected — reuse
   `ErrNotFound`, `ErrAlreadyExists`, `ErrValidation`, `ErrInvalidState`).
6. Unit tests for the new app method.
7. E2E tests against the live daemon (SQLite-only — Nexus is single-
   backend per `TOOLING-BASELINE-REMAINING-WORK.md` PG deferral)
   covering REST and MCP.
8. Harness `Client.CloneDrive` (REST) for the e2e tests. MCP e2e tests
   reuse the existing harness `Client.MCPCall` at
   `tests/e2e/harness/harness.go:1247`, which already handles session
   initialization (`Mcp-Session-Id`), the JSON-vs-SSE response framing,
   and notification-vs-result filtering.

Out of scope:
1. Hot drive attach (deferred per umbrella spec).
2. CSI VolumeSnapshot resource as a first-class Nexus entity (the
   intermediate snapshot is implementation detail; the API is "clone
   from a source drive ref" with optional named snapshot reuse).
3. Per-snapshot drive metadata persistence (no `domain.DriveSnapshot`
   table). The intermediate btrfs snapshot lives under
   `<drivesDir>/.snapshots/` and is cleaned up after the clone or
   retained if `snapshot_name` was specified.
4. Persisting source provenance on `domain.Drive` (out — request-
   scoped echo only).
5. Flow's Nexus driver impl that consumes this — separate plan.
6. k8s driver impl — separate future plan.
7. Refactoring `CloneSnapshot` to use the new primitive across the
   board (only the drive-clone path uses it here; the `RestoreVolume`
   call inside `CloneSnapshot` is left untouched, with the existing
   bug noted in Task 1's commit message as a follow-up signal).

## Prerequisites

- `internal/infra/storage/btrfs.go` provides `SnapshotVolume`,
  `DeleteVolumeSnapshot` (verified in source).
- `pkg/btrfs/btrfs.go::CreateSnapshot(source, dest, readOnly bool)` is
  the underlying primitive (verified in source — used by both
  `BtrfsStorage.SnapshotVolume` and `BtrfsStorage.RestoreVolume`).
- `internal/app/vm_service.go::CreateDrive` exists and persists drive
  metadata via `s.driveStore.CreateDrive`.
- `internal/infra/sqlite/store.go` exposes `Open(path string) (*Store,
  error)` and `*Store` implements `domain.DriveStore` alongside
  `domain.VMStore`. In-memory tests use `sqlite.Open(":memory:")`.
- E2E harness pattern `startBtrfsDaemon` in
  `tests/e2e/snapshot_test.go:79` already wires a btrfs-capable
  daemon for snapshot tests.
- `requireBtrfs` skip-guard helper at `tests/e2e/snapshot_test.go:20`
  — reuse it. The clone path uses in-process btrfs ioctls only (no
  shell-out to `nexus-btrfs`), so `requireBtrfsSend` would over-skip.

## Tech stack

Go 1.26 (Nexus root module + nested `tests/e2e` module). No new
dependencies. Existing:
- `github.com/danielgtaylor/huma/v2` for REST.
- `github.com/mark3labs/mcp-go` for MCP.
- `github.com/Work-Fort/Nexus/pkg/btrfs` for the underlying ioctl
  surface.

## Build commands

- `mise run build` — builds nexus binary + helpers.
- `mise run test` — unit tests across the root module.
- `mise run e2e` — e2e tests under `tests/e2e/`.
- Targeted: `go test -run <Name> ./internal/app/...` from repo root for
  unit tests during TDD; `cd tests/e2e && go test -run <Name> .` for
  e2e iterations.

---

## Task Breakdown

### Task 1: Add `CloneVolume` primitive to `domain.Storage`

**Files:**
- Modify: `internal/domain/ports.go` (extend the `Storage` interface
  near line 232)
- Modify: `internal/infra/storage/btrfs.go` (add `CloneVolume` after
  `RestoreVolume` ~line 178)
- Modify: `internal/infra/storage/noop.go` (add `CloneVolume` after
  `RestoreVolume` ~line 59)
- Modify: `internal/infra/storage/btrfs_test.go` (add a unit test that
  proves `CloneVolume` materialises a writable subvolume into a fresh
  path)

**Rationale:** `RestoreVolume` is destructive — it requires the target
to exist so it can delete it before re-creating from a snapshot. That
contract is right for "restore this VM's drive back to snapshot X" and
wrong for "create a new drive that is a CoW copy of snapshot X." A
fresh primitive avoids overloading `RestoreVolume`'s semantics and
also gives `CloneSnapshot` (the whole-VM path) a correct future
migration target. The new method is one ioctl call; cost is trivial.

**Step 1: Write the failing storage unit test**

Append to `internal/infra/storage/btrfs_test.go`:

```go
func TestBtrfsStorage_CloneVolume(t *testing.T) {
	requireBtrfs(t)

	dir := t.TempDir()
	store, err := NewBtrfs(dir)
	if err != nil {
		t.Fatalf("NewBtrfs: %v", err)
	}

	if _, err := store.CreateVolume(context.Background(), "src", 0); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	// Drop a marker file so we can verify CoW semantics.
	if err := os.WriteFile(filepath.Join(dir, "src", "marker"), []byte("hi"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	if err := store.SnapshotVolume(context.Background(), "src", "src@snap-1"); err != nil {
		t.Fatalf("SnapshotVolume: %v", err)
	}

	// CloneVolume materialises src@snap-1 into a brand-new path "clone"
	// without requiring "clone" to exist beforehand.
	if err := store.CloneVolume(context.Background(), "src@snap-1", "clone"); err != nil {
		t.Fatalf("CloneVolume: %v", err)
	}

	// The clone must be a writable subvolume containing the marker.
	clonePath := filepath.Join(dir, "clone")
	got, err := os.ReadFile(filepath.Join(clonePath, "marker"))
	if err != nil {
		t.Fatalf("read clone marker: %v", err)
	}
	if string(got) != "hi" {
		t.Errorf("clone content = %q, want %q", got, "hi")
	}
	ro, err := btrfs.GetReadOnly(clonePath)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if ro {
		t.Errorf("clone must be writable, got read-only")
	}

	t.Cleanup(func() {
		// Reverse order: clone first (a clone of a snapshot), then snapshot, then src.
		_ = btrfs.DeleteSubvolume(clonePath)
		_ = store.DeleteVolumeSnapshot(context.Background(), "src@snap-1")
		_ = store.DeleteVolume(context.Background(), "src")
	})
}
```

**Note on the `requireBtrfs` helper:** `tests/e2e/snapshot_test.go:20`
defines `requireBtrfs` in package `e2e` (unexported), so it cannot be
imported from `internal/infra/storage`. First check whether
`internal/infra/storage/btrfs_test.go` already has its own copy (run
`grep -n "func requireBtrfs" internal/infra/storage/btrfs_test.go`).
If absent, copy the ~10-line helper into `btrfs_test.go`:

```go
const btrfsSuperMagic = 0x9123683e

func requireBtrfs(t *testing.T) {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(".", &st); err != nil {
		t.Skipf("statfs: %v", err)
	}
	if st.Type != btrfsSuperMagic {
		t.Skip("working directory is not on btrfs")
	}
	if _, err := exec.LookPath("btrfs"); err != nil {
		t.Skip("btrfs CLI not in PATH")
	}
}
```

Add the imports `os/exec`, `syscall` to the test file's import block.

**Step 2: Run the test to verify it fails**

Run: `go test -run TestBtrfsStorage_CloneVolume ./internal/infra/storage/...`
Expected: FAIL — `store.CloneVolume undefined`.

**Step 3: Add the interface method**

Modify `internal/domain/ports.go::Storage` (~line 232). Insert one new
method, alphabetically ordered with the existing snapshot ops:

```go
// Storage manages the underlying volume backend (e.g. btrfs subvolumes).
type Storage interface {
	CreateVolume(ctx context.Context, name string, sizeBytes uint64) (path string, err error)
	DeleteVolume(ctx context.Context, name string) error
	VolumePath(name string) string
	SendVolume(ctx context.Context, name string, w io.Writer) error
	ReceiveVolume(ctx context.Context, name string, r io.Reader) error
	SnapshotVolume(ctx context.Context, volumeName, snapshotName string) error
	RestoreVolume(ctx context.Context, snapshotName, volumeName string) error
	// CloneVolume materialises an existing snapshot into a brand-new
	// (non-existent) volume name. Unlike RestoreVolume, the destination
	// MUST NOT exist; the call fails if it does. This is the primitive
	// behind the CSI-shaped CloneDrive operation.
	CloneVolume(ctx context.Context, snapshotName, newVolumeName string) error
	DeleteVolumeSnapshot(ctx context.Context, snapshotName string) error
	SendVolumeSnapshot(ctx context.Context, snapshotName string, w io.Writer) error
}
```

**Step 4: Implement on `BtrfsStorage`**

Add after `RestoreVolume` in `internal/infra/storage/btrfs.go` (~line
178):

```go
// CloneVolume materialises a writable copy of the named snapshot at a
// brand-new volume path. Fails if the destination already exists.
// Unlike RestoreVolume, this is non-destructive — it is the primitive
// behind CSI clone-from-snapshot semantics, where the "data source"
// is a snapshot and the resulting PVC is a fresh volume.
func (s *BtrfsStorage) CloneVolume(_ context.Context, snapshotName, newVolumeName string) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	volPath := filepath.Join(s.basePath, newVolumeName)
	if _, err := os.Stat(volPath); err == nil {
		return fmt.Errorf("clone target %s: %w", newVolumeName, os.ErrExist)
	}
	if err := btrfs.CreateSnapshot(snapPath, volPath, false); err != nil {
		return fmt.Errorf("clone volume %s from %s: %w", newVolumeName, snapshotName, err)
	}
	return nil
}
```

**Step 5: Implement on `NoopStorage`**

Add after `RestoreVolume` in `internal/infra/storage/noop.go` (~line
59):

```go
func (s *NoopStorage) CloneVolume(_ context.Context, _, _ string) error {
	return domain.ErrSnapshotNotSupported
}
```

**Step 6: Run the storage test to verify it passes**

Run: `go test -run TestBtrfsStorage_CloneVolume ./internal/infra/storage/...`
Expected: PASS on btrfs hosts; SKIP on non-btrfs.

Also run: `go build ./...` from repo root to confirm every consumer of
`domain.Storage` (mocks, fakes, real impls) still compiles. If a test
fake implements `Storage` elsewhere, compilation will surface it.

**Step 7: Commit**

```
git commit -m "$(cat <<'EOF'
feat(storage): add CloneVolume primitive for CSI clone-from-snapshot

RestoreVolume(snap, target) requires target to already exist — it
deletes target first, then re-creates it from the snapshot. That is
the right shape for "roll this VM's drive back to a previous
snapshot" but the wrong shape for "create a new drive that is a
copy-on-write copy of an existing snapshot," which is the CSI
clone-from-snapshot operation.

Add CloneVolume(snapshotName, newVolumeName) that materialises a
snapshot into a brand-new (non-existent) subvolume via
btrfs.CreateSnapshot with readOnly=false. Fails if the destination
exists.

This is the primitive behind the upcoming CloneDrive use-case and
is the correct future migration target for CloneSnapshot's drive-
clone loop in internal/app/snapshot.go (a latent defect there is
out of scope for this commit; the broken path is currently never
exercised because every existing CloneSnapshot e2e test runs
against a VM with no attached drives).

Implemented on BtrfsStorage; NoopStorage returns
ErrSnapshotNotSupported.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: App-layer `CloneDrive` use-case

**Depends on:** Task 1 (the new storage primitive).

**Files:**
- Create: `internal/app/drive_clone.go`
- Create: `internal/app/drive_clone_test.go`

**Rationale for file split:** `vm_service.go` is already 1461 lines.
Drive-clone is a distinct CSI-shaped capability with its own tests; a
new file keeps the diff bisectable.

**Step 1: Write the failing unit test**

Create `internal/app/drive_clone_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package app_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
)

// fakeStorage is an in-memory domain.Storage for unit tests. Tracks
// calls so tests can assert the CSI-shaped sequence:
// SnapshotVolume(src, intermediate) -> CloneVolume(intermediate, dst)
// -> DeleteVolumeSnapshot(intermediate) [when retain=false].
type fakeStorage struct {
	volumes   map[string]bool
	snapshots map[string]string // snapshot -> source volume
	calls     []string
	failOn    string // method name to fail on, "" = none
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{
		volumes:   map[string]bool{},
		snapshots: map[string]string{},
	}
}

func (s *fakeStorage) CreateVolume(_ context.Context, name string, _ uint64) (string, error) {
	s.calls = append(s.calls, "CreateVolume:"+name)
	if s.failOn == "CreateVolume" {
		return "", errors.New("synthetic failure")
	}
	s.volumes[name] = true
	return "/fake/" + name, nil
}
func (s *fakeStorage) DeleteVolume(_ context.Context, name string) error {
	s.calls = append(s.calls, "DeleteVolume:"+name)
	delete(s.volumes, name)
	return nil
}
func (s *fakeStorage) VolumePath(name string) string                         { return "/fake/" + name }
func (s *fakeStorage) SendVolume(context.Context, string, io.Writer) error   { return nil }
func (s *fakeStorage) ReceiveVolume(context.Context, string, io.Reader) error { return nil }
func (s *fakeStorage) SnapshotVolume(_ context.Context, vol, snap string) error {
	s.calls = append(s.calls, "SnapshotVolume:"+vol+"->"+snap)
	if s.failOn == "SnapshotVolume" {
		return errors.New("synthetic failure")
	}
	if !s.volumes[vol] {
		return errors.New("source volume not found")
	}
	s.snapshots[snap] = vol
	return nil
}
func (s *fakeStorage) RestoreVolume(_ context.Context, _, _ string) error { return nil }
func (s *fakeStorage) CloneVolume(_ context.Context, snap, vol string) error {
	s.calls = append(s.calls, "CloneVolume:"+snap+"->"+vol)
	if s.failOn == "CloneVolume" {
		return errors.New("synthetic failure")
	}
	if _, ok := s.snapshots[snap]; !ok {
		return errors.New("snapshot not found")
	}
	if s.volumes[vol] {
		return errors.New("clone target already exists")
	}
	s.volumes[vol] = true
	return nil
}
func (s *fakeStorage) DeleteVolumeSnapshot(_ context.Context, snap string) error {
	s.calls = append(s.calls, "DeleteVolumeSnapshot:"+snap)
	delete(s.snapshots, snap)
	return nil
}
func (s *fakeStorage) SendVolumeSnapshot(context.Context, string, io.Writer) error { return nil }

// newCloneTestSvc builds a VMService backed by an in-memory sqlite
// store (which implements domain.DriveStore) and the fakeStorage.
// Returns the service, the fake, the underlying store (so tests can
// AttachDrive directly to exercise the source-attached rejection
// path), and a cleanup hook the test must defer.
func newCloneTestSvc(t *testing.T) (*app.VMService, *fakeStorage, *sqlite.Store, func()) {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	fs := newFakeStorage()
	svc := app.NewVMService(nil, nil, nil, app.WithStorage(store, fs))
	return svc, fs, store, func() { _ = store.Close() }
}

func TestCloneDrive_HappyPath(t *testing.T) {
	svc, fs, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	src, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "project-master", Size: "100Mi", MountPath: "/work",
	})
	if err != nil {
		t.Fatalf("seed source drive: %v", err)
	}

	clone, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: src.Name,
		Name:            "work-item-W1",
	})
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.Name != "work-item-W1" {
		t.Errorf("clone name = %q, want work-item-W1", clone.Name)
	}
	if clone.SizeBytes != src.SizeBytes {
		t.Errorf("clone size = %d, want %d (inherited)", clone.SizeBytes, src.SizeBytes)
	}
	if clone.MountPath != src.MountPath {
		t.Errorf("clone mount = %q, want %q (inherited from source)", clone.MountPath, src.MountPath)
	}
	if clone.VMID != "" {
		t.Errorf("clone must be unattached, got VMID=%q", clone.VMID)
	}

	// Storage call sequence after seed:
	// SnapshotVolume(src->ephemeral) -> CloneVolume(ephemeral->dst) -> DeleteVolumeSnapshot(ephemeral).
	tail := fs.calls[1:] // skip the initial CreateVolume from seed
	if len(tail) != 3 ||
		!strings.HasPrefix(tail[0], "SnapshotVolume:project-master->") ||
		!strings.HasPrefix(tail[1], "CloneVolume:") ||
		!strings.HasPrefix(tail[2], "DeleteVolumeSnapshot:") {
		t.Errorf("clone call sequence wrong: %v", tail)
	}

	got, err := svc.GetDrive(context.Background(), "work-item-W1")
	if err != nil {
		t.Fatalf("GetDrive after clone: %v", err)
	}
	if got.ID != clone.ID {
		t.Errorf("stored clone ID mismatch")
	}
}

func TestCloneDrive_MountPathOverride(t *testing.T) {
	svc, _, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	}); err != nil {
		t.Fatal(err)
	}

	clone, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "dst",
		MountPath:       "/somewhere/else",
	})
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.MountPath != "/somewhere/else" {
		t.Errorf("override mount = %q, want /somewhere/else", clone.MountPath)
	}
}

func TestCloneDrive_RetainSnapshot(t *testing.T) {
	svc, fs, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "dst",
		SnapshotName:    "named-snap-1",
	}); err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}

	// With explicit SnapshotName, the intermediate snapshot is RETAINED.
	for _, c := range fs.calls {
		if strings.HasPrefix(c, "DeleteVolumeSnapshot:") {
			t.Errorf("snapshot must be retained when SnapshotName is set, got: %v", fs.calls)
		}
	}
	if _, ok := fs.snapshots["named-snap-1"]; !ok {
		t.Errorf("named snapshot missing from fake; calls=%v", fs.calls)
	}
}

func TestCloneDrive_SourceNotFound(t *testing.T) {
	svc, _, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	_, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "ghost",
		Name:            "clone",
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCloneDrive_NameConflict(t *testing.T) {
	svc, _, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	for _, n := range []string{"src", "taken"} {
		if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
			Name: n, Size: "10Mi", MountPath: "/m",
		}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}

	_, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "taken",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestCloneDrive_SourceAttached_Rejected(t *testing.T) {
	svc, _, store, cleanup := newCloneTestSvc(t)
	defer cleanup()

	src, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	})
	if err != nil {
		t.Fatal(err)
	}
	// AttachDrive directly via the underlying store — VMService.AttachDrive
	// would require a real VMStore (we passed nil). The CloneDrive code path
	// only inspects src.VMID, which is what AttachDrive sets.
	if err := store.AttachDrive(context.Background(), src.ID, "vm-fake"); err != nil {
		t.Fatal(err)
	}

	_, err = svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "clone",
	})
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}
```

**Step 2: Run the test to verify it fails**

Run: `go test -run TestCloneDrive ./internal/app/...`
Expected: FAIL — `app.CloneDrive` and `app.CloneDriveParams` undefined.

**Step 3: Implement `CloneDrive`**

Create `internal/app/drive_clone.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/nxid"
)

// snapshotNameMax is the maximum allowed length of a generated
// intermediate snapshot name. Btrfs caps subvolume names at 255 bytes
// (BTRFS_SUBVOL_NAME_MAX) — pkg/btrfs.CreateSnapshot enforces this.
// We pick 240 to leave headroom for the "@clone-" prefix and a 26-byte
// nxid suffix without ever provoking ErrNameTooLong from the kernel.
const snapshotNameMax = 240

// CloneDriveParams is the CSI-shaped input for cloning a drive from a
// source volume reference. Maps 1:1 to a k8s PVC-from-VolumeSnapshot
// dataSource:
//
//	apiVersion: v1
//	kind: PersistentVolumeClaim
//	spec:
//	  dataSource:
//	    kind: VolumeSnapshot          // implicit; intermediate
//	    name: <SnapshotName>          // optional; auto-generated when empty
//	  resources:
//	    requests:
//	      storage: <inherited from source>
//
// SourceVolumeRef is the existing drive name or ID to clone from.
// Name is the new drive's name (must be unique; nxid.ValidateName).
// MountPath is OPTIONAL; if empty, the clone inherits the source's
// MountPath. CSI separates volume creation from mount-target
// declaration — Nexus stores MountPath per drive only because the
// attach step uses it.
// SnapshotName is the name of the intermediate VolumeSnapshot. If
// empty, an ephemeral snapshot is created and deleted after the clone.
// If non-empty, the snapshot is retained under that name (CSI
// semantics — caller owns its lifecycle).
type CloneDriveParams struct {
	SourceVolumeRef string
	Name            string
	MountPath       string // optional
	SnapshotName    string // optional
}

// CloneDrive creates a new drive that is a copy-on-write clone of an
// existing source drive. The source must not be attached to a VM. The
// new drive is unattached.
//
// Implementation: SnapshotVolume(src, intermediate) ->
// CloneVolume(intermediate, new) -> [optional] DeleteVolumeSnapshot.
func (s *VMService) CloneDrive(ctx context.Context, params CloneDriveParams) (*domain.Drive, error) {
	if s.storage == nil || s.driveStore == nil {
		return nil, fmt.Errorf("drives not enabled: %w", domain.ErrValidation)
	}
	if params.SourceVolumeRef == "" {
		return nil, fmt.Errorf("source_volume_ref is required: %w", domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(params.Name); err != nil {
		return nil, fmt.Errorf("invalid name: %v: %w", err, domain.ErrValidation)
	}

	src, err := s.driveStore.ResolveDrive(ctx, params.SourceVolumeRef)
	if err != nil {
		return nil, err // store wraps with ErrNotFound
	}
	if src.VMID != "" {
		return nil, fmt.Errorf("source drive %q is attached to VM %s: %w",
			src.Name, src.VMID, domain.ErrInvalidState)
	}

	if existing, err := s.driveStore.GetDriveByName(ctx, params.Name); err == nil && existing != nil {
		return nil, fmt.Errorf("drive name %q: %w", params.Name, domain.ErrAlreadyExists)
	}

	mountPath := params.MountPath
	if mountPath == "" {
		mountPath = src.MountPath
	}

	snapName := params.SnapshotName
	retainSnapshot := snapName != ""
	if !retainSnapshot {
		snapName = generateEphemeralSnapName(src.Name)
	}

	if err := s.storage.SnapshotVolume(ctx, src.Name, snapName); err != nil {
		return nil, fmt.Errorf("snapshot source %s: %w", src.Name, err)
	}

	if err := s.storage.CloneVolume(ctx, snapName, params.Name); err != nil {
		_ = s.storage.DeleteVolumeSnapshot(ctx, snapName)
		return nil, fmt.Errorf("clone into %s: %w", params.Name, err)
	}

	d := &domain.Drive{
		ID:        nxid.New(),
		Name:      params.Name,
		SizeBytes: src.SizeBytes,
		MountPath: mountPath,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.driveStore.CreateDrive(ctx, d); err != nil {
		_ = s.storage.DeleteVolume(ctx, params.Name)
		_ = s.storage.DeleteVolumeSnapshot(ctx, snapName)
		return nil, fmt.Errorf("persist cloned drive: %w", err)
	}

	if !retainSnapshot {
		if err := s.storage.DeleteVolumeSnapshot(ctx, snapName); err != nil {
			// Non-fatal: the clone succeeded. The orphan snapshot will
			// be cleaned up on next btrfs compaction.
			log.Warn("clone: failed to delete intermediate snapshot",
				"snapshot", snapName, "err", err)
		}
	}

	log.Info("drive cloned",
		"id", d.ID, "name", d.Name, "source", src.Name,
		"snapshot_retained", retainSnapshot)
	return d, nil
}

// generateEphemeralSnapName builds an intermediate snapshot name that
// stays inside btrfs's subvolume name cap. Format: "<src>@clone-<nxid>",
// truncating <src> from the right when the total would exceed
// snapshotNameMax. Truncation only affects internal naming — the
// generated name is opaque to callers.
func generateEphemeralSnapName(srcName string) string {
	suffix := "@clone-" + nxid.New()
	maxSrc := snapshotNameMax - len(suffix)
	if maxSrc < 1 {
		// nxid alone exceeds cap; should be unreachable but guard anyway.
		return strings.TrimPrefix(suffix, "@")
	}
	if len(srcName) > maxSrc {
		srcName = srcName[:maxSrc]
	}
	return srcName + suffix
}
```

**Step 4: Run the tests to verify they pass**

Run: `go test -run TestCloneDrive ./internal/app/...`
Expected: PASS for all 6 cases.

If any test fails, fix the implementation — do not weaken assertions.

**Step 5: Commit**

```
git commit -m "$(cat <<'EOF'
feat(app): add CSI-shaped CloneDrive operation

Adds VMService.CloneDrive (and CloneDriveParams) that produces a
new drive as a copy-on-write clone of an existing source drive.
Wraps storage.SnapshotVolume + storage.CloneVolume + an optional
DeleteVolumeSnapshot, in that order, so the wire surface maps 1:1
to a k8s PVC-from-VolumeSnapshot dataSource.

Exported field names use CSI vocabulary: SourceVolumeRef, Name,
SnapshotName, MountPath. MountPath is optional and inherits from
the source when omitted, matching CSI's separation of volume
creation from mount-target declaration. Flow's RuntimeDriver port
(CloneWorkItemVolume) does not take a mount path.

Validation:
- source must exist; ErrNotFound otherwise
- source must not be attached; ErrInvalidState otherwise
- target name must be unique; ErrAlreadyExists otherwise
- empty SnapshotName -> ephemeral intermediate, deleted after
- non-empty SnapshotName -> intermediate retained (CSI semantics)

Ephemeral snapshot names use a length-guarded "<src>@clone-<nxid>"
template that stays inside btrfs's BTRFS_SUBVOL_NAME_MAX cap.

6 unit tests cover happy path, mount_path override, snapshot
retention, source not found, name conflict, attached-source
rejection.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: REST endpoint `POST /v1/drives/clone`

**Depends on:** Task 2 (the app method).

**Files:**
- Modify: `internal/infra/httpapi/handler.go` (add input/output types
  near the existing `CreateDriveInput` ~line 77, register the route in
  `registerDriveRoutes` ~line 850)
- Modify: `internal/infra/httpapi/handler_test.go` (extend `mockStore`
  with `domain.DriveStore` methods, add a route-level integration test
  using the existing `setupHandler` pattern)

**Note on test scaffolding:** the existing `mockStore` in
`handler_test.go` is VM-only. Two options were considered:

a) Extend `mockStore` with `domain.DriveStore` methods (in-memory map).
b) Use `sqlite.Open(":memory:")` for the drive store + a fake
   `domain.Storage`.

**Decision: (a).** It keeps the test independent of any real DB
package and matches the existing handler-test idiom. The added methods
are pure CRUD over a `map[string]*domain.Drive`.

**Step 1: Extend `mockStore` with `domain.DriveStore`**

Update the struct definition near `handler_test.go:23` to add a
`drives` field:

```go
type mockStore struct {
	vms    map[string]*domain.VM
	drives map[string]*domain.Drive
}
```

Update `newMockStore` (line 27):

```go
func newMockStore() *mockStore {
	return &mockStore{
		vms:    make(map[string]*domain.VM),
		drives: make(map[string]*domain.Drive),
	}
}
```

Append the `domain.DriveStore` methods after the existing `Resolve`
method (~line 175):

```go
// --- domain.DriveStore methods ---

func (m *mockStore) CreateDrive(_ context.Context, d *domain.Drive) error {
	if _, ok := m.drives[d.ID]; ok {
		return domain.ErrAlreadyExists
	}
	for _, existing := range m.drives {
		if existing.Name == d.Name {
			return domain.ErrAlreadyExists
		}
	}
	cp := *d
	m.drives[d.ID] = &cp
	return nil
}

func (m *mockStore) GetDrive(_ context.Context, id string) (*domain.Drive, error) {
	d, ok := m.drives[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *d
	return &cp, nil
}

func (m *mockStore) GetDriveByName(_ context.Context, name string) (*domain.Drive, error) {
	for _, d := range m.drives {
		if d.Name == name {
			cp := *d
			return &cp, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockStore) ResolveDrive(ctx context.Context, ref string) (*domain.Drive, error) {
	if d, err := m.GetDrive(ctx, ref); err == nil {
		return d, nil
	}
	return m.GetDriveByName(ctx, ref)
}

func (m *mockStore) ListDrives(_ context.Context) ([]*domain.Drive, error) {
	out := make([]*domain.Drive, 0, len(m.drives))
	for _, d := range m.drives {
		cp := *d
		out = append(out, &cp)
	}
	return out, nil
}

func (m *mockStore) AttachDrive(_ context.Context, driveID, vmID string) error {
	d, ok := m.drives[driveID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = vmID
	return nil
}

func (m *mockStore) DetachDrive(_ context.Context, driveID string) error {
	d, ok := m.drives[driveID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = ""
	return nil
}

func (m *mockStore) DetachAllDrives(_ context.Context, vmID string) error {
	for _, d := range m.drives {
		if d.VMID == vmID {
			d.VMID = ""
		}
	}
	return nil
}

func (m *mockStore) GetDrivesByVM(_ context.Context, vmID string) ([]*domain.Drive, error) {
	var out []*domain.Drive
	for _, d := range m.drives {
		if d.VMID == vmID {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *mockStore) DeleteDrive(_ context.Context, id string) error {
	if _, ok := m.drives[id]; !ok {
		return domain.ErrNotFound
	}
	delete(m.drives, id)
	return nil
}
```

**Step 2: Add `setupHandlerWithStorage` and `handlerFakeStorage`**

Append to `handler_test.go` near the existing `setupHandler` helper
(~line 250):

```go
// setupHandlerWithStorage returns a handler whose VMService has the
// drive-storage path wired (so /v1/drives/clone is routable). The
// storage backend is an in-test fake that mirrors the unit-test
// fakeStorage; the drive store is mockStore (extended above).
func setupHandlerWithStorage(t *testing.T) (http.Handler, *app.VMService, *mockStore) {
	t.Helper()
	store := newMockStore()
	rt := newMockRuntime()
	fs := newHandlerFakeStorage()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
		app.WithStorage(store, fs))
	health := app.NewHealthService()
	health.Start(context.Background())
	return httpapi.NewHandler(svc, health), svc, store
}

func newHandlerFakeStorage() *handlerFakeStorage {
	return &handlerFakeStorage{
		volumes:   map[string]bool{},
		snapshots: map[string]string{},
	}
}

// handlerFakeStorage is a minimal in-memory domain.Storage. It mirrors
// the unit-test fakeStorage in internal/app/drive_clone_test.go but
// lives here so the httpapi package has no dependency on the app-test
// package.
type handlerFakeStorage struct {
	volumes   map[string]bool
	snapshots map[string]string
}

func (s *handlerFakeStorage) CreateVolume(_ context.Context, name string, _ uint64) (string, error) {
	s.volumes[name] = true
	return "/fake/" + name, nil
}
func (s *handlerFakeStorage) DeleteVolume(_ context.Context, name string) error {
	delete(s.volumes, name)
	return nil
}
func (s *handlerFakeStorage) VolumePath(name string) string                         { return "/fake/" + name }
func (s *handlerFakeStorage) SendVolume(context.Context, string, io.Writer) error   { return nil }
func (s *handlerFakeStorage) ReceiveVolume(context.Context, string, io.Reader) error { return nil }
func (s *handlerFakeStorage) SnapshotVolume(_ context.Context, vol, snap string) error {
	if !s.volumes[vol] {
		return errors.New("source volume not found")
	}
	s.snapshots[snap] = vol
	return nil
}
func (s *handlerFakeStorage) RestoreVolume(_ context.Context, _, _ string) error { return nil }
func (s *handlerFakeStorage) CloneVolume(_ context.Context, snap, vol string) error {
	if _, ok := s.snapshots[snap]; !ok {
		return errors.New("snapshot not found")
	}
	if s.volumes[vol] {
		return errors.New("clone target exists")
	}
	s.volumes[vol] = true
	return nil
}
func (s *handlerFakeStorage) DeleteVolumeSnapshot(_ context.Context, snap string) error {
	delete(s.snapshots, snap)
	return nil
}
func (s *handlerFakeStorage) SendVolumeSnapshot(context.Context, string, io.Writer) error {
	return nil
}
```

Add `"errors"` and `"io"` to the test file's import block if not
already present.

**Step 3: Write the failing handler tests**

Append to `handler_test.go`:

```go
func TestCloneDriveEndpoint_Success(t *testing.T) {
	h, svc, _ := setupHandlerWithStorage(t)

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "master", Size: "10Mi", MountPath: "/m",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := doRequest(h, "POST", "/v1/drives/clone", map[string]any{
		"source_volume_ref": "master",
		"name":              "work-1",
		"mount_path":        "/work",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["name"] != "work-1" {
		t.Errorf("name = %v, want work-1", resp["name"])
	}
	if resp["source_volume_ref"] != "master" {
		t.Errorf("source_volume_ref = %v, want master", resp["source_volume_ref"])
	}
	if resp["mount_path"] != "/work" {
		t.Errorf("mount_path = %v, want /work", resp["mount_path"])
	}
}

func TestCloneDriveEndpoint_MountPathInherited(t *testing.T) {
	h, svc, _ := setupHandlerWithStorage(t)

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "master", Size: "10Mi", MountPath: "/inherited",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := doRequest(h, "POST", "/v1/drives/clone", map[string]any{
		"source_volume_ref": "master",
		"name":              "work-1",
		// mount_path omitted
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["mount_path"] != "/inherited" {
		t.Errorf("mount_path = %v, want /inherited (inherited from source)", resp["mount_path"])
	}
}

func TestCloneDriveEndpoint_SourceNotFound(t *testing.T) {
	h, _, _ := setupHandlerWithStorage(t)

	rec := doRequest(h, "POST", "/v1/drives/clone", map[string]any{
		"source_volume_ref": "ghost",
		"name":              "clone",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCloneDriveEndpoint_NameConflict(t *testing.T) {
	h, svc, _ := setupHandlerWithStorage(t)

	for _, n := range []string{"src", "taken"} {
		if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
			Name: n, Size: "10Mi", MountPath: "/m",
		}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}

	rec := doRequest(h, "POST", "/v1/drives/clone", map[string]any{
		"source_volume_ref": "src",
		"name":              "taken",
	})
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCloneDriveEndpoint_SourceAttached(t *testing.T) {
	h, svc, store := setupHandlerWithStorage(t)

	src, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "busy", Size: "10Mi", MountPath: "/m",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := store.AttachDrive(context.Background(), src.ID, "vm-fake"); err != nil {
		t.Fatalf("attach: %v", err)
	}

	rec := doRequest(h, "POST", "/v1/drives/clone", map[string]any{
		"source_volume_ref": "busy",
		"name":              "clone",
	})
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (source attached); body=%s", rec.Code, rec.Body.String())
	}
}
```

**Step 4: Run the tests to verify they fail**

Run: `go test -run TestCloneDriveEndpoint ./internal/infra/httpapi/...`
Expected: FAIL — `404` or "no route matched POST /v1/drives/clone".

**Step 5: Add request/response types and register the route**

Add near the existing `CreateDriveInput` (~line 77) in `handler.go`:

```go
// CloneDriveInput is the CSI-shaped request body for POST /v1/drives/clone.
// Field names mirror k8s PVC dataSource:
//
//	source_volume_ref  -> the existing drive (name or ID) to clone from.
//	name               -> the new drive's name.
//	mount_path         -> optional CSI mount target. When omitted the
//	                     clone inherits the source drive's mount_path
//	                     (CSI separates volume creation from mount-
//	                     target declaration; mount_path is a property
//	                     of the consuming runtime, not the volume).
//	snapshot_name      -> optional named intermediate VolumeSnapshot.
//	                     Omitted = ephemeral, deleted after clone.
type CloneDriveInput struct {
	Body struct {
		SourceVolumeRef string `json:"source_volume_ref" doc:"Source drive ID or name to clone from"`
		Name            string `json:"name" doc:"New drive name"`
		MountPath       string `json:"mount_path,omitempty" doc:"Optional mount path; inherits from source when omitted"`
		SnapshotName    string `json:"snapshot_name,omitempty" doc:"Optional intermediate snapshot name; if set, the snapshot is retained"`
	}
}
```

Add a new response type near `driveResponse` (~line 245):

```go
// cloneDriveResponse extends driveResponse with the CSI provenance
// fields the immediate caller may want to record. Provenance is
// REQUEST-SCOPED ONLY — it is not persisted on domain.Drive, so a
// later GET /v1/drives/{id} returns the standard driveResponse shape
// without these fields. Document the same in the OpenAPI description
// for the route.
type cloneDriveResponse struct {
	ID              string  `json:"id" doc:"Drive ID"`
	Name            string  `json:"name" doc:"Drive name"`
	SizeBytes       uint64  `json:"size_bytes" doc:"Size in bytes (inherited from source)"`
	MountPath       string  `json:"mount_path" doc:"Mount path (inherited from source unless overridden)"`
	VMID            *string `json:"vm_id,omitempty" doc:"Attached VM ID (always nil for fresh clones)"`
	CreatedAt       string  `json:"created_at" doc:"Creation timestamp"`
	SourceVolumeRef string  `json:"source_volume_ref" doc:"Source drive that was cloned (request-scoped echo, not persisted)"`
	SnapshotName    string  `json:"snapshot_name,omitempty" doc:"Retained intermediate snapshot name, if any"`
}

type CloneDriveOutput struct {
	Body cloneDriveResponse
}
```

Register the route at the end of `registerDriveRoutes` (after the
`/v1/drives/{id}/detach` block, ~line 850):

```go
	huma.Register(api, huma.Operation{
		OperationID: "clone-drive",
		Method:      http.MethodPost,
		Path:        "/v1/drives/clone",
		Summary:     "Clone a drive from a source volume",
		Description: "CSI-shaped clone-from-snapshot operation. Maps 1:1 to a k8s " +
			"PersistentVolumeClaim with a VolumeSnapshot dataSource. The source drive " +
			"must be detached. When snapshot_name is set, the intermediate VolumeSnapshot " +
			"is retained (caller-owned lifecycle); when omitted, an ephemeral snapshot " +
			"is created and deleted after the clone completes. The response echoes " +
			"source_volume_ref and (when retained) snapshot_name for the immediate " +
			"caller's bookkeeping; this provenance is NOT persisted, so subsequent " +
			"GET /v1/drives/{id} calls return the standard drive shape only.",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"Drives"},
	}, func(ctx context.Context, input *CloneDriveInput) (*CloneDriveOutput, error) {
		d, err := svc.CloneDrive(ctx, app.CloneDriveParams{
			SourceVolumeRef: input.Body.SourceVolumeRef,
			Name:            input.Body.Name,
			MountPath:       input.Body.MountPath,
			SnapshotName:    input.Body.SnapshotName,
		})
		if err != nil {
			return nil, mapDomainError(err)
		}
		resp := cloneDriveResponse{
			ID:              d.ID,
			Name:            d.Name,
			SizeBytes:       d.SizeBytes,
			MountPath:       d.MountPath,
			CreatedAt:       d.CreatedAt.UTC().Format(timeFormatJSON),
			SourceVolumeRef: input.Body.SourceVolumeRef,
		}
		if input.Body.SnapshotName != "" {
			resp.SnapshotName = input.Body.SnapshotName
		}
		return &CloneDriveOutput{Body: resp}, nil
	})
```

**Step 6: Run the tests to verify they pass**

Run: `go test -run TestCloneDriveEndpoint ./internal/infra/httpapi/...`
Expected: PASS for all five cases (Success → 201, MountPathInherited
→ 201 with `/inherited`, SourceNotFound → 404, NameConflict → 409,
SourceAttached → 409).

**Step 7: Commit**

```
git commit -m "$(cat <<'EOF'
feat(httpapi): expose POST /v1/drives/clone with CSI shape

Wraps the new app.CloneDrive use-case behind a REST endpoint whose
request and response shape map 1:1 to k8s CSI primitives:

  source_volume_ref  <- VolumeSnapshot dataSource
  snapshot_name      <- VolumeSnapshot.metadata.name (optional)
  name               <- PersistentVolumeClaim.metadata.name
  mount_path         <- optional; inherited from source when omitted

This is the wire shape Flow's RuntimeDriver.CloneWorkItemVolume will
target — Nexus today, k8s tomorrow — so the future k8s adapter is a
translation layer rather than a re-architecture.

Status mapping:
  201 Created  - clone succeeded
  400          - missing required field (source_volume_ref/name)
  404          - source drive not found
  409          - target name already exists, or source attached to a VM

Provenance echoed in the response (source_volume_ref, snapshot_name)
is request-scoped only — it is not persisted on domain.Drive. The
OpenAPI description and the response struct comment document this.

Test scaffolding extends the existing mockStore with the
domain.DriveStore methods and adds setupHandlerWithStorage that wires
WithStorage onto the VMService. handlerFakeStorage mirrors the
unit-test fake without depending on the app-test package.

Five handler tests cover: success (with explicit mount_path),
mount_path inheritance, source-not-found, name conflict, and
attached-source rejection (409).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: MCP tool `drive_clone`

**Depends on:** Task 2 (the app method).

**Files:**
- Modify: `internal/infra/mcp/handler.go` (extend `registerDriveTools`,
  which spans ~line 416 to ~line 524 — append the new tool after the
  `drive_detach` block at ~line 523)

**Note on test scaffolding:** `internal/infra/mcp/handler_test.go` is
a 17-line file with one smoke test (`TestNewHandlerNonNil`) — it has
no test seam for invoking individual tools. The mcp-go library wraps
tools behind `server.NewStreamableHTTPServer`, which speaks JSON-RPC
over HTTP; constructing a tool-invocation harness in unit tests would
mean reimplementing the JSON-RPC handshake.

**Decision:** keep the unit-test surface minimal (smoke test only,
unchanged) and exercise `drive_clone` via E2E in Task 6 against the
real daemon's `/mcp` endpoint. The harness gains a small `CallMCPTool`
helper in Task 5.

**Step 1: Register the MCP tool**

Append to `registerDriveTools` (after the `drive_detach` block, ~line
523) in `internal/infra/mcp/handler.go`:

```go
	// drive_clone — CSI-shaped clone-from-snapshot operation.
	s.AddTool(mcp.NewTool("drive_clone",
		mcp.WithDescription("Clone an existing drive into a new drive (CSI VolumeSnapshot + PVC dataSource shape). "+
			"Source must be detached. mount_path is optional — inherits from source when omitted. "+
			"snapshot_name is optional — when set, the intermediate snapshot is retained. "+
			"Usage: drive_clone(source_volume_ref: \"master\", name: \"work-1\")"),
		mcp.WithString("source_volume_ref", mcp.Description("Source drive ID or name to clone from"), mcp.Required()),
		mcp.WithString("name", mcp.Description("New drive name"), mcp.Required()),
		mcp.WithString("mount_path", mcp.Description("Optional mount path; inherits from source when omitted")),
		mcp.WithString("snapshot_name", mcp.Description("Optional intermediate snapshot name; if set, the snapshot is retained")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		src, errRes := requireString(req, "source_volume_ref")
		if errRes != nil {
			return errRes, nil
		}
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}
		mountPath := mcp.ParseString(req, "mount_path", "")
		snapName := mcp.ParseString(req, "snapshot_name", "")

		d, err := svc.CloneDrive(ctx, app.CloneDriveParams{
			SourceVolumeRef: src,
			Name:            name,
			MountPath:       mountPath,
			SnapshotName:    snapName,
		})
		if err != nil {
			return errResult(err)
		}
		// Echo the CSI provenance fields back so the result is
		// self-describing for an MCP caller (e.g., Flow's runtime driver).
		// Provenance is request-scoped only — it is not persisted on
		// domain.Drive.
		out := map[string]any{
			"id":                d.ID,
			"name":              d.Name,
			"size_bytes":        d.SizeBytes,
			"mount_path":        d.MountPath,
			"created_at":        d.CreatedAt,
			"source_volume_ref": src,
		}
		if snapName != "" {
			out["snapshot_name"] = snapName
		}
		return jsonResult(out)
	})
```

**Step 2: Verify the package still compiles and the smoke test passes**

Run: `go build ./internal/infra/mcp/... && go test ./internal/infra/mcp/...`
Expected: PASS (the existing `TestNewHandlerNonNil` smoke test, no new
unit test in this task — full coverage is in the e2e Task 6).

**Step 3: Commit**

```
git commit -m "$(cat <<'EOF'
feat(mcp): add drive_clone tool with CSI vocabulary

Mirrors the new POST /v1/drives/clone REST endpoint as an MCP tool
so operator tooling and Flow's runtime driver can use the same
CSI-shaped operation regardless of transport.

Tool inputs are the four CSI fields (source_volume_ref required,
name required, mount_path optional, snapshot_name optional). The
JSON result echoes them back along with the new drive's ID, size,
and creation timestamp — provenance is request-scoped, matching
the REST endpoint's contract.

Coverage lives in e2e (subsequent commit): the mcp-go library
wraps tools behind a JSON-RPC streamable HTTP server, so unit-
testing individual tools requires reimplementing the handshake;
exercising via the real /mcp endpoint is honest and adds no test
infrastructure here.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Harness `Client.CloneDrive` (REST helper)

**Depends on:** Task 3 (REST endpoint).

**Files:**
- Modify: `tests/e2e/harness/harness.go` (add `CloneDriveResponse`
  type near the existing `Drive` ~line 569, and `CloneDrive` method
  near the existing drive operations ~line 978)

**No new MCP helper is required.** The harness already exposes
`Client.MCPCall(toolName, args)` at
`tests/e2e/harness/harness.go:1247` with full session management
(`Mcp-Session-Id`), automatic `initialize` handshake, JSON-vs-SSE
response framing, and notification-vs-result filtering. The
`MCPToolResult` type is already defined at line 1176. Task 6's MCP
e2e tests use it directly.

**Step 1: Add the REST clone helpers**

Insert near `tests/e2e/harness/harness.go:577` (right after `Drive`):

```go
// CloneDriveResponse mirrors the CSI-shaped JSON returned from
// POST /v1/drives/clone — a Drive plus the provenance fields.
// Provenance is request-scoped only and is not persisted.
type CloneDriveResponse struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	SizeBytes       uint64  `json:"size_bytes"`
	MountPath       string  `json:"mount_path"`
	VMID            *string `json:"vm_id,omitempty"`
	CreatedAt       string  `json:"created_at"`
	SourceVolumeRef string  `json:"source_volume_ref"`
	SnapshotName    string  `json:"snapshot_name,omitempty"`
}
```

Insert at the end of the "Drive operations" block (~line 978, after
`DetachDrive`):

```go
// CloneDrive issues POST /v1/drives/clone with a CSI-shaped body and
// returns the new drive plus echoed provenance. Pass empty mountPath
// to inherit the source's mount_path; pass empty snapshotName for an
// ephemeral intermediate snapshot.
func (c *Client) CloneDrive(sourceVolumeRef, name, mountPath, snapshotName string) (*CloneDriveResponse, error) {
	type reqBody struct {
		SourceVolumeRef string `json:"source_volume_ref"`
		Name            string `json:"name"`
		MountPath       string `json:"mount_path,omitempty"`
		SnapshotName    string `json:"snapshot_name,omitempty"`
	}
	body, err := json.Marshal(reqBody{
		SourceVolumeRef: sourceVolumeRef,
		Name:            name,
		MountPath:       mountPath,
		SnapshotName:    snapshotName,
	})
	if err != nil {
		return nil, err
	}
	resp, err := c.post("/v1/drives/clone", string(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	var out CloneDriveResponse
	return &out, json.NewDecoder(resp.Body).Decode(&out)
}
```

Use `json.Marshal` (not `fmt.Sprintf`) because mount_path and
snapshot_name are optional — `omitempty` semantics matter for the
inheritance test.

**Step 2: Verify it compiles**

Run: `cd tests/e2e && go vet ./harness/...`
Expected: PASS.

**Step 3: Commit**

```
git commit -m "$(cat <<'EOF'
test(e2e): add harness Client.CloneDrive REST helper

CloneDrive issues POST /v1/drives/clone with the same CSI-shaped
request body the REST endpoint accepts, marshalled via json.Marshal
so omitempty semantics (mount_path, snapshot_name) carry through to
the wire. Returns CloneDriveResponse so e2e tests can assert on the
provenance echo.

MCP coverage in the upcoming e2e tests reuses the existing
Client.MCPCall helper at tests/e2e/harness/harness.go:1247, which
already handles the initialize handshake, Mcp-Session-Id, and the
JSON-vs-SSE response framings. No new MCP helper is needed.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: E2E coverage for `CloneDrive` (REST + MCP, SQLite + btrfs)

**Depends on:** Tasks 3, 4, 5 (REST endpoint, MCP tool, harness helpers).

**Files:**
- Create: `tests/e2e/drive_clone_test.go`

The clone path uses `BtrfsStorage.SnapshotVolume`,
`BtrfsStorage.CloneVolume`, and `BtrfsStorage.DeleteVolumeSnapshot`
— all in-process btrfs ioctls. `requireBtrfs` is the right guard;
`requireBtrfsSend` would over-skip (that helper exists for the
send/receive path which DOES shell out to `nexus-btrfs`).

**Step 1: Write the e2e test file**

Create `tests/e2e/drive_clone_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCloneDrive_E2E_HappyPath(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	src, err := bd.client.CreateDrive("project-master", "10Mi", "/work")
	if err != nil {
		t.Fatalf("create source drive: %v", err)
	}

	clone, err := bd.client.CloneDrive(src.Name, "work-item-W1", "/work", "")
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.Name != "work-item-W1" {
		t.Errorf("clone name = %q, want work-item-W1", clone.Name)
	}
	if clone.SourceVolumeRef != src.Name {
		t.Errorf("source_volume_ref echo = %q, want %q", clone.SourceVolumeRef, src.Name)
	}
	if clone.SizeBytes != src.SizeBytes {
		t.Errorf("clone size = %d, want %d", clone.SizeBytes, src.SizeBytes)
	}
	if clone.VMID != nil {
		t.Errorf("clone must be unattached, got vm_id=%v", *clone.VMID)
	}

	// Verify the clone is a real btrfs subvolume on disk and writable.
	clonePath := filepath.Join(bd.drivesDir, clone.Name)
	out, err := btrfsPropertyGet(clonePath)
	if err != nil {
		t.Fatalf("btrfs property get %s: %v: %s", clonePath, err, out)
	}
	if !strings.Contains(out, "ro=false") {
		t.Errorf("clone subvolume not writable: %q", out)
	}

	// And it is reachable via GET /v1/drives.
	drives, err := bd.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	var found bool
	for _, d := range drives {
		if d.Name == clone.Name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cloned drive not in ListDrives: %v", drives)
	}
}

func TestCloneDrive_E2E_MountPathInherited(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	if _, err := bd.client.CreateDrive("master", "10Mi", "/inherited"); err != nil {
		t.Fatalf("create source: %v", err)
	}

	clone, err := bd.client.CloneDrive("master", "child", "", "")
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.MountPath != "/inherited" {
		t.Errorf("mount_path = %q, want /inherited (inherited)", clone.MountPath)
	}
}

func TestCloneDrive_E2E_RetainSnapshot(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	src, err := bd.client.CreateDrive("master-2", "10Mi", "/m")
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	const snapName = "named-snap-e2e"
	clone, err := bd.client.CloneDrive(src.Name, "clone-2", "/c", snapName)
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.SnapshotName != snapName {
		t.Errorf("snapshot_name echo = %q, want %q", clone.SnapshotName, snapName)
	}

	// The named intermediate snapshot must exist at
	// <drivesDir>/.snapshots/<snapName> as a read-only subvolume.
	snapPath := filepath.Join(bd.drivesDir, ".snapshots", snapName)
	out, err := btrfsPropertyGet(snapPath)
	if err != nil {
		t.Fatalf("named snapshot missing at %s: %v: %s", snapPath, err, out)
	}
	if !strings.Contains(out, "ro=true") {
		t.Errorf("retained snapshot not read-only: %q", out)
	}
}

func TestCloneDrive_E2E_SourceNotFound(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	_, err := bd.client.CloneDrive("ghost", "clone", "", "")
	if err == nil {
		t.Fatal("expected error for missing source")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want a 404", err)
	}
}

func TestCloneDrive_E2E_NameConflict(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	if _, err := bd.client.CreateDrive("src", "10Mi", "/m"); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	if _, err := bd.client.CreateDrive("taken", "10Mi", "/t"); err != nil {
		t.Fatalf("seed taken: %v", err)
	}

	_, err := bd.client.CloneDrive("src", "taken", "", "")
	if err == nil {
		t.Fatal("expected error for name conflict")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("err = %v, want a 409", err)
	}
}

func TestCloneDrive_E2E_MCP_HappyPath(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	if _, err := bd.client.CreateDrive("mcp-master", "10Mi", "/m"); err != nil {
		t.Fatalf("seed source: %v", err)
	}

	res, err := bd.client.MCPCall("drive_clone", map[string]any{
		"source_volume_ref": "mcp-master",
		"name":              "mcp-child",
	})
	if err != nil {
		t.Fatalf("MCPCall: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Content)
	}
	if !strings.Contains(res.Content, `"name":"mcp-child"`) {
		t.Errorf("result content missing expected name; got=%s", res.Content)
	}
	if !strings.Contains(res.Content, `"source_volume_ref":"mcp-master"`) {
		t.Errorf("result content missing source_volume_ref echo; got=%s", res.Content)
	}

	// The drive is also reachable via REST after MCP creation.
	drives, err := bd.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	var found bool
	for _, d := range drives {
		if d.Name == "mcp-child" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("MCP-cloned drive not in ListDrives")
	}
}

func TestCloneDrive_E2E_MCP_MissingRequired(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	res, err := bd.client.MCPCall("drive_clone", map[string]any{
		"name": "child-only",
		// missing source_volume_ref
	})
	if err != nil {
		t.Fatalf("MCPCall: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected isError=true for missing source_volume_ref; content=%s", res.Content)
	}
	if !strings.Contains(res.Content, "source_volume_ref") {
		t.Errorf("error content should name the missing field; got=%s", res.Content)
	}
}
```

**Step 2: Run the e2e tests**

Run: `mise run e2e -- -run TestCloneDrive_E2E -v`

Expected: 7 PASS or 7 SKIP (all-or-nothing on `requireBtrfs`).

If running on a non-btrfs host, the suite must SKIP cleanly with
"working directory is not on btrfs".

**Step 3: Commit**

```
git commit -m "$(cat <<'EOF'
test(e2e): cover POST /v1/drives/clone and drive_clone end-to-end

Seven e2e scenarios against the live daemon on SQLite + btrfs:

REST:
  1. happy path — clone succeeds, clone is a writable btrfs subvolume,
     intermediate snapshot is cleaned up
  2. mount_path inheritance — empty mount_path inherits from source
  3. retained snapshot — when snapshot_name is set, the intermediate
     snapshot lives on at <drivesDir>/.snapshots/<name> as a read-only
     subvolume (CSI VolumeSnapshot semantics)
  4. source not found — returns 404
  5. target name conflict — returns 409

MCP:
  6. happy path — drive_clone via /mcp creates a drive reachable via
     REST, response echoes source_volume_ref
  7. missing required field — drive_clone returns isError=true when
     source_volume_ref is omitted

Single-backend (SQLite) per the Nexus PG deferral. Guarded with
requireBtrfs (the clone path uses in-process btrfs ioctls, so
requireBtrfsSend would over-skip).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Document the new operation

**Depends on:** Tasks 3 and 4.

**Files:**
- Modify: `docs/2026-04-18-vm-pool-and-clone.md` (mark the
  `CloneDrive` requirement as implemented; reference the REST + MCP
  surfaces)
- Modify: `docs/remaining-features.md` (close the corresponding entry
  if present; otherwise no-op — verify with `grep -n CloneDrive
  docs/remaining-features.md` first)

**Note:** the umbrella doc has a section titled "Drive clone from a
long-lived master" (verified — it appears in
`docs/2026-04-18-vm-pool-and-clone.md` around line 50). That heading
is stable; the developer can rely on it. If `grep -n "Drive clone
from a long-lived master" docs/2026-04-18-vm-pool-and-clone.md`
returns no matches at the time of the task, fall back to finding the
nearest analog and mention the divergence in the commit body.

**Step 1: Update the umbrella spec**

Edit `docs/2026-04-18-vm-pool-and-clone.md`. Replace the entire
"Drive clone from a long-lived master" section (the `Required
addition: CloneDrive on DriveService` block) with:

```markdown
### Drive clone from a long-lived master — IMPLEMENTED

`CloneDrive` ships as `app.VMService.CloneDrive` and is exposed on
both REST and MCP using a CSI-shaped wire surface that maps 1:1 to
k8s `VolumeSnapshot` + `PersistentVolumeClaim` clone-from-snapshot
semantics:

- REST: `POST /v1/drives/clone` with body
  `{source_volume_ref, name, mount_path?, snapshot_name?}`
- MCP: tool `drive_clone` with the same four arguments

`mount_path` is optional — when omitted the clone inherits the
source drive's `mount_path`, matching CSI's separation of volume
creation from mount-target declaration. The intermediate btrfs
snapshot is ephemeral when `snapshot_name` is omitted (CSI no-
snapshot path) and retained when set (CSI named-snapshot path).

Implementation reuses `s.storage.SnapshotVolume` and a new
`s.storage.CloneVolume` primitive; the underlying btrfs operation
is `btrfs.CreateSnapshot(snap, dst, readOnly=false)`. Provenance
(source_volume_ref / snapshot_name) is echoed in the response for
the immediate caller's bookkeeping but is not persisted on
`domain.Drive`.
```

Leave the rest of the document (pool tagging, no-hot-attach, etc.)
intact.

**Step 2: Check `docs/remaining-features.md`**

Run: `grep -n "CloneDrive\|clone-drive\|drive.clone" docs/remaining-features.md`

If matches exist, remove the corresponding entries. If none, this
file is untouched in this commit.

**Step 3: Note on cross-repo tracker**

`/home/kazw/Work/WorkFort/AGENT-POOL-REMAINING-WORK.md` is **not in
this repo** — do NOT modify it from this plan. The Team Lead updates
the cross-repo tracker separately when this plan completes.

**Step 4: Commit**

```
git commit -m "$(cat <<'EOF'
docs(vm-pool-and-clone): mark CloneDrive as implemented

The umbrella spec called for CloneDrive on DriveService; the
operation now ships as VMService.CloneDrive, surfaced at
POST /v1/drives/clone and MCP tool drive_clone with a CSI-shaped
request body that maps 1:1 to k8s VolumeSnapshot + PVC clone-from-
snapshot semantics. mount_path is optional with inheritance from
source; snapshot_name controls intermediate retention.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Verification Checklist

After all seven tasks land:

- [ ] `mise run test` from repo root → all unit tests pass, including
      the new `TestBtrfsStorage_CloneVolume` (skipped on non-btrfs)
      and the 6 `TestCloneDrive*` cases in `internal/app/`.
- [ ] `mise run test` from repo root → 4 new `TestCloneDriveEndpoint*`
      cases in `internal/infra/httpapi/` pass.
- [ ] `mise run test` from repo root → existing
      `TestNewHandlerNonNil` smoke test in `internal/infra/mcp/` still
      passes; no new unit tests in that package by design.
- [ ] On a btrfs host: `mise run e2e -- -run TestCloneDrive_E2E -v`
      → 7 PASS.
- [ ] On a non-btrfs host: same command → 7 SKIP with
      `working directory is not on btrfs`.
- [ ] `cd /home/kazw/Work/WorkFort/nexus/lead && git status` → clean
      working tree.
- [ ] `git log --oneline -7` shows seven new commits with multi-line
      conventional format, `Co-Authored-By: Claude Sonnet 4.6` trailer,
      no `!` markers, no `BREAKING CHANGE:` footers.
- [ ] `grep -rn "subvol\|btrfs_snapshot_id\|parent_subvol_path" \
      internal/infra/httpapi/handler.go internal/infra/mcp/handler.go`
      → ZERO matches (no btrfs vocabulary in the public API).
- [ ] `curl -s http://localhost:9600/openapi.json | jq '.paths."/v1/drives/clone"'`
      against a running daemon shows the route registered with
      `source_volume_ref`, `name`, `mount_path`, `snapshot_name` fields
      and a description noting that provenance is request-scoped.
- [ ] MCP `tools/list` against the daemon includes `drive_clone`.
- [ ] `docs/2026-04-18-vm-pool-and-clone.md` reflects the implemented
      state.

## Anti-patterns to avoid

- **Do not** expose any btrfs vocabulary in the REST or MCP surface.
  The internal package may use `subvol` / `snapshot` — the wire MUST
  use CSI shape.
- **Do not** add a `domain.DriveSnapshot` entity table. Intermediate
  snapshots are implementation detail.
- **Do not** persist `source_volume_ref` / `snapshot_name` on
  `domain.Drive`. Provenance is request-scoped echo only.
- **Do not** require `mount_path` on the wire. CSI separates volume
  creation from mount-target declaration; inheriting from source is
  the correct default.
- **Do not** wire a Flow-side consumer in this plan. The Nexus driver
  impl in Flow that calls this endpoint is a separate plan.
- **Do not** alter `CloneSnapshot` (the whole-VM operation). The
  latent `RestoreVolume`-into-non-existent-target defect there is
  noted in Task 1's commit message but not fixed in this plan; a
  follow-up may migrate `CloneSnapshot` onto `CloneVolume` for
  correctness once the team has appetite for that scope.
- **Do not** skip the cap-aware guards if the developer chooses to
  also exercise the export/import path during local verification —
  use `requireBtrfsSend` for those (already present in the test file
  alongside `requireBtrfs`).
