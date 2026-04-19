---
type: plan
step: "1"
title: "Nexus CloneDrive — CSI-shaped REST + MCP"
status: pending
assessment_status: needed
provenance:
  source: roadmap
  issue_id: null
  roadmap_step: null
dates:
  created: "2026-04-19"
  approved: null
  completed: null
related_plans:
  - docs/2026-04-18-vm-pool-and-clone.md
---

# Nexus CloneDrive — CSI-Shaped REST + MCP

**Goal:** Expose a drive-only clone-from-snapshot operation on Nexus
that maps 1:1 to k8s CSI primitives (VolumeSnapshot + PVC clone-from-
snapshot). Flow's `RuntimeDriver.CloneWorkItemVolume` is the consumer;
its k8s impl will use the same wire shape against a k8s API server.

The btrfs primitive `s.storage.SnapshotVolume` already exists and is
called by `internal/app/snapshot.go::CreateSnapshot` to clone drives as
part of cloning a whole VM. This plan exposes the same primitive at the
**drive level** behind a CSI-vocabulary API surface so a future k8s
adapter is a translation layer, not a re-architecture.

## Hard architectural constraints

The public API (REST request/response, MCP tool input/output) MUST use
CSI vocabulary, NOT Nexus-internal btrfs terminology:

| Use (CSI shape) | Do NOT expose |
|-----------------|---------------|
| `source_volume_ref` | `subvol`, `parent_subvol_path`, `src_drive_id_or_name` |
| `snapshot_name` (intermediate, optional) | `btrfs_snapshot_id`, `subvol@snap` |
| `name` (new clone drive name) | `clone_path`, `target_subvol` |
| `data_source` (request body wrapper) | direct btrfs args |
| `mount_path` (CSI mount target) | container-internal subvol path |

This matches `flow/lead/internal/domain/ports.go::CloneWorkItemVolume`
and `flow/lead/internal/domain/types.go::VolumeRef`. The Flow Nexus
driver impl (separate plan) will translate `VolumeRef{Kind: "nexus-
drive", ID: <drive-id>}` to/from these REST/MCP fields.

**Internals stay btrfs.** The wrapper service may name internal
variables `subvolName`, `snapshotName`, etc. — those names are private
to the package. Only the exported surface is CSI-shaped.

## Scope boundaries

In scope:
1. `CloneDrive` use-case in `internal/app` wrapping `s.storage.SnapshotVolume`.
2. REST endpoint `POST /v1/drives/clone` with CSI request/response shape.
3. MCP tool `drive_clone` with the same input/output as REST.
4. Domain error sentinel additions where needed (none expected — reuse
   `ErrNotFound`, `ErrAlreadyExists`, `ErrValidation`).
5. Unit tests for the new app method.
6. E2E tests against the live daemon (SQLite-only — Nexus is single-
   backend per `TOOLING-BASELINE-REMAINING-WORK.md` PG deferral).
7. Harness `Client` method `CloneDrive` for the e2e tests.

Out of scope:
1. Hot drive attach (deferred per umbrella spec).
2. CSI VolumeSnapshot resource as a first-class Nexus entity (the
   intermediate snapshot is implementation detail; the API is "clone
   from a source drive ref" with optional named snapshot reuse).
3. Per-snapshot drive metadata persistence (no `domain.DriveSnapshot`
   table). The intermediate btrfs snapshot lives under
   `<drivesDir>/.snapshots/` and is cleaned up after the clone or
   retained if `snapshot_name` was specified.
4. Flow's Nexus driver impl that consumes this — separate plan.
5. k8s driver impl — separate future plan.

## Prerequisites

- `internal/infra/storage/btrfs.go` already provides `SnapshotVolume`,
  `RestoreVolume`, `DeleteVolumeSnapshot` (verified in source).
- `internal/app/vm_service.go::CreateDrive` already exists and persists
  drive metadata via `s.driveStore.CreateDrive`.
- `internal/app/snapshot.go::CloneSnapshot` already shows the
  `SnapshotVolume` → `RestoreVolume` → `driveStore.CreateDrive` pattern
  for the whole-VM clone case (lines 196-233).
- E2E harness pattern `startBtrfsDaemon` in
  `tests/e2e/snapshot_test.go:79` already wires up a btrfs-capable
  daemon for snapshot tests.
- `requireBtrfs` and `requireBtrfsSend` skip-guard helpers exist in
  `tests/e2e/snapshot_test.go:20,40` — reuse `requireBtrfs` (the clone
  path does NOT shell out to `nexus-btrfs`; it goes through the
  in-process btrfs ioctl path).

## Tech stack

Go 1.26 (Nexus root module + nested `tests/e2e` module). No new
dependencies. Existing:
- `github.com/danielgtaylor/huma/v2` for REST.
- `github.com/mark3labs/mcp-go` for MCP.
- `github.com/Work-Fort/Nexus/pkg/btrfs` for the underlying ioctl
  surface (already used by `BtrfsStorage.SnapshotVolume`).

## Build commands

- `mise run build` — builds nexus binary + helpers.
- `mise run test` — unit tests across the root module.
- `mise run e2e` — e2e tests under `tests/e2e/`.
- Targeted: `go test -run <Name> ./internal/app/...` from repo root for
  unit tests during TDD; `cd tests/e2e && go test -run <Name> .` for
  e2e iterations.

---

## Task Breakdown

### Task 1: App-layer `CloneDrive` use-case

**Files:**
- Create: `internal/app/drive_clone.go`
- Create: `internal/app/drive_clone_test.go`

**Rationale for file split:** `vm_service.go` is already 1461 lines.
Drive-clone is a distinct CSI-shaped capability with its own tests; a
new file keeps the diff bisectable and the test isolated.

**Step 1: Write the failing unit test**

Create `internal/app/drive_clone_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
	"github.com/Work-Fort/Nexus/internal/infra/storage"
)

// fakeStorage implements domain.Storage in-memory for unit tests. It
// tracks CreateVolume / SnapshotVolume / RestoreVolume / DeleteVolume
// calls so tests can assert the CSI-shaped sequence:
// SnapshotVolume(src, intermediate) → RestoreVolume(intermediate, dst)
// → DeleteVolumeSnapshot(intermediate)  (when retain=false).
type fakeStorage struct {
	volumes      map[string]bool
	snapshots    map[string]string // snapshot -> source volume
	calls        []string
	failOn       string // method name to fail on, "" = none
}

func newFakeStorage(seed ...string) *fakeStorage {
	fs := &fakeStorage{
		volumes:   map[string]bool{},
		snapshots: map[string]string{},
	}
	for _, v := range seed {
		fs.volumes[v] = true
	}
	return fs
}

// (implement domain.Storage methods; keep in same file)

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
func (s *fakeStorage) VolumePath(name string) string { return "/fake/" + name }
func (s *fakeStorage) SendVolume(context.Context, string, io.Writer) error      { return nil }
func (s *fakeStorage) ReceiveVolume(context.Context, string, io.Reader) error    { return nil }
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
func (s *fakeStorage) RestoreVolume(_ context.Context, snap, vol string) error {
	s.calls = append(s.calls, "RestoreVolume:"+snap+"->"+vol)
	if s.failOn == "RestoreVolume" {
		return errors.New("synthetic failure")
	}
	if _, ok := s.snapshots[snap]; !ok {
		return errors.New("snapshot not found")
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

func TestCloneDrive_HappyPath(t *testing.T) {
	store, cleanup := sqlite.NewMemoryDriveStore(t)
	defer cleanup()
	fs := newFakeStorage()

	svc := app.NewVMService(nil, nil, nil, app.WithStorage(store, fs))

	// Seed the source drive.
	src, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name:      "project-master",
		Size:      "100Mi",
		MountPath: "/work",
	})
	if err != nil {
		t.Fatalf("seed source drive: %v", err)
	}

	clone, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: src.Name,
		Name:            "work-item-W1",
		MountPath:       "/work",
	})
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.Name != "work-item-W1" {
		t.Errorf("clone name = %q, want work-item-W1", clone.Name)
	}
	if clone.SizeBytes != src.SizeBytes {
		t.Errorf("clone size = %d, want %d (inherited from source)", clone.SizeBytes, src.SizeBytes)
	}
	if clone.MountPath != "/work" {
		t.Errorf("clone mount = %q, want /work", clone.MountPath)
	}
	if clone.VMID != "" {
		t.Errorf("clone must be unattached, got VMID=%q", clone.VMID)
	}

	// Storage call sequence: SnapshotVolume → RestoreVolume → DeleteVolumeSnapshot.
	wantPrefix := []string{"CreateVolume:project-master"} // from the seed
	got := fs.calls
	if len(got) < 4 || got[0] != wantPrefix[0] {
		t.Fatalf("unexpected call sequence: %v", got)
	}
	tail := got[1:]
	if len(tail) != 3 ||
		!strings.HasPrefix(tail[0], "SnapshotVolume:project-master->") ||
		!strings.HasPrefix(tail[1], "RestoreVolume:") ||
		!strings.HasPrefix(tail[2], "DeleteVolumeSnapshot:") {
		t.Errorf("clone call sequence wrong: %v", tail)
	}

	// Drive store now has the clone.
	got2, err := svc.GetDrive(context.Background(), "work-item-W1")
	if err != nil {
		t.Fatalf("GetDrive after clone: %v", err)
	}
	if got2.ID != clone.ID {
		t.Errorf("stored clone ID mismatch")
	}
}

func TestCloneDrive_RetainSnapshot(t *testing.T) {
	store, cleanup := sqlite.NewMemoryDriveStore(t)
	defer cleanup()
	fs := newFakeStorage()
	svc := app.NewVMService(nil, nil, nil, app.WithStorage(store, fs))

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	}); err != nil {
		t.Fatal(err)
	}

	_, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "dst",
		MountPath:       "/dst",
		SnapshotName:    "named-snap-1",
	})
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}

	// With an explicit SnapshotName, the intermediate snapshot is RETAINED
	// (CSI VolumeSnapshot semantics — caller named it, caller owns its lifecycle).
	for _, c := range fs.calls {
		if strings.HasPrefix(c, "DeleteVolumeSnapshot:") {
			t.Errorf("snapshot must be retained when SnapshotName is set, got delete call: %v", fs.calls)
		}
	}
	// Snapshot still present in fake.
	if _, ok := fs.snapshots["named-snap-1"]; !ok {
		t.Errorf("named snapshot missing from fake; calls=%v", fs.calls)
	}
}

func TestCloneDrive_SourceNotFound(t *testing.T) {
	store, cleanup := sqlite.NewMemoryDriveStore(t)
	defer cleanup()
	fs := newFakeStorage()
	svc := app.NewVMService(nil, nil, nil, app.WithStorage(store, fs))

	_, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "ghost",
		Name:            "clone",
		MountPath:       "/x",
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCloneDrive_NameConflict(t *testing.T) {
	store, cleanup := sqlite.NewMemoryDriveStore(t)
	defer cleanup()
	fs := newFakeStorage()
	svc := app.NewVMService(nil, nil, nil, app.WithStorage(store, fs))

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "taken", Size: "10Mi", MountPath: "/t",
	}); err != nil {
		t.Fatal(err)
	}

	_, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "taken",
		MountPath:       "/x",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestCloneDrive_SourceAttachedToRunningVM_Rejected(t *testing.T) {
	// CSI semantics forbid cloning from a volume that is in active use
	// without consistency (we conservatively reject any attached source).
	store, cleanup := sqlite.NewMemoryDriveStore(t)
	defer cleanup()
	fs := newFakeStorage()
	svc := app.NewVMService(nil, nil, nil, app.WithStorage(store, fs))

	src, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate attachment by writing AttachDrive directly on the store.
	if err := store.AttachDrive(context.Background(), src.ID, "vm-1"); err != nil {
		t.Fatal(err)
	}

	_, err = svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "clone",
		MountPath:       "/x",
	})
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}
```

The `sqlite.NewMemoryDriveStore` test helper does not yet exist; it
lives alongside the existing sqlite driveStore. If absent, create it
in `internal/infra/sqlite/drive_store_test_helpers.go` with the
following contents:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package sqlite

import (
	"testing"
)

// NewMemoryDriveStore returns an in-memory sqlite-backed DriveStore for
// tests. The cleanup func MUST be deferred.
func NewMemoryDriveStore(t *testing.T) (*DriveStore, func()) {
	t.Helper()
	db, err := openMemory()
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		t.Fatalf("migrate: %v", err)
	}
	return NewDriveStore(db), func() { _ = db.Close() }
}
```

If the existing sqlite package already exposes a different test helper
(scan `internal/infra/sqlite/*_test.go` first), reuse that and skip
creating the helper. The test must construct a working `domain.DriveStore`
without any disk dependency.

**Step 2: Run the test to verify it fails**

Run: `go test -run TestCloneDrive ./internal/app/...`

Expected: FAIL — `app.CloneDrive` and `app.CloneDriveParams` undefined,
plus possible "fakeStorage.SendVolume / SendVolumeSnapshot signature
mismatch" if `io.Writer` import is missing. Add the missing import:

```go
import (
	"errors"
	"io"
	"strings"
	"testing"
	// ...
)
```

Re-run; expected FAIL message: `app.CloneDrive undefined`.

**Step 3: Implement `CloneDrive`**

Create `internal/app/drive_clone.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/nxid"
)

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
// MountPath is the CSI mount target inside the consuming VM.
// SnapshotName is the name of the intermediate VolumeSnapshot. If
// empty, an ephemeral snapshot is created and deleted after the clone.
// If non-empty, the snapshot is retained under that name (CSI semantics
// — the caller owns its lifecycle).
type CloneDriveParams struct {
	SourceVolumeRef string
	Name            string
	MountPath       string
	SnapshotName    string // optional
}

// CloneDrive creates a new drive that is a copy-on-write clone of an
// existing source drive. The source must not be attached to a VM. The
// new drive is unattached.
//
// Implementation: SnapshotVolume(src, intermediate) → RestoreVolume(
// intermediate, new) → optionally DeleteVolumeSnapshot(intermediate).
// This is the same primitive sequence used by CloneSnapshot in
// snapshot.go, exposed at the drive level for k8s-CSI parity.
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
	if params.MountPath == "" {
		return nil, fmt.Errorf("mount_path is required: %w", domain.ErrValidation)
	}

	src, err := s.driveStore.ResolveDrive(ctx, params.SourceVolumeRef)
	if err != nil {
		return nil, err // already wrapped with ErrNotFound by the store
	}
	if src.VMID != "" {
		return nil, fmt.Errorf("source drive %q is attached to VM %s: %w",
			src.Name, src.VMID, domain.ErrInvalidState)
	}

	if existing, err := s.driveStore.GetDriveByName(ctx, params.Name); err == nil && existing != nil {
		return nil, fmt.Errorf("drive name %q: %w", params.Name, domain.ErrAlreadyExists)
	}

	// Choose the intermediate snapshot name. When the caller did NOT
	// specify one, generate an ephemeral name we will delete after.
	snapName := params.SnapshotName
	retainSnapshot := snapName != ""
	if !retainSnapshot {
		snapName = src.Name + "@clone-" + nxid.New()
	}

	if err := s.storage.SnapshotVolume(ctx, src.Name, snapName); err != nil {
		return nil, fmt.Errorf("snapshot source %s: %w", src.Name, err)
	}
	// On any failure past this point we must clean up the snapshot.
	cleanupSnap := func() {
		if !retainSnapshot {
			return
		}
		// Caller asked for retention — leave it.
	}
	deleteSnapOnError := func() {
		_ = s.storage.DeleteVolumeSnapshot(ctx, snapName)
	}

	if err := s.storage.RestoreVolume(ctx, snapName, params.Name); err != nil {
		deleteSnapOnError()
		return nil, fmt.Errorf("restore clone %s: %w", params.Name, err)
	}

	d := &domain.Drive{
		ID:        nxid.New(),
		Name:      params.Name,
		SizeBytes: src.SizeBytes,
		MountPath: params.MountPath,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.driveStore.CreateDrive(ctx, d); err != nil {
		_ = s.storage.DeleteVolume(ctx, params.Name)
		deleteSnapOnError()
		return nil, fmt.Errorf("persist cloned drive: %w", err)
	}

	if !retainSnapshot {
		if err := s.storage.DeleteVolumeSnapshot(ctx, snapName); err != nil {
			// Non-fatal: the clone succeeded; the orphan snapshot will
			// be cleaned up by btrfs subvolume reclaim on next compaction.
			log.Warn("clone: failed to delete intermediate snapshot",
				"snapshot", snapName, "err", err)
		}
	}
	cleanupSnap()

	log.Info("drive cloned",
		"id", d.ID, "name", d.Name, "source", src.Name,
		"snapshot_retained", retainSnapshot)
	return d, nil
}
```

**Step 4: Run the tests to verify they pass**

Run: `go test -run TestCloneDrive ./internal/app/...`
Expected: PASS for all 5 cases.

If any test fails, fix the implementation — do not weaken assertions.

**Step 5: Commit**

```
git commit -m "$(cat <<'EOF'
feat(app): add CSI-shaped CloneDrive operation

Adds VMService.CloneDrive (and CloneDriveParams) that produces a
new drive as a copy-on-write clone of an existing source drive.
The implementation reuses the existing storage.SnapshotVolume +
RestoreVolume primitives that the whole-VM CloneSnapshot path
already calls, exposed at the drive level so a future k8s
RuntimeDriver impl in Flow can use the same wire shape against
either a Nexus REST endpoint or a k8s API server.

The exported field names use CSI vocabulary (SourceVolumeRef,
SnapshotName, Name, MountPath) so the upcoming HTTP and MCP
surfaces map 1:1 to k8s VolumeSnapshot / PVC dataSource. Internal
btrfs naming stays internal.

Validation:
- source must exist; ErrNotFound otherwise
- source must not be attached; ErrInvalidState otherwise
- target name must be unique; ErrAlreadyExists otherwise
- empty SnapshotName -> ephemeral intermediate, deleted after
- non-empty SnapshotName -> intermediate retained (CSI semantics)

5 unit tests cover happy path, snapshot retention, source not
found, name conflict, attached-source rejection.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: REST endpoint `POST /v1/drives/clone`

**Depends on:** Task 1 (the app method).

**Files:**
- Modify: `internal/infra/httpapi/handler.go` (add input/output types
  near the existing `CreateDriveInput` ~line 77, register the route in
  `registerDriveRoutes` ~line 759, end of function)
- Modify: `internal/infra/httpapi/handler_test.go` (add an integration
  test using `httptest.Server` against the registered handler)

**Step 1: Write the failing handler test**

Append to `internal/infra/httpapi/handler_test.go`:

```go
func TestCloneDriveEndpoint_Success(t *testing.T) {
	// Use the same in-process VMService scaffold the file's other
	// integration tests use; locate the existing helper (likely
	// newTestServer or similar) and reuse it.
	srv, svc, cleanup := newTestServerWithStorage(t)
	defer cleanup()

	// Seed source drive via service to avoid HTTP setup noise.
	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "master", Size: "10Mi", MountPath: "/m",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"source_volume_ref":"master","name":"work-1","mount_path":"/work"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/drives/clone", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		MountPath     string `json:"mount_path"`
		SizeBytes     uint64 `json:"size_bytes"`
		SourceRef     string `json:"source_volume_ref"`
		SnapshotName  string `json:"snapshot_name,omitempty"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "work-1" {
		t.Errorf("name = %q, want work-1", resp.Name)
	}
	if resp.SourceRef != "master" {
		t.Errorf("source_volume_ref = %q, want master", resp.SourceRef)
	}
}

func TestCloneDriveEndpoint_SourceNotFound(t *testing.T) {
	srv, _, cleanup := newTestServerWithStorage(t)
	defer cleanup()

	body := `{"source_volume_ref":"ghost","name":"clone","mount_path":"/x"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/drives/clone", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCloneDriveEndpoint_NameConflict(t *testing.T) {
	srv, svc, cleanup := newTestServerWithStorage(t)
	defer cleanup()

	for _, n := range []string{"src", "taken"} {
		if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
			Name: n, Size: "10Mi", MountPath: "/m",
		}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}

	body := `{"source_volume_ref":"src","name":"taken","mount_path":"/x"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/drives/clone", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}
```

If `newTestServerWithStorage` does not exist in `handler_test.go`, locate
the existing test helper that constructs a VMService with a fake or
in-memory `domain.Storage` + `domain.DriveStore`. If none exists,
create it next to other helpers in `handler_test.go`:

```go
// newTestServerWithStorage returns an http.Handler over a VMService
// wired with an in-memory drive store and a fakeStorage stand-in (the
// same fakeStorage from internal/app/drive_clone_test.go — copy it or
// extract to a shared internal/apptest helper).
func newTestServerWithStorage(t *testing.T) (http.Handler, *app.VMService, func()) {
	// implementation: minimal — follow whatever pattern existing tests
	// in this file already establish; the goal is to invoke
	// httpapi.NewHandler against a VMService that has WithStorage set.
}
```

**Note for the developer:** if `handler_test.go` does not currently
test any drive endpoint (likely — the file's existing tests focus on
VMs), prefer extending it minimally over splitting into a new file.
Three new tests in the same file is fine.

**Step 2: Run the test to verify it fails**

Run: `go test -run TestCloneDriveEndpoint ./internal/infra/httpapi/...`
Expected: FAIL — `404` or "no route matched POST /v1/drives/clone".

**Step 3: Add request/response types and register the route**

Add near the existing `CreateDriveInput` (~line 77) in `handler.go`:

```go
// CloneDriveInput is the CSI-shaped request body for POST /v1/drives/clone.
// Field names mirror k8s PVC dataSource:
//
//	source_volume_ref  -> the existing drive (name or ID) to clone from.
//	name               -> the new drive's name.
//	mount_path         -> CSI mount target inside the consuming VM.
//	snapshot_name      -> optional; named intermediate VolumeSnapshot.
//	                     Omitted = ephemeral snapshot, deleted after clone.
type CloneDriveInput struct {
	Body struct {
		SourceVolumeRef string `json:"source_volume_ref" doc:"Source drive ID or name to clone from"`
		Name            string `json:"name" doc:"New drive name"`
		MountPath       string `json:"mount_path" doc:"Mount path inside the VM"`
		SnapshotName    string `json:"snapshot_name,omitempty" doc:"Optional intermediate snapshot name; if set, the snapshot is retained"`
	}
}
```

Add a new response type next to `driveResponse` (~line 245):

```go
// cloneDriveResponse extends driveResponse with the CSI provenance
// fields the caller may want to record (e.g., the SourceVolumeRef
// and the SnapshotName actually used). Keeping this distinct from
// driveResponse means GET /v1/drives/{id} stays narrow while clone
// callers get a complete record of what was cloned.
type cloneDriveResponse struct {
	ID              string  `json:"id" doc:"Drive ID"`
	Name            string  `json:"name" doc:"Drive name"`
	SizeBytes       uint64  `json:"size_bytes" doc:"Size in bytes (inherited from source)"`
	MountPath       string  `json:"mount_path" doc:"Mount path"`
	VMID            *string `json:"vm_id,omitempty" doc:"Attached VM ID (always nil for fresh clones)"`
	CreatedAt       string  `json:"created_at" doc:"Creation timestamp"`
	SourceVolumeRef string  `json:"source_volume_ref" doc:"Source drive that was cloned"`
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
		OperationID:   "clone-drive",
		Method:        http.MethodPost,
		Path:          "/v1/drives/clone",
		Summary:       "Clone a drive from a source volume",
		Description: "CSI-shaped clone-from-snapshot operation. Maps 1:1 to a k8s " +
			"PersistentVolumeClaim with a VolumeSnapshot dataSource. The " +
			"source drive must be detached. When snapshot_name is set, the " +
			"intermediate VolumeSnapshot is retained (caller-owned lifecycle); " +
			"when omitted, an ephemeral snapshot is created and deleted after " +
			"the clone completes.",
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

**Step 4: Run the tests to verify they pass**

Run: `go test -run TestCloneDriveEndpoint ./internal/infra/httpapi/...`
Expected: PASS for all three cases (Success → 201, SourceNotFound → 404,
NameConflict → 409).

**Step 5: Commit**

```
git commit -m "$(cat <<'EOF'
feat(httpapi): expose POST /v1/drives/clone with CSI shape

Wraps the new app.CloneDrive use-case behind a REST endpoint whose
request and response shape map 1:1 to k8s CSI primitives:

  source_volume_ref  <- VolumeSnapshot dataSource
  snapshot_name      <- VolumeSnapshot.metadata.name (optional)
  name + mount_path  <- PersistentVolumeClaim spec

This is the wire shape Flow's RuntimeDriver.CloneWorkItemVolume will
target — Nexus today, k8s tomorrow — so the future k8s adapter is a
translation layer rather than a re-architecture.

Status mapping:
  201 Created  - clone succeeded
  400          - missing required field (source_volume_ref/name/mount_path)
  404          - source drive not found
  409          - target name already exists, or source attached to a VM

Three handler tests cover the success path and the two conflict paths.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: MCP tool `drive_clone`

**Depends on:** Task 1 (the app method).

**Files:**
- Modify: `internal/infra/mcp/handler.go` (extend `registerDriveTools`
  ~line 416)
- Modify: `internal/infra/mcp/handler_test.go` (add a tool-level test)

**Step 1: Write the failing MCP tool test**

Append to `internal/infra/mcp/handler_test.go`:

```go
func TestDriveCloneTool(t *testing.T) {
	svc, cleanup := newTestVMService(t)
	defer cleanup()

	// Seed source drive.
	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "master", Size: "10Mi", MountPath: "/m",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	h := mcp.NewHandler(svc, nil)
	resp := callMCPTool(t, h, "drive_clone", map[string]any{
		"source_volume_ref": "master",
		"name":              "work-1",
		"mount_path":        "/work",
	})
	if resp.IsError {
		t.Fatalf("tool returned error: %s", resp.TextContent())
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(resp.TextContent()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["name"] != "work-1" {
		t.Errorf("name = %v, want work-1", got["name"])
	}
}

func TestDriveCloneTool_MissingRequired(t *testing.T) {
	svc, cleanup := newTestVMService(t)
	defer cleanup()

	h := mcp.NewHandler(svc, nil)
	resp := callMCPTool(t, h, "drive_clone", map[string]any{
		"name":       "work-1",
		"mount_path": "/x",
		// missing source_volume_ref
	})
	if !resp.IsError {
		t.Errorf("expected error result for missing source_volume_ref")
	}
}
```

If `newTestVMService` and `callMCPTool` do not exist in
`handler_test.go`, follow the patterns the existing tests in that file
already use to construct an MCP handler and invoke a tool against it.
Do not invent helpers that don't fit the file's conventions; reuse what
is there.

**Step 2: Run the test to verify it fails**

Run: `go test -run TestDriveCloneTool ./internal/infra/mcp/...`
Expected: FAIL — `tool drive_clone not found` or equivalent.

**Step 3: Register the MCP tool**

Append to `registerDriveTools` (after the `drive_detach` block, ~line
523) in `internal/infra/mcp/handler.go`:

```go
	// drive_clone — CSI-shaped clone-from-snapshot operation.
	s.AddTool(mcp.NewTool("drive_clone",
		mcp.WithDescription("Clone an existing drive into a new drive (CSI VolumeSnapshot + PVC dataSource shape). "+
			"Source must be detached. Usage: drive_clone(source_volume_ref: \"master\", name: \"work-1\", mount_path: \"/work\")"),
		mcp.WithString("source_volume_ref", mcp.Description("Source drive ID or name to clone from"), mcp.Required()),
		mcp.WithString("name", mcp.Description("New drive name"), mcp.Required()),
		mcp.WithString("mount_path", mcp.Description("Mount path inside the VM"), mcp.Required()),
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
		mountPath, errRes := requireString(req, "mount_path")
		if errRes != nil {
			return errRes, nil
		}
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
		// Echo the CSI provenance fields back so the tool result is
		// self-describing for an MCP caller (e.g., Flow's runtime driver).
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

**Step 4: Run the test to verify it passes**

Run: `go test -run TestDriveCloneTool ./internal/infra/mcp/...`
Expected: PASS for both cases.

**Step 5: Commit**

```
git commit -m "$(cat <<'EOF'
feat(mcp): add drive_clone tool with CSI vocabulary

Mirrors the new POST /v1/drives/clone REST endpoint as an MCP tool
so operator tooling and Flow's runtime driver can both use the same
CSI-shaped operation regardless of transport.

Tool inputs are the four CSI fields (source_volume_ref, name,
mount_path, snapshot_name); the JSON result echoes them back along
with the new drive's ID and inherited size, so the caller has a
complete provenance record.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Harness `Client.CloneDrive` method

**Depends on:** Task 2 (the REST endpoint).

**Files:**
- Modify: `tests/e2e/harness/harness.go` (add a `CloneDrive` method
  near the existing drive operations ~line 925, plus a `CloneDriveResponse`
  type near the existing `Drive` ~line 569)

**Step 1: Add the response type**

Insert near `tests/e2e/harness/harness.go:577` (right after `Drive`):

```go
// CloneDriveResponse mirrors the CSI-shaped JSON returned from
// POST /v1/drives/clone — a Drive plus the provenance fields.
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

**Step 2: Add the `CloneDrive` method**

Insert at the end of the "Drive operations" block (~line 978, after
`DetachDrive`):

```go
// CloneDrive issues POST /v1/drives/clone with a CSI-shaped body and
// returns the new drive plus echoed provenance.
func (c *Client) CloneDrive(sourceVolumeRef, name, mountPath, snapshotName string) (*CloneDriveResponse, error) {
	body := fmt.Sprintf(
		`{"source_volume_ref":%q,"name":%q,"mount_path":%q,"snapshot_name":%q}`,
		sourceVolumeRef, name, mountPath, snapshotName,
	)
	resp, err := c.post("/v1/drives/clone", body)
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

**Step 3: Verify it compiles**

Run: `cd tests/e2e && go vet ./harness/...`
Expected: PASS.

**Step 4: Commit**

```
git commit -m "$(cat <<'EOF'
test(e2e): add harness Client.CloneDrive method

Mirrors POST /v1/drives/clone with the same CSI-shaped request body
the REST endpoint accepts. Returns CloneDriveResponse so e2e tests
can assert on the source_volume_ref / snapshot_name echo as well as
the new drive's identity.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: E2E coverage for `CloneDrive` (SQLite-only, btrfs)

**Depends on:** Tasks 2 and 4 (REST endpoint + harness client).

**Files:**
- Create: `tests/e2e/drive_clone_test.go`

The clone path uses `BtrfsStorage.SnapshotVolume` + `RestoreVolume`,
which go through the in-process `pkg/btrfs` ioctl interface — they do
NOT shell out to `build/nexus-btrfs`. So `requireBtrfs` is the right
guard; `requireBtrfsSend` would over-skip.

**Step 1: Write the e2e test file**

Create `tests/e2e/drive_clone_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"path/filepath"
	"testing"
)

func TestCloneDrive_E2E_HappyPath(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	// Seed the source drive.
	src, err := bd.client.CreateDrive("project-master", "10Mi", "/work")
	if err != nil {
		t.Fatalf("create source drive: %v", err)
	}

	// Clone it into a new drive.
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
		t.Errorf("clone size = %d, want %d (inherited)", clone.SizeBytes, src.SizeBytes)
	}
	if clone.VMID != nil {
		t.Errorf("clone must be unattached, got vm_id=%v", *clone.VMID)
	}

	// Verify the clone is a real btrfs subvolume on disk.
	clonePath := filepath.Join(bd.drivesDir, clone.Name)
	out, err := btrfsPropertyGet(clonePath)
	if err != nil {
		t.Fatalf("btrfs property get %s: %v: %s", clonePath, err, out)
	}
	// Cloned drives are writable (ro=false). The intermediate snapshot
	// should already be cleaned up because we passed snapshot_name="".
	if !contains(out, "ro=false") {
		t.Errorf("clone subvolume not writable: %q", out)
	}

	// And it is reachable via GET /v1/drives/{id}.
	got, err := bd.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	var found bool
	for _, d := range got {
		if d.Name == clone.Name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cloned drive not in ListDrives: %v", got)
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
	// <drivesDir>/.snapshots/<snapName>.
	snapPath := filepath.Join(bd.drivesDir, ".snapshots", snapName)
	out, err := btrfsPropertyGet(snapPath)
	if err != nil {
		t.Fatalf("named snapshot missing at %s: %v: %s", snapPath, err, out)
	}
	// Snapshots are read-only.
	if !contains(out, "ro=true") {
		t.Errorf("retained snapshot not read-only: %q", out)
	}
}

func TestCloneDrive_E2E_SourceNotFound(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	_, err := bd.client.CloneDrive("ghost", "clone", "/x", "")
	if err == nil {
		t.Fatal("expected error for missing source")
	}
	// Loosely check the status — the harness Client surfaces APIError
	// strings with "404" prefix.
	if !contains(err.Error(), "404") {
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

	_, err := bd.client.CloneDrive("src", "taken", "/x", "")
	if err == nil {
		t.Fatal("expected error for name conflict")
	}
	if !contains(err.Error(), "409") {
		t.Errorf("err = %v, want a 409", err)
	}
}

// contains is a tiny test helper that avoids pulling strings into every
// test function (mirrors the pattern already used in this package).
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
```

If a `contains` helper already exists elsewhere in `tests/e2e/`,
delete the local copy and use the existing one. Verify with
`grep -n "func contains(" tests/e2e/*.go` before committing.

**Step 2: Run the e2e tests**

Run: `mise run e2e -- -run TestCloneDrive_E2E -v`

Expected: 4 PASS or 4 SKIP. The SKIP path applies on a host without
btrfs; the PASS path requires the btrfs filesystem (no caps required —
the clone path uses ioctls only).

If running on a non-btrfs host, the suite should SKIP cleanly with
"working directory is not on btrfs" — verify the SKIP message before
declaring success.

**Step 3: Commit**

```
git commit -m "$(cat <<'EOF'
test(e2e): cover POST /v1/drives/clone end-to-end on SQLite + btrfs

Four e2e scenarios against the live daemon:
  1. happy path — clone succeeds, clone is a writable btrfs subvolume,
     intermediate snapshot is cleaned up
  2. retained snapshot — when snapshot_name is set, the intermediate
     snapshot lives on at <drivesDir>/.snapshots/<name> as a read-only
     subvolume (CSI VolumeSnapshot semantics)
  3. source not found — returns 404
  4. target name conflict — returns 409

Single-backend (SQLite) per the Nexus PG deferral. Guarded with the
existing requireBtrfs helper; the clone path uses in-process btrfs
ioctls, so requireBtrfsSend would over-skip.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Document the new operation

**Depends on:** Tasks 2 and 3.

**Files:**
- Modify: `docs/2026-04-18-vm-pool-and-clone.md` (mark the
  `CloneDrive` requirement as implemented; add a brief reference to
  the REST + MCP surfaces)
- Modify: `docs/remaining-features.md` (close the corresponding entry
  if one exists; otherwise no-op — verify with `grep -n CloneDrive
  docs/remaining-features.md` first)

**Step 1: Update the umbrella spec**

Edit `docs/2026-04-18-vm-pool-and-clone.md`. In the "Drive clone from
a long-lived master" section, replace the `Required addition: CloneDrive
on DriveService` block with a short note that the operation has landed:

```markdown
### Drive clone from a long-lived master — IMPLEMENTED

`CloneDrive` ships as `app.VMService.CloneDrive` and is exposed on
both REST and MCP using a CSI-shaped wire surface that maps 1:1 to
k8s `VolumeSnapshot` + `PersistentVolumeClaim` clone-from-snapshot
semantics:

- REST: `POST /v1/drives/clone` with body
  `{source_volume_ref, name, mount_path, snapshot_name?}`
- MCP: tool `drive_clone` with the same four arguments

The intermediate btrfs snapshot is ephemeral when `snapshot_name` is
omitted (CSI no-snapshot path) and retained when set (CSI named-
snapshot path).

The implementation reuses the existing `s.storage.SnapshotVolume`
primitive that `CloneSnapshot` already uses for whole-VM clones —
just exposed at the drive level.
```

Leave the rest of the document (pool tagging, no-hot-attach, etc.)
intact.

**Step 2: Update the cross-cutting tracker**

`/home/kazw/Work/WorkFort/AGENT-POOL-REMAINING-WORK.md` is **not in
this repo** — do NOT modify it from this plan. The Team Lead will
update the cross-repo tracker separately when this plan completes.

**Step 3: Commit**

```
git commit -m "$(cat <<'EOF'
docs(vm-pool-and-clone): mark CloneDrive as implemented

The umbrella spec called for CloneDrive on DriveService; the
operation now ships as VMService.CloneDrive, surfaced at
POST /v1/drives/clone and MCP tool drive_clone with a CSI-shaped
request body that maps 1:1 to k8s VolumeSnapshot + PVC clone-from-
snapshot semantics.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Verification Checklist

After all six tasks land:

- [ ] `mise run test` from repo root → all unit tests pass, including
      the 5 new `TestCloneDrive*` cases in `internal/app/`.
- [ ] `mise run test` from repo root → 3 new `TestCloneDriveEndpoint*`
      cases in `internal/infra/httpapi/` pass.
- [ ] `mise run test` from repo root → 2 new `TestDriveCloneTool*`
      cases in `internal/infra/mcp/` pass.
- [ ] On a btrfs host: `mise run e2e -- -run TestCloneDrive_E2E -v`
      → 4 PASS.
- [ ] On a non-btrfs host: same command → 4 SKIP with
      `working directory is not on btrfs`.
- [ ] `cd /home/kazw/Work/WorkFort/nexus/lead && git status` → clean
      working tree.
- [ ] `git log --oneline -7` shows six new commits with multi-line
      conventional format, `Co-Authored-By: Claude Sonnet 4.6` trailer,
      no `!` markers, no `BREAKING CHANGE:` footers.
- [ ] `grep -rn "subvol\|btrfs_snapshot_id\|parent_subvol_path" \
      internal/infra/httpapi/handler.go internal/infra/mcp/handler.go`
      → ZERO matches (no btrfs vocabulary in the public API).
- [ ] `curl -s http://localhost:9600/openapi.json | jq '.paths."/v1/drives/clone"'`
      against a running daemon shows the route registered with
      `source_volume_ref`, `name`, `mount_path`, `snapshot_name` fields.
- [ ] MCP `tools/list` against the daemon includes `drive_clone`.
- [ ] `docs/2026-04-18-vm-pool-and-clone.md` reflects the implemented
      state.

## Anti-patterns to avoid

- **Do not** expose any btrfs vocabulary in the REST or MCP surface.
  The internal package may use `subvol` / `snapshot` — the wire MUST
  use CSI shape.
- **Do not** add a `domain.DriveSnapshot` entity table. Intermediate
  snapshots are implementation detail; a future k8s adapter would
  use `VolumeSnapshot` resources directly without persisting them in
  Nexus's database.
- **Do not** wire a Flow-side consumer in this plan. The Nexus driver
  impl in Flow that calls this endpoint is a separate plan, dispatched
  after this one lands.
- **Do not** alter `CloneSnapshot` (the whole-VM operation) — it stays
  on its current code path; the new use-case is parallel, not a
  refactor.
- **Do not** skip the cap-aware guards if the developer chooses to
  also exercise the export/import path during local verification —
  use `requireBtrfsSend` for those (already present in the test file
  alongside `requireBtrfs`).
