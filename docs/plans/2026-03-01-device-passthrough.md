# Device Passthrough Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add generic device passthrough (GPUs, FPGAs, render nodes) to nexus so host devices can be attached to stopped VMs and included in the OCI spec.

**Architecture:** Devices are independent resources (like drives) stored in a `devices` table, with attach/detach lifecycle. When a VM's container is recreated, attached devices produce `specs.LinuxDevice` + `specs.LinuxDeviceCgroup` entries. No host-level VFIO/IOMMU management — those are prerequisites.

**Tech Stack:** Go, SQLite (sqlc + goose), containerd OCI spec, `unix.Stat_t` for device type/major/minor detection.

**Design doc:** `docs/plans/2026-03-01-device-passthrough-design.md`

---

### Task 1: Domain types — Device and CreateDeviceParams

**Files:**
- Create: `internal/domain/device.go`

**Step 1: Write `internal/domain/device.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import "time"

// Device represents a host device mapping that can be attached to a VM.
type Device struct {
	ID            string
	HostPath      string // e.g. "/dev/vfio/42", "/dev/dri/renderD128"
	ContainerPath string // path inside the container
	Permissions   string // cgroup device access: "rwm", "rw", "r"
	GID           uint32 // GID for device node inside container (0 = root)
	VMID          string // attached VM ID, empty = unattached
	CreatedAt     time.Time
}

// CreateDeviceParams holds parameters for registering a new device mapping.
type CreateDeviceParams struct {
	HostPath      string
	ContainerPath string
	Permissions   string
	GID           uint32
}
```

**Step 2: Verify it compiles**

Run: `mise run build`
Expected: PASS

**Step 3: Commit**

```
feat(domain): add Device type and CreateDeviceParams
```

---

### Task 2: Domain ports — DeviceStore interface, sentinel error, WithDevices

**Files:**
- Modify: `internal/domain/ports.go`

**Step 1: Add DeviceStore interface, ErrDeviceAttached, DeviceInfo, and WithDevices to `ports.go`**

After the `DriveStore` interface block, add:

```go
// DeviceStore persists device metadata.
type DeviceStore interface {
	CreateDevice(ctx context.Context, d *Device) error
	GetDevice(ctx context.Context, id string) (*Device, error)
	ListDevices(ctx context.Context) ([]*Device, error)
	AttachDevice(ctx context.Context, deviceID, vmID string) error
	DetachDevice(ctx context.Context, deviceID string) error
	DetachAllDevices(ctx context.Context, vmID string) error
	GetDevicesByVM(ctx context.Context, vmID string) ([]*Device, error)
	DeleteDevice(ctx context.Context, id string) error
}

// ErrDeviceAttached is returned when deleting a device that is attached to a VM.
var ErrDeviceAttached = errors.New("device is attached to a VM")
```

Add `Devices` field to `CreateConfig`:

```go
type CreateConfig struct {
	NetNSPath string
	Mounts    []Mount
	Devices   []DeviceInfo
}
```

Add `DeviceInfo` type and `WithDevices` option:

```go
// DeviceInfo describes a device to include in the OCI spec.
type DeviceInfo struct {
	HostPath      string
	ContainerPath string
	Permissions   string // "rwm", "rw", "r"
	GID           uint32
}

// WithDevices adds device mappings to the container spec.
func WithDevices(devices []DeviceInfo) CreateOpt {
	return func(c *CreateConfig) {
		c.Devices = devices
	}
}
```

**Step 2: Verify it compiles**

Run: `mise run build`
Expected: PASS

**Step 3: Commit**

```
feat(domain): add DeviceStore interface and WithDevices CreateOpt
```

---

### Task 3: SQLite migration — `004_add_devices.sql`

**Files:**
- Create: `internal/infra/sqlite/migrations/004_add_devices.sql`

**Step 1: Write the migration file**

```sql
-- +goose Up
CREATE TABLE devices (
    id              TEXT PRIMARY KEY,
    host_path       TEXT NOT NULL,
    container_path  TEXT NOT NULL,
    permissions     TEXT NOT NULL DEFAULT 'rwm',
    gid             INTEGER NOT NULL DEFAULT 0,
    vm_id           TEXT REFERENCES vms(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_devices_vm_id ON devices(vm_id);

-- +goose Down
DROP INDEX IF EXISTS idx_devices_vm_id;
DROP TABLE IF EXISTS devices;
```

**Step 2: Verify migration embedded**

Run: `mise run build`
Expected: PASS (embedded FS picks up new .sql file)

**Step 3: Commit**

```
feat(sqlite): add 004_add_devices migration
```

---

### Task 4: SQLite queries + sqlc generate

**Files:**
- Modify: `internal/infra/sqlite/queries.sql`
- Modify: `sqlc.yaml` (if rename needed)
- Regenerated: `internal/infra/sqlite/db.go`, `models.go`, `queries.sql.go`

**Step 1: Add device queries to `queries.sql`**

Append after the drive queries:

```sql
-- name: InsertDevice :exec
INSERT INTO devices (id, host_path, container_path, permissions, gid, vm_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetDevice :one
SELECT id, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE id = ?;

-- name: ListDevices :many
SELECT id, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices ORDER BY created_at DESC;

-- name: AttachDevice :exec
UPDATE devices SET vm_id = ? WHERE id = ?;

-- name: DetachDevice :exec
UPDATE devices SET vm_id = NULL WHERE id = ?;

-- name: DetachAllDevices :exec
UPDATE devices SET vm_id = NULL WHERE vm_id = ?;

-- name: GetDevicesByVM :many
SELECT id, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE vm_id = ? ORDER BY host_path;

-- name: DeleteDevice :exec
DELETE FROM devices WHERE id = ?;
```

**Step 2: Check if sqlc needs a rename for `devices` table**

Run: `sqlc generate` and check the generated model name. If sqlc generates `Device` (correct), no rename needed. If it generates something odd (like `Devife`), add a rename entry in `sqlc.yaml` under `rename:`, mirroring the `drife: Drive` pattern.

Run: `sqlc generate`

**Step 3: Verify it compiles**

Run: `mise run build`
Expected: PASS

**Step 4: Commit**

```
feat(sqlite): add device queries and regenerate sqlc
```

---

### Task 5: DeviceStore implementation on Store

**Files:**
- Modify: `internal/infra/sqlite/store.go`
- Test: `internal/infra/sqlite/store_test.go` (if exists, otherwise skip — integration tested via app layer)

**Step 1: Add `deviceFromRow` helper and DeviceStore methods to `store.go`**

After the drive methods, add:

```go
// --- domain.DeviceStore implementation ---

func (s *Store) CreateDevice(ctx context.Context, d *domain.Device) error {
	var vmID sql.NullString
	if d.VMID != "" {
		vmID = sql.NullString{String: d.VMID, Valid: true}
	}
	return s.q.InsertDevice(ctx, InsertDeviceParams{
		ID:            d.ID,
		HostPath:      d.HostPath,
		ContainerPath: d.ContainerPath,
		Permissions:   d.Permissions,
		Gid:           int64(d.GID),
		VmID:          vmID,
		CreatedAt:     d.CreatedAt.UTC().Format(timeFormat),
	})
}

func (s *Store) GetDevice(ctx context.Context, id string) (*domain.Device, error) {
	row, err := s.q.GetDevice(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get device: %w", err)
	}
	return deviceFromRow(row)
}

func (s *Store) ListDevices(ctx context.Context) ([]*domain.Device, error) {
	rows, err := s.q.ListDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	devices := make([]*domain.Device, len(rows))
	for i, r := range rows {
		d, err := deviceFromRow(r)
		if err != nil {
			return nil, err
		}
		devices[i] = d
	}
	return devices, nil
}

func (s *Store) AttachDevice(ctx context.Context, deviceID, vmID string) error {
	return s.q.AttachDevice(ctx, AttachDeviceParams{
		VmID: sql.NullString{String: vmID, Valid: true},
		ID:   deviceID,
	})
}

func (s *Store) DetachDevice(ctx context.Context, deviceID string) error {
	return s.q.DetachDevice(ctx, deviceID)
}

func (s *Store) DetachAllDevices(ctx context.Context, vmID string) error {
	return s.q.DetachAllDevices(ctx, sql.NullString{String: vmID, Valid: true})
}

func (s *Store) GetDevicesByVM(ctx context.Context, vmID string) ([]*domain.Device, error) {
	rows, err := s.q.GetDevicesByVM(ctx, sql.NullString{String: vmID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("get devices by vm: %w", err)
	}
	devices := make([]*domain.Device, len(rows))
	for i, r := range rows {
		d, err := deviceFromRow(r)
		if err != nil {
			return nil, err
		}
		devices[i] = d
	}
	return devices, nil
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	return s.q.DeleteDevice(ctx, id)
}

func deviceFromRow(row Device) (*domain.Device, error) {
	d := &domain.Device{
		ID:            row.ID,
		HostPath:      row.HostPath,
		ContainerPath: row.ContainerPath,
		Permissions:   row.Permissions,
		GID:           uint32(row.Gid),
	}
	if row.VmID.Valid {
		d.VMID = row.VmID.String
	}
	var err error
	d.CreatedAt, err = time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at for device %s: %w", row.ID, err)
	}
	return d, nil
}
```

Note: The sqlc-generated type name might be `Device` (matching the table `devices`). Adjust the `deviceFromRow` parameter type if sqlc generates a different name. Check `internal/infra/sqlite/models.go` after step 4.

**Step 2: Verify it compiles**

Run: `mise run build`
Expected: PASS

**Step 3: Commit**

```
feat(sqlite): implement DeviceStore on Store
```

---

### Task 6: App service — device methods and tests

This is the largest task. We add 6 device methods to `VMService`, update `recreateContainer`, and update `DeleteVM` for auto-detach.

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`

**Step 1: Write failing tests for device CRUD in `vm_service_test.go`**

Add a `mockDeviceStore` (mirroring `mockDriveStore`), a `newSvcWithDevices` helper, and device tests:

```go
// --- mock DeviceStore ---

type mockDeviceStore struct {
	devices map[string]*domain.Device
}

func newMockDeviceStore() *mockDeviceStore {
	return &mockDeviceStore{devices: make(map[string]*domain.Device)}
}

func (m *mockDeviceStore) CreateDevice(_ context.Context, d *domain.Device) error {
	if _, ok := m.devices[d.ID]; ok {
		return domain.ErrAlreadyExists
	}
	m.devices[d.ID] = d
	return nil
}

func (m *mockDeviceStore) GetDevice(_ context.Context, id string) (*domain.Device, error) {
	d, ok := m.devices[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return d, nil
}

func (m *mockDeviceStore) ListDevices(_ context.Context) ([]*domain.Device, error) {
	var result []*domain.Device
	for _, d := range m.devices {
		result = append(result, d)
	}
	return result, nil
}

func (m *mockDeviceStore) AttachDevice(_ context.Context, deviceID, vmID string) error {
	d, ok := m.devices[deviceID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = vmID
	return nil
}

func (m *mockDeviceStore) DetachDevice(_ context.Context, deviceID string) error {
	d, ok := m.devices[deviceID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = ""
	return nil
}

func (m *mockDeviceStore) DetachAllDevices(_ context.Context, vmID string) error {
	for _, d := range m.devices {
		if d.VMID == vmID {
			d.VMID = ""
		}
	}
	return nil
}

func (m *mockDeviceStore) GetDevicesByVM(_ context.Context, vmID string) ([]*domain.Device, error) {
	var result []*domain.Device
	for _, d := range m.devices {
		if d.VMID == vmID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (m *mockDeviceStore) DeleteDevice(_ context.Context, id string) error {
	delete(m.devices, id)
	return nil
}

// helper to create svc with devices support
func newSvcWithDevices() (*app.VMService, *mockStore, *mockRuntime, *mockDeviceStore) {
	store := newMockStore()
	rt := newMockRuntime()
	devStore := newMockDeviceStore()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithDeviceStore(devStore))
	return svc, store, rt, devStore
}
```

Then add device tests:

```go
// --- device tests ---

func TestCreateDevice(t *testing.T) {
	svc, _, _, devStore := newSvcWithDevices()

	d, err := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath:      "/dev/dri/renderD128",
		ContainerPath: "/dev/dri/renderD128",
		Permissions:   "rw",
		GID:           44,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.HostPath != "/dev/dri/renderD128" {
		t.Errorf("host_path = %q, want /dev/dri/renderD128", d.HostPath)
	}
	if d.Permissions != "rw" {
		t.Errorf("permissions = %q, want rw", d.Permissions)
	}
	if d.GID != 44 {
		t.Errorf("gid = %d, want 44", d.GID)
	}
	if _, ok := devStore.devices[d.ID]; !ok {
		t.Error("device not in store")
	}
}

func TestCreateDeviceValidation(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	tests := []struct {
		name   string
		params domain.CreateDeviceParams
	}{
		{"empty host_path", domain.CreateDeviceParams{ContainerPath: "/dev/x", Permissions: "rw"}},
		{"empty container_path", domain.CreateDeviceParams{HostPath: "/dev/null", Permissions: "rw"}},
		{"non-absolute container_path", domain.CreateDeviceParams{HostPath: "/dev/null", ContainerPath: "dev/x", Permissions: "rw"}},
		{"empty permissions", domain.CreateDeviceParams{HostPath: "/dev/null", ContainerPath: "/dev/x"}},
		{"invalid permissions char", domain.CreateDeviceParams{HostPath: "/dev/null", ContainerPath: "/dev/x", Permissions: "rwx"}},
		{"duplicate permissions", domain.CreateDeviceParams{HostPath: "/dev/null", ContainerPath: "/dev/x", Permissions: "rrw"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateDevice(context.Background(), tt.params)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDeleteDevice(t *testing.T) {
	svc, _, _, devStore := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rwm",
	})

	if err := svc.DeleteDevice(context.Background(), d.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := devStore.devices[d.ID]; ok {
		t.Error("device still in store")
	}
}

func TestDeleteDeviceAttached(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rwm",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "vm1", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDevice(context.Background(), d.ID, vm.ID)

	err := svc.DeleteDevice(context.Background(), d.ID)
	if !errors.Is(err, domain.ErrDeviceAttached) {
		t.Errorf("err = %v, want ErrDeviceAttached", err)
	}
}

func TestAttachDetachDevice(t *testing.T) {
	svc, store, rt, devStore := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "worker", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	// Attach
	if err := svc.AttachDevice(context.Background(), d.ID, vm.ID); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got, _ := devStore.GetDevice(context.Background(), d.ID)
	if got.VMID != vm.ID {
		t.Errorf("device vm_id = %q, want %q", got.VMID, vm.ID)
	}
	if _, ok := rt.containers[vm.ID]; !ok {
		t.Error("container not recreated after attach")
	}
	vmGot, _ := store.Get(context.Background(), vm.ID)
	if vmGot.State != domain.VMStateCreated {
		t.Errorf("vm state = %q, want created", vmGot.State)
	}

	// Detach
	if err := svc.DetachDevice(context.Background(), d.ID); err != nil {
		t.Fatalf("detach: %v", err)
	}
	got, _ = devStore.GetDevice(context.Background(), d.ID)
	if got.VMID != "" {
		t.Errorf("device vm_id = %q, want empty", got.VMID)
	}
}

func TestAttachDeviceRunningVMFails(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "running-vm", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	err := svc.AttachDevice(context.Background(), d.ID, vm.ID)
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}

func TestDeleteVMAutoDetachesDevices(t *testing.T) {
	svc, _, _, devStore := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rwm",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "ephemeral", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDevice(context.Background(), d.ID, vm.ID)

	if err := svc.DeleteVM(context.Background(), vm.ID); err != nil {
		t.Fatalf("delete vm: %v", err)
	}

	got, err := devStore.GetDevice(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("get device after vm delete: %v", err)
	}
	if got.VMID != "" {
		t.Errorf("device vm_id = %q, want empty after VM delete", got.VMID)
	}
}

func TestListDevices(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/zero", ContainerPath: "/dev/zero", Permissions: "r",
	})

	devices, err := svc.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 2 {
		t.Errorf("count = %d, want 2", len(devices))
	}
}

func TestGetDevice(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	created, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rwm", GID: 10,
	})

	got, err := svc.GetDevice(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GID != 10 {
		t.Errorf("gid = %d, want 10", got.GID)
	}
}
```

**Step 2: Run tests — expect failures (methods don't exist yet)**

Run: `go test ./internal/app/ -v -run TestCreateDevice`
Expected: FAIL — compile error, `WithDeviceStore` and device methods undefined

**Step 3: Implement `WithDeviceStore` and device methods in `vm_service.go`**

Add `deviceStore` field:

```go
type VMService struct {
	store       domain.VMStore
	runtime     domain.Runtime
	network     domain.Network
	driveStore  domain.DriveStore
	storage     domain.Storage
	deviceStore domain.DeviceStore
	config      VMServiceConfig
}
```

Add `WithDeviceStore` option:

```go
// WithDeviceStore enables device management.
func WithDeviceStore(deviceStore domain.DeviceStore) func(*VMService) {
	return func(s *VMService) {
		s.deviceStore = deviceStore
	}
}
```

Add `validatePermissions` helper:

```go
// validatePermissions checks that s contains only 'r', 'w', 'm' with no duplicates.
func validatePermissions(s string) bool {
	if len(s) == 0 || len(s) > 3 {
		return false
	}
	seen := make(map[rune]bool, 3)
	for _, c := range s {
		if c != 'r' && c != 'w' && c != 'm' {
			return false
		}
		if seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}
```

Add 6 device methods (matching the drive pattern):

```go
// CreateDevice registers a new device mapping.
func (s *VMService) CreateDevice(ctx context.Context, params domain.CreateDeviceParams) (*domain.Device, error) {
	if s.deviceStore == nil {
		return nil, fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	if params.HostPath == "" {
		return nil, fmt.Errorf("host_path is required: %w", domain.ErrValidation)
	}
	if params.ContainerPath == "" {
		return nil, fmt.Errorf("container_path is required: %w", domain.ErrValidation)
	}
	if !strings.HasPrefix(params.ContainerPath, "/") {
		return nil, fmt.Errorf("container_path must be absolute: %w", domain.ErrValidation)
	}
	if !validatePermissions(params.Permissions) {
		return nil, fmt.Errorf("permissions must be 1-3 chars of 'r','w','m' with no duplicates: %w", domain.ErrValidation)
	}

	d := &domain.Device{
		ID:            uuid.New().String(),
		HostPath:      params.HostPath,
		ContainerPath: params.ContainerPath,
		Permissions:   params.Permissions,
		GID:           params.GID,
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.deviceStore.CreateDevice(ctx, d); err != nil {
		return nil, fmt.Errorf("store create device: %w", err)
	}

	log.Info("device created", "id", d.ID, "host_path", d.HostPath)
	return d, nil
}

// GetDevice retrieves a device by ID.
func (s *VMService) GetDevice(ctx context.Context, id string) (*domain.Device, error) {
	return s.deviceStore.GetDevice(ctx, id)
}

// ListDevices returns all devices.
func (s *VMService) ListDevices(ctx context.Context) ([]*domain.Device, error) {
	return s.deviceStore.ListDevices(ctx)
}

// DeleteDevice removes a device. Fails if attached to a VM.
func (s *VMService) DeleteDevice(ctx context.Context, id string) error {
	d, err := s.deviceStore.GetDevice(ctx, id)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("device %q attached to VM %s: %w", d.HostPath, d.VMID, domain.ErrDeviceAttached)
	}

	if err := s.deviceStore.DeleteDevice(ctx, id); err != nil {
		return fmt.Errorf("store delete device: %w", err)
	}

	log.Info("device deleted", "id", id, "host_path", d.HostPath)
	return nil
}

// AttachDevice attaches a device to a stopped VM, recreating the container.
func (s *VMService) AttachDevice(ctx context.Context, deviceID, vmID string) error {
	vm, err := s.store.Get(ctx, vmID)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to attach devices: %w", domain.ErrInvalidState)
	}

	d, err := s.deviceStore.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("device already attached to VM %s: %w", d.VMID, domain.ErrDeviceAttached)
	}

	if err := s.deviceStore.AttachDevice(ctx, deviceID, vmID); err != nil {
		return fmt.Errorf("store attach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		s.deviceStore.DetachDevice(ctx, deviceID) //nolint:errcheck // best-effort rollback
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("device attached", "device", d.HostPath, "vm", vm.Name)
	return nil
}

// DetachDevice detaches a device from its VM, recreating the container.
func (s *VMService) DetachDevice(ctx context.Context, deviceID string) error {
	d, err := s.deviceStore.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if d.VMID == "" {
		return nil // already detached, idempotent
	}

	vm, err := s.store.Get(ctx, d.VMID)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to detach devices: %w", domain.ErrInvalidState)
	}

	if err := s.deviceStore.DetachDevice(ctx, deviceID); err != nil {
		return fmt.Errorf("store detach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("device detached", "device", d.HostPath, "vm", vm.Name)
	return nil
}
```

Add `"strings"` to the imports if not already present.

**Step 4: Update `DeleteVM` — auto-detach devices**

In `DeleteVM`, after the drive detach block:

```go
if s.deviceStore != nil {
	if err := s.deviceStore.DetachAllDevices(ctx, id); err != nil {
		log.Warn("detach devices failed", "id", id, "err", err)
	}
}
```

**Step 5: Update `recreateContainer` — include devices in OCI spec**

After building the drive mounts, query and build device info:

```go
func (s *VMService) recreateContainer(ctx context.Context, vm *domain.VM) error {
	// existing drive mount logic (unchanged)
	drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
	if err != nil {
		return fmt.Errorf("get drives: %w", err)
	}
	var mounts []domain.Mount
	for _, d := range drives {
		mounts = append(mounts, domain.Mount{
			HostPath:      s.storage.VolumePath(d.Name),
			ContainerPath: d.MountPath,
		})
	}

	// new: query attached devices
	var deviceInfos []domain.DeviceInfo
	if s.deviceStore != nil {
		devices, err := s.deviceStore.GetDevicesByVM(ctx, vm.ID)
		if err != nil {
			return fmt.Errorf("get devices: %w", err)
		}
		for _, dev := range devices {
			deviceInfos = append(deviceInfos, domain.DeviceInfo{
				HostPath:      dev.HostPath,
				ContainerPath: dev.ContainerPath,
				Permissions:   dev.Permissions,
				GID:           dev.GID,
			})
		}
	}

	if err := s.runtime.Delete(ctx, vm.ID); err != nil {
		log.Warn("runtime delete before recreate", "id", vm.ID, "err", err)
	}

	var createOpts []domain.CreateOpt
	if vm.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(vm.NetNSPath))
	}
	if len(mounts) > 0 {
		createOpts = append(createOpts, domain.WithMounts(mounts))
	}
	if len(deviceInfos) > 0 {
		createOpts = append(createOpts, domain.WithDevices(deviceInfos))
	}

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime, createOpts...); err != nil {
		return fmt.Errorf("runtime create: %w", err)
	}
	return nil
}
```

Note: `recreateContainer` currently assumes `s.driveStore` and `s.storage` are non-nil (it's only called from drive attach/detach). With devices, it can now be called when only `deviceStore` is set. Guard the drive query:

```go
if s.driveStore != nil && s.storage != nil {
	drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
	// ...
}
```

**Step 6: Run tests**

Run: `go test ./internal/app/ -v -count=1`
Expected: ALL PASS

**Step 7: Commit**

```
feat(app): add device CRUD, attach/detach, auto-detach on VM delete
```

---

### Task 7: OCI device translation in containerd runtime

**Files:**
- Modify: `internal/infra/containerd/runtime.go`

**Step 1: Handle `createCfg.Devices` in `Create()`**

After the mounts block (line ~124), add device handling:

```go
if len(createCfg.Devices) > 0 {
	for _, dev := range createCfg.Devices {
		fi, err := os.Stat(dev.HostPath)
		if err != nil {
			return fmt.Errorf("stat device %s: %w", dev.HostPath, err)
		}
		stat, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot get device info for %s", dev.HostPath)
		}

		devType := "c" // char device
		if fi.Mode()&os.ModeDevice != 0 && fi.Mode()&os.ModeCharDevice == 0 {
			devType = "b" // block device
		}

		major := int64(unix.Major(stat.Rdev))
		minor := int64(unix.Minor(stat.Rdev))
		gid := dev.GID

		specOpts = append(specOpts, oci.WithLinuxDevice(dev.ContainerPath, devType, major, minor, func(d *specs.LinuxDevice) error {
			d.GID = &gid
			return nil
		}))

		specOpts = append(specOpts, oci.WithDevices(dev.ContainerPath, dev.Permissions))
	}
}
```

Wait — `oci.WithLinuxDevice` and `oci.WithDevices` may not match the containerd v2 API exactly. Instead, use raw spec manipulation via a custom `oci.SpecOpts`:

```go
if len(createCfg.Devices) > 0 {
	specOpts = append(specOpts, withDevices(createCfg.Devices))
}
```

Define `withDevices` as a local helper:

```go
// withDevices returns an OCI spec option that adds device nodes and cgroup allow rules.
func withDevices(devices []domain.DeviceInfo) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		for _, dev := range devices {
			fi, err := os.Stat(dev.HostPath)
			if err != nil {
				return fmt.Errorf("stat device %s: %w", dev.HostPath, err)
			}
			stat, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot get device info for %s", dev.HostPath)
			}

			devType := "c"
			if fi.Mode()&os.ModeDevice != 0 && fi.Mode()&os.ModeCharDevice == 0 {
				devType = "b"
			}
			major := int64(unix.Major(stat.Rdev))
			minor := int64(unix.Minor(stat.Rdev))

			gid := dev.GID
			s.Linux.Devices = append(s.Linux.Devices, specs.LinuxDevice{
				Path:  dev.ContainerPath,
				Type:  devType,
				Major: major,
				Minor: minor,
				GID:   &gid,
			})

			s.Linux.Resources.Devices = append(s.Linux.Resources.Devices, specs.LinuxDeviceCgroup{
				Allow:  true,
				Type:   devType,
				Major:  &major,
				Minor:  &minor,
				Access: dev.Permissions,
			})
		}
		return nil
	}
}
```

Add required imports:

```go
"golang.org/x/sys/unix"
"github.com/containerd/containerd/v2/core/containers"
```

Note: The `oci.Spec` type alias and the `oci.Client` parameter depend on containerd v2 API. Check the exact signatures in `containerd/v2/pkg/oci`. The function signature for `oci.SpecOpts` is:
```go
type SpecOpts func(context.Context, Client, *containers.Container, *Spec) error
```
where `Client` and `Spec` are in the `oci` package.

**Step 2: Verify it compiles**

Run: `mise run build`
Expected: PASS

**Step 3: Commit**

```
feat(containerd): translate attached devices into OCI spec entries
```

---

### Task 8: HTTP handlers — 6 device routes

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

**Step 1: Add request/response types**

```go
type createDeviceRequest struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Permissions   string `json:"permissions"`
	GID           uint32 `json:"gid"`
}

type attachDeviceRequest struct {
	VMID string `json:"vm_id"`
}

type deviceResponse struct {
	ID            string  `json:"id"`
	HostPath      string  `json:"host_path"`
	ContainerPath string  `json:"container_path"`
	Permissions   string  `json:"permissions"`
	GID           uint32  `json:"gid"`
	VMID          *string `json:"vm_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
}
```

**Step 2: Add `deviceToResponse` helper**

```go
func deviceToResponse(d *domain.Device) deviceResponse {
	r := deviceResponse{
		ID:            d.ID,
		HostPath:      d.HostPath,
		ContainerPath: d.ContainerPath,
		Permissions:   d.Permissions,
		GID:           d.GID,
		CreatedAt:     d.CreatedAt.UTC().Format(timeFormatJSON),
	}
	if d.VMID != "" {
		r.VMID = &d.VMID
	}
	return r
}
```

**Step 3: Add 6 device handler functions**

```go
// --- device handlers ---

func handleCreateDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req createDeviceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		d, err := svc.CreateDevice(r.Context(), domain.CreateDeviceParams{
			HostPath:      req.HostPath,
			ContainerPath: req.ContainerPath,
			Permissions:   req.Permissions,
			GID:           req.GID,
		})
		if err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, deviceToResponse(d))
	}
}

func handleListDevices(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, err := svc.ListDevices(r.Context())
		if err != nil {
			mapError(w, err)
			return
		}
		resp := make([]deviceResponse, len(devices))
		for i, d := range devices {
			resp[i] = deviceToResponse(d)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		d, err := svc.GetDevice(r.Context(), id)
		if err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, deviceToResponse(d))
	}
}

func handleDeleteDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DeleteDevice(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleAttachDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req attachDeviceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if err := svc.AttachDevice(r.Context(), id, req.VMID); err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func handleDetachDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DetachDevice(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
```

**Step 4: Register routes in `NewHandler`**

After the drive routes and before the webhook route:

```go
mux.HandleFunc("POST /v1/devices", handleCreateDevice(svc))
mux.HandleFunc("GET /v1/devices", handleListDevices(svc))
mux.HandleFunc("GET /v1/devices/{id}", handleGetDevice(svc))
mux.HandleFunc("DELETE /v1/devices/{id}", handleDeleteDevice(svc))
mux.HandleFunc("POST /v1/devices/{id}/attach", handleAttachDevice(svc))
mux.HandleFunc("POST /v1/devices/{id}/detach", handleDetachDevice(svc))
```

**Step 5: Add `ErrDeviceAttached` to `mapError`**

```go
case errors.Is(err, domain.ErrDeviceAttached):
	writeError(w, http.StatusConflict, err.Error())
```

**Step 6: Verify it compiles**

Run: `mise run build`
Expected: PASS

**Step 7: Commit**

```
feat(httpapi): add 6 device passthrough routes
```

---

### Task 9: Daemon wiring

**Files:**
- Modify: `cmd/daemon.go`

**Step 1: Wire DeviceStore into VMService**

After the storage wiring (line ~110), add:

```go
svcOpts = append(svcOpts, app.WithDeviceStore(store))
```

The SQLite `Store` already implements `domain.DeviceStore` (from Task 5), so pass the same `store` instance.

**Step 2: Verify it compiles**

Run: `mise run build`
Expected: PASS

**Step 3: Run all tests**

Run: `go test ./... -count=1`
Expected: ALL PASS

**Step 4: Commit**

```
feat(daemon): wire device store into VMService
```

---

### Task 10: Manual integration smoke test

This task is manual — no code changes.

**Step 1: Build and run**

```bash
mise run build
# Start daemon (with appropriate flags)
```

**Step 2: Register a device**

```bash
curl -s -X POST http://127.0.0.1:9600/v1/devices \
  -d '{"host_path":"/dev/null","container_path":"/dev/null","permissions":"rwm","gid":0}' | jq .
```

Expected: 201 with device JSON.

**Step 3: List and get**

```bash
curl -s http://127.0.0.1:9600/v1/devices | jq .
curl -s http://127.0.0.1:9600/v1/devices/{id} | jq .
```

**Step 4: Create a VM, attach device, start, verify**

```bash
# Create VM
curl -s -X POST http://127.0.0.1:9600/v1/vms \
  -d '{"name":"test-dev","role":"agent"}' | jq .

# Attach device
curl -s -X POST http://127.0.0.1:9600/v1/devices/{device_id}/attach \
  -d '{"vm_id":"<vm_id>"}' | jq .

# Start VM
curl -s -X POST http://127.0.0.1:9600/v1/vms/{vm_id}/start

# Exec to verify device exists
curl -s -X POST http://127.0.0.1:9600/v1/vms/{vm_id}/exec \
  -d '{"cmd":["ls","-la","/dev/null"]}' | jq .
```

**Step 5: Stop VM, detach, delete**

```bash
curl -s -X POST http://127.0.0.1:9600/v1/vms/{vm_id}/stop
curl -s -X POST http://127.0.0.1:9600/v1/devices/{device_id}/detach
curl -s -X DELETE http://127.0.0.1:9600/v1/devices/{device_id}
curl -s -X DELETE http://127.0.0.1:9600/v1/vms/{vm_id}
```
