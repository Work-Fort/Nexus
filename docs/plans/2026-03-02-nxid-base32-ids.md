# Base32 Resource IDs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace UUID-based resource IDs with random uint64 encoded as lowercase base32, and add ref-based resolution (ID or name) to all API endpoints.

**Architecture:** New `pkg/nxid` package generates 13-char base32 IDs from random uint64s. All three resource types (VMs, drives, devices) use nxid. Devices gain a required `name` field. API endpoints accept either base32 ID or name — resolution tries base32 decode first, otherwise name lookup. Names that are valid base32 are rejected at creation time.

**Tech Stack:** Go `encoding/base32`, `crypto/rand`

---

### Task 1: `pkg/nxid` — ID generation and validation

**Files:**
- Create: `pkg/nxid/nxid.go`
- Create: `pkg/nxid/nxid_test.go`

**Context:** This package provides the core ID and name primitives used by all resource types. IDs are random uint64 values encoded as 13-char lowercase base32 (RFC 4648, no padding). Names are user-chosen identifiers validated against format rules and rejected if they could be confused with a base32 ID.

**Implementation — `pkg/nxid/nxid.go`:**

```go
package nxid

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"regexp"
)

// encoding is lowercase RFC 4648 base32 without padding.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// nameRe matches valid resource names: 1-24 lowercase alphanumeric chars and dashes,
// must start and end with a letter or digit.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,22}[a-z0-9])?$`)

// New generates a random uint64 and returns it as a 13-char lowercase base32 string.
func New() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("nxid: crypto/rand failed: " + err.Error())
	}
	return encoding.EncodeToString(buf[:])
}

// IsNxID returns true if s is a valid base32-encoded nxid (exactly 8 bytes decoded).
func IsNxID(s string) bool {
	b, err := encoding.DecodeString(s)
	return err == nil && len(b) == 8
}

// ValidateName checks that name follows the naming rules:
//   - 1–24 characters
//   - starts and ends with [a-z0-9]
//   - body contains only [a-z0-9-]
//   - must NOT be a valid base32 ID (to avoid ambiguity)
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name must be 1-24 chars, start/end with a-z0-9, contain only a-z0-9 and dashes")
	}
	if IsNxID(name) {
		return fmt.Errorf("name cannot be a valid resource ID")
	}
	return nil
}
```

**Tests — `pkg/nxid/nxid_test.go`:**

Test cases:
- `TestNew`: generates non-empty 13-char string; two calls produce different values
- `TestIsNxID`: valid nxid returns true; names with dashes return false; wrong length returns false; empty string returns false
- `TestValidateName`:
  - Valid: `"my-vm"`, `"a"`, `"a-b-c"`, `"vm1"`, `"abc-def-123"` (24 chars)
  - Invalid empty: `""`
  - Invalid too long: 25 chars
  - Invalid starts with dash: `"-abc"`
  - Invalid ends with dash: `"abc-"`
  - Invalid uppercase: `"MyVM"`
  - Invalid special chars: `"my_vm"`, `"my.vm"`
  - Invalid base32 collision: generate an nxid with `New()`, try to use it as a name → error "cannot be a valid resource ID"

**Commit:** `feat: add pkg/nxid for base32 ID generation and name validation`

---

### Task 2: Domain — add Name to Device, add Resolve to store interfaces

**Files:**
- Modify: `internal/domain/device.go` — add `Name` field to `Device` and `CreateDeviceParams`
- Modify: `internal/domain/ports.go` — add `Resolve` method to `VMStore`, `ResolveDrive` to `DriveStore`, `ResolveDevice` + `GetDeviceByName` to `DeviceStore`

**Context:** Devices currently have no name. All three resource types need a `Resolve(ctx, ref)` method that looks up by ID-or-name. This is the store's responsibility because it's a data access concern.

**Changes to `internal/domain/device.go`:**

Add `Name` field to `Device` struct (after `ID`):
```go
type Device struct {
	ID            string
	Name          string    // user-chosen name for the device mapping
	HostPath      string
	...
}
```

Add `Name` field to `CreateDeviceParams`:
```go
type CreateDeviceParams struct {
	Name          string
	HostPath      string
	...
}
```

**Changes to `internal/domain/ports.go`:**

Add to `VMStore`:
```go
Resolve(ctx context.Context, ref string) (*VM, error)
```

Add to `DriveStore`:
```go
ResolveDrive(ctx context.Context, ref string) (*Drive, error)
```

Add to `DeviceStore`:
```go
GetDeviceByName(ctx context.Context, name string) (*Device, error)
ResolveDevice(ctx context.Context, ref string) (*Device, error)
```

**Commit:** `feat(domain): add Name to Device and Resolve methods to store interfaces`

---

### Task 3: Migration 005 — add name column to devices

**Files:**
- Create: `internal/infra/sqlite/migrations/005_add_device_name.sql`

**Context:** The devices table currently has no `name` column. We need to add it as `TEXT UNIQUE NOT NULL`. Since SQLite's `ALTER TABLE ADD COLUMN` requires a default for NOT NULL, we recreate the table. Existing rows (dev-only) get their `id` as the default name.

**Migration:**

```sql
-- +goose Up
CREATE TABLE devices_new (
    id              TEXT PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    host_path       TEXT NOT NULL,
    container_path  TEXT NOT NULL,
    permissions     TEXT NOT NULL DEFAULT 'rwm',
    gid             INTEGER NOT NULL DEFAULT 0,
    vm_id           TEXT REFERENCES vms(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO devices_new (id, name, host_path, container_path, permissions, gid, vm_id, created_at)
    SELECT id, id, host_path, container_path, permissions, gid, vm_id, created_at FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
CREATE INDEX idx_devices_vm_id ON devices(vm_id);

-- +goose Down
CREATE TABLE devices_old (
    id              TEXT PRIMARY KEY,
    host_path       TEXT NOT NULL,
    container_path  TEXT NOT NULL,
    permissions     TEXT NOT NULL DEFAULT 'rwm',
    gid             INTEGER NOT NULL DEFAULT 0,
    vm_id           TEXT REFERENCES vms(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO devices_old (id, host_path, container_path, permissions, gid, vm_id, created_at)
    SELECT id, host_path, container_path, permissions, gid, vm_id, created_at FROM devices;
DROP TABLE devices;
ALTER TABLE devices_old RENAME TO devices;
CREATE INDEX idx_devices_vm_id ON devices(vm_id);
```

**Commit:** `feat(sqlite): add name column to devices table`

---

### Task 4: SQL queries — add device name queries + resolve queries for all three

**Files:**
- Modify: `internal/infra/sqlite/queries.sql` — add resolve queries, update device insert/select

**Context:** Three new resolve queries use `WHERE id = ? OR name = ?` which hits both the PRIMARY KEY index and the UNIQUE name index. Device queries need to include the new `name` column. After editing, run `sqlc generate`.

**Changes to `internal/infra/sqlite/queries.sql`:**

Update `InsertDevice` to include `name`:
```sql
-- name: InsertDevice :exec
INSERT INTO devices (id, name, host_path, container_path, permissions, gid, vm_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
```

Update all device SELECT queries (`GetDevice`, `ListDevices`, `GetDevicesByVM`) to include `name` in the column list:
```sql
-- name: GetDevice :one
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE id = ?;
```

Add new device query:
```sql
-- name: GetDeviceByName :one
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE name = ?;
```

Add three resolve queries (one per resource):
```sql
-- name: ResolveVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path
FROM vms WHERE id = ? OR name = ?;

-- name: ResolveDrive :one
SELECT id, name, size_bytes, mount_path, vm_id, created_at
FROM drives WHERE id = ? OR name = ?;

-- name: ResolveDevice :one
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE id = ? OR name = ?;
```

Then run:
```bash
sqlc generate
```

Check if sqlc generates any type renames that need fixing in `sqlc.yaml`.

**Commit:** `feat(sqlite): add resolve and device name queries`

---

### Task 5: Store — implement Resolve methods, update device methods for name

**Files:**
- Modify: `internal/infra/sqlite/store.go`

**Context:** The store needs three new `Resolve*` methods and the device methods need to handle the new `name` column. The resolve methods call the new sqlc-generated query functions with `(ref, ref)` — same value for both the `id` and `name` parameters. Also add `GetDeviceByName`.

**New methods on `Store`:**

```go
func (s *Store) Resolve(ctx context.Context, ref string) (*domain.VM, error) {
	row, err := s.q.ResolveVM(ctx, ResolveVMParams{ID: ref, Name: ref})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("resolve vm: %w", err)
	}
	return vmFromRow(row)
}

func (s *Store) ResolveDrive(ctx context.Context, ref string) (*domain.Drive, error) {
	row, err := s.q.ResolveDrive(ctx, ResolveDriveParams{ID: ref, Name: ref})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("resolve drive: %w", err)
	}
	return driveFromRow(row)
}

func (s *Store) ResolveDevice(ctx context.Context, ref string) (*domain.Device, error) {
	row, err := s.q.ResolveDevice(ctx, ResolveDeviceParams{ID: ref, Name: ref})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("resolve device: %w", err)
	}
	return deviceFromRow(row)
}

func (s *Store) GetDeviceByName(ctx context.Context, name string) (*domain.Device, error) {
	row, err := s.q.GetDeviceByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get device by name: %w", err)
	}
	return deviceFromRow(row)
}
```

**Update `CreateDevice`** — add `Name` to the insert params.

**Update `deviceFromRow`** — set `d.Name = row.Name`.

Note: The sqlc-generated `Device` struct will now include `Name string`. The `ResolveVM` query returns the same columns as `GetVM`, so sqlc may generate a new params type `ResolveVMParams{ID string, Name string}` — adjust accordingly.

**Commit:** `feat(sqlite): implement resolve methods and device name support`

---

### Task 6: Service — use nxid, validate names, resolve for lookups

**Files:**
- Modify: `internal/app/vm_service.go` — replace `uuid.New().String()` with `nxid.New()`, add name validation, change ID params to ref params
- Modify: `internal/app/vm_service_test.go` — update mocks for new interface methods, add name validation tests

**Context:** This is the largest change. Every service method that takes an `id` parameter from external callers switches to using `store.Resolve*` instead of `store.Get*`. Name validation using `nxid.ValidateName` is added to all create methods. The `uuid` import is replaced with `nxid`.

**Import change:**
```go
// Remove:
"github.com/google/uuid"
// Add:
"github.com/Work-Fort/Nexus/pkg/nxid"
```

**ID generation** — three places:
```go
// CreateVM (line ~105):
ID: nxid.New(),

// CreateDrive (line ~323):
ID: nxid.New(),

// CreateDevice (line ~484):
ID: nxid.New(),
```

**Name validation** — add to all three create methods, after the existing `name is required` check:
```go
if err := nxid.ValidateName(params.Name); err != nil {
	return nil, fmt.Errorf("invalid name: %v: %w", err, domain.ErrValidation)
}
```

For `CreateDevice`, also add the name-required check (it didn't have one):
```go
if params.Name == "" {
	return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
}
```

**Resolve for lookups** — change all methods that take an external `id` param:

| Method | Old call | New call |
|--------|----------|----------|
| `GetVM(ctx, id)` | `s.store.Get(ctx, id)` | `s.store.Resolve(ctx, ref)` |
| `DeleteVM(ctx, id)` | `s.store.Get(ctx, id)` | `s.store.Resolve(ctx, ref)` |
| `StartVM(ctx, id)` | `s.store.Get(ctx, id)` | `s.store.Resolve(ctx, ref)` |
| `StopVM(ctx, id)` | `s.store.Get(ctx, id)` | `s.store.Resolve(ctx, ref)` |
| `ExecVM(ctx, id, cmd)` | `s.store.Get(ctx, id)` | `s.store.Resolve(ctx, ref)` |
| `GetDrive(ctx, id)` | `s.driveStore.GetDrive(ctx, id)` | `s.driveStore.ResolveDrive(ctx, ref)` |
| `DeleteDrive(ctx, id)` | `s.driveStore.GetDrive(ctx, id)` | `s.driveStore.ResolveDrive(ctx, ref)` |
| `AttachDrive(ctx, driveID, vmID)` | `s.store.Get(ctx, vmID)` + `s.driveStore.GetDrive(ctx, driveID)` | `s.store.Resolve(ctx, vmRef)` + `s.driveStore.ResolveDrive(ctx, driveRef)` |
| `DetachDrive(ctx, driveID)` | `s.driveStore.GetDrive(ctx, driveID)` | `s.driveStore.ResolveDrive(ctx, driveRef)` |
| `GetDevice(ctx, id)` | `s.deviceStore.GetDevice(ctx, id)` | `s.deviceStore.ResolveDevice(ctx, ref)` |
| `DeleteDevice(ctx, id)` | `s.deviceStore.GetDevice(ctx, id)` | `s.deviceStore.ResolveDevice(ctx, ref)` |
| `AttachDevice(ctx, deviceID, vmID)` | `s.store.Get(ctx, vmID)` + `s.deviceStore.GetDevice(ctx, deviceID)` | `s.store.Resolve(ctx, vmRef)` + `s.deviceStore.ResolveDevice(ctx, deviceRef)` |
| `DetachDevice(ctx, deviceID)` | `s.deviceStore.GetDevice(ctx, deviceID)` | `s.deviceStore.ResolveDevice(ctx, deviceRef)` |

**Internal lookups stay as Get** — `recreateContainer` uses `s.store.Get(ctx, vm.ID)` where `vm.ID` is already a resolved ID. Same for `DetachDrive`/`DetachDevice` loading the VM via `d.VMID`. The webhook handler's `s.store.GetByName(ctx, name)` can switch to `s.store.Resolve(ctx, name)`.

**Rename parameter names** from `id` to `ref` in method signatures for clarity:
```go
func (s *VMService) GetVM(ctx context.Context, ref string) (*domain.VM, error) {
```

**Device create** — add `Name` field:
```go
d := &domain.Device{
	ID:            nxid.New(),
	Name:          params.Name,
	...
}
```

**Test updates (`vm_service_test.go`):**
- Add `Resolve` method to `mockVMStore` (looks up by ID first, then iterates map for name match)
- Add `ResolveDrive` method to `mockDriveStore`
- Add `ResolveDevice` and `GetDeviceByName` methods to `mockDeviceStore`
- Add test: `TestCreateVMInvalidName` — empty, too long, starts with dash, ends with dash, uppercase, base32 collision
- Add test: `TestCreateDriveInvalidName` — same cases
- Add test: `TestCreateDeviceInvalidName` — same cases plus name-required
- Update existing tests that pass `vm.ID` to service methods — these still work since Resolve finds by ID
- Add test: `TestGetVMByName` — create VM, get by name, verify same VM returned
- Add test: `TestDeleteVMByName` — create VM, delete by name

**Commit:** `feat(app): use nxid for ID generation, add name validation and ref-based lookups`

---

### Task 7: HTTP handlers — add name to device requests/responses

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

**Context:** The device create request and response types need the `name` field. The attach request bodies that take `vm_id` should also work with VM names — this already works because the service layer resolves refs. No route changes needed — `{id}` in the URL is now a ref but the parameter name doesn't affect clients.

**Changes:**

Update `createDeviceRequest`:
```go
type createDeviceRequest struct {
	Name          string `json:"name"`
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Permissions   string `json:"permissions"`
	GID           uint32 `json:"gid"`
}
```

Update `handleCreateDevice` to pass `Name`:
```go
d, err := svc.CreateDevice(r.Context(), domain.CreateDeviceParams{
	Name:          req.Name,
	HostPath:      req.HostPath,
	...
})
```

Update `deviceResponse`:
```go
type deviceResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	HostPath      string  `json:"host_path"`
	ContainerPath string  `json:"container_path"`
	Permissions   string  `json:"permissions"`
	GID           uint32  `json:"gid"`
	VMID          *string `json:"vm_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
}
```

Update `deviceToResponse` to include `Name`:
```go
func deviceToResponse(d *domain.Device) deviceResponse {
	resp := deviceResponse{
		ID:            d.ID,
		Name:          d.Name,
		...
	}
	...
}
```

**Commit:** `feat(httpapi): add name field to device request/response`

---

### Task 8: Runtime — replace uuid in exec ID

**Files:**
- Modify: `internal/infra/containerd/runtime.go`

**Context:** The `Exec` method uses `uuid.New().String()[:8]` to generate unique exec process IDs. Replace with `nxid.New()` to eliminate the last uuid dependency. The exec ID just needs to be unique within the container.

**Change in `Exec()` (line ~315):**
```go
// Old:
execID := fmt.Sprintf("%s-exec-%s", id, uuid.New().String()[:8])
// New:
execID := fmt.Sprintf("%s-exec-%s", id, nxid.New())
```

**Update imports** — remove `"github.com/google/uuid"`, add `"github.com/Work-Fort/Nexus/pkg/nxid"`.

**Commit:** `refactor(containerd): use nxid for exec process IDs`

---

### Task 9: Remove uuid dependency

**Files:**
- Modify: `go.mod`

**Context:** After tasks 6 and 8, no code imports `github.com/google/uuid`. Run `go mod tidy` to remove it from `go.mod` and `go.sum`.

```bash
go mod tidy
```

Verify: `grep uuid go.mod` should return empty.

**Commit:** `chore: remove unused uuid dependency`

---

## Files Modified Summary

| File | Change |
|------|--------|
| `pkg/nxid/nxid.go` | **NEW** — ID generation, IsNxID, ValidateName |
| `pkg/nxid/nxid_test.go` | **NEW** — tests |
| `internal/domain/device.go` | Add `Name` to Device + CreateDeviceParams |
| `internal/domain/ports.go` | Add Resolve to VMStore, ResolveDrive to DriveStore, ResolveDevice + GetDeviceByName to DeviceStore |
| `internal/infra/sqlite/migrations/005_add_device_name.sql` | **NEW** — add name column to devices |
| `internal/infra/sqlite/queries.sql` | Update device queries for name, add 3 resolve queries, add GetDeviceByName |
| `internal/infra/sqlite/store.go` | Resolve*, GetDeviceByName, update CreateDevice + deviceFromRow for name |
| `internal/app/vm_service.go` | nxid.New(), name validation, ref-based lookups, device Name field |
| `internal/app/vm_service_test.go` | Mock updates, name validation tests, ref-based lookup tests |
| `internal/infra/httpapi/handler.go` | Device name in request/response types |
| `internal/infra/containerd/runtime.go` | nxid for exec IDs |
| `go.mod` / `go.sum` | Remove uuid dependency |

## Verification

1. `go build ./...` — all packages compile
2. `go test ./pkg/nxid/...` — nxid unit tests pass
3. `go test ./internal/...` — all service + store tests pass
4. `go vet ./...` — no issues
5. `grep -r "google/uuid" --include="*.go" .` — no uuid imports remain
6. Build and start daemon with `mise run build && mise run run`
7. `curl -s localhost:9600/v1/vms | jq '.[].id'` — IDs are 13-char base32, not UUIDs
8. Create a VM with name `my-vm`, then `GET /v1/vms/my-vm` — resolves by name
9. `GET /v1/vms/{base32-id}` — resolves by ID
10. Create device with name, verify name in response
11. Try creating a resource with a valid base32 string as name — rejected
