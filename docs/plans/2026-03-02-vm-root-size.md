# VM Root Size Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `root_size` field to VMs that limits the writable layer size using btrfs simple quotas.

**Architecture:** The `root_size` string flows from the HTTP API through the domain layer as bytes, into `CreateConfig` as a functional option. The containerd runtime adapter applies the quota via `btrfs qgroup limit` on the snapshot subvolume after container creation. Expand is a `PATCH` that updates the qgroup limit in-place.

**Tech Stack:** Go, btrfs squotas, containerd Go client, sqlc, huma v2, existing `pkg/bytesize`

---

### Task 1: Add `Format` to `pkg/bytesize`

The `Parse` function exists but there's no `Format` to convert bytes back to
human-readable strings for API responses.

**Files:**
- Modify: `pkg/bytesize/bytesize.go`
- Modify: `pkg/bytesize/bytesize_test.go`

**Step 1: Write the failing test**

Add to `pkg/bytesize/bytesize_test.go`:

```go
func TestFormat(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{512, "512"},
		{1_000_000_000, "1G"},
		{2_000_000_000_000, "2T"},
		{500_000_000, "500M"},
		{1_500_000_000, "1.5G"},
		{1_000_000, "1M"},
		{1_000, "1K"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := bytesize.Format(tt.input)
			if got != tt.want {
				t.Errorf("Format(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `mise run test -- -run TestFormat ./pkg/bytesize/ -v`
Expected: FAIL — `bytesize.Format` undefined

**Step 3: Write minimal implementation**

Add to `pkg/bytesize/bytesize.go`:

```go
// Format converts bytes to a human-readable size string using SI suffixes.
// Uses the largest whole suffix that divides evenly, falling back to one
// decimal place if needed. Zero returns "0".
func Format(n uint64) string {
	if n == 0 {
		return "0"
	}

	type unit struct {
		suffix string
		size   uint64
	}
	units := []unit{
		{"T", 1_000_000_000_000},
		{"G", 1_000_000_000},
		{"M", 1_000_000},
		{"K", 1_000},
	}

	for _, u := range units {
		if n >= u.size {
			if n%u.size == 0 {
				return fmt.Sprintf("%d%s", n/u.size, u.suffix)
			}
			val := float64(n) / float64(u.size)
			s := fmt.Sprintf("%.1f%s", val, u.suffix)
			return s
		}
	}
	return fmt.Sprintf("%d", n)
}
```

**Step 4: Run test to verify it passes**

Run: `mise run test -- -run TestFormat ./pkg/bytesize/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/bytesize/bytesize.go pkg/bytesize/bytesize_test.go
git commit -m "feat(bytesize): add Format function for bytes to human-readable strings"
```

---

### Task 2: Add `RootSize` to domain model

**Files:**
- Modify: `internal/domain/vm.go`
- Modify: `internal/domain/ports.go`

**Step 1: Add `RootSize` field to `VM` and `CreateVMParams`**

In `internal/domain/vm.go`, add `RootSize int64` to the `VM` struct (after `DNSConfig`):

```go
type VM struct {
	// ... existing fields ...
	DNSConfig *DNSConfig
	RootSize  int64 // bytes, 0 = unlimited
	CreatedAt time.Time
	// ...
}
```

Add `RootSize` to `CreateVMParams`:

```go
type CreateVMParams struct {
	Name      string
	Role      VMRole
	Image     string
	Runtime   string
	DNSConfig *DNSConfig
	RootSize  int64 // bytes, 0 = unlimited
}
```

**Step 2: Add `WithRootSize` functional option to `CreateConfig`**

In `internal/domain/ports.go`, add field and option:

```go
type CreateConfig struct {
	NetNSPath      string
	Mounts         []Mount
	Devices        []DeviceInfo
	ResolvConfPath string
	RootSize       int64 // bytes, 0 = no quota
}

// WithRootSize sets a btrfs quota limit on the container snapshot.
func WithRootSize(size int64) CreateOpt {
	return func(c *CreateConfig) {
		c.RootSize = size
	}
}
```

**Step 3: Add `UpdateRootSize` to `VMStore` interface**

In `internal/domain/ports.go`, add to the `VMStore` interface:

```go
type VMStore interface {
	// ... existing methods ...
	UpdateRootSize(ctx context.Context, id string, rootSize int64) error
}
```

**Step 4: Run tests to verify nothing broke**

Run: `mise run test`
Expected: Compilation errors in sqlite store (missing `UpdateRootSize`). That's
expected — we'll fix it in Task 3.

**Step 5: Commit**

```bash
git add internal/domain/vm.go internal/domain/ports.go
git commit -m "feat(domain): add RootSize field to VM and CreateVMParams"
```

---

### Task 3: Add database migration and sqlc queries

**Files:**
- Create: `internal/infra/sqlite/migrations/007_add_vm_root_size.sql`
- Modify: `internal/infra/sqlite/queries.sql`
- Modify: `internal/infra/sqlite/store.go` (after sqlc regeneration)

**Step 1: Create migration**

```sql
-- +goose Up
ALTER TABLE vms ADD COLUMN root_size INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE vms DROP COLUMN root_size;
```

**Step 2: Update sqlc queries**

Add `root_size` to every VM SELECT and INSERT in `internal/infra/sqlite/queries.sql`.

For `InsertVM`:
```sql
-- name: InsertVM :exec
INSERT INTO vms (id, name, role, image, runtime, state, created_at, ip, gateway, netns_path, dns_servers, dns_search, root_size)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
```

For all SELECT queries (`GetVM`, `GetVMByName`, `ListVMs`, `ListVMsByRole`, `ResolveVM`),
add `root_size` to the column list:
```sql
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size
FROM vms ...
```

Add the update query:
```sql
-- name: UpdateVMRootSize :exec
UPDATE vms SET root_size = ? WHERE id = ?;
```

**Step 3: Regenerate sqlc**

Run: `mise run sqlc`

**Step 4: Implement `UpdateRootSize` in store**

Add to `internal/infra/sqlite/store.go`:

```go
func (s *Store) UpdateRootSize(ctx context.Context, id string, rootSize int64) error {
	return s.q.UpdateVMRootSize(ctx, UpdateVMRootSizeParams{RootSize: rootSize, ID: id})
}
```

Update the `Create` method to include `root_size` in the `InsertVM` call.
Update all `scanVM` / row-to-domain mapping to include the `RootSize` field.

**Step 5: Run tests**

Run: `mise run test`
Expected: PASS (existing store tests should pass with the new column defaulting to 0)

**Step 6: Commit**

```bash
git add internal/infra/sqlite/
git commit -m "feat(sqlite): add root_size column and queries"
```

---

### Task 4: Add root size validation and passing in VMService

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`

**Step 1: Write failing tests**

Add to `internal/app/vm_service_test.go`:

```go
func TestCreateVMWithRootSize(t *testing.T) {
	store, rt, net := setupMocks(t)
	svc := app.NewVMService(store, rt, net)

	vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "sized-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 1_000_000_000, // 1G
	})
	if err != nil {
		t.Fatalf("CreateVM error: %v", err)
	}
	if vm.RootSize != 1_000_000_000 {
		t.Errorf("RootSize = %d, want 1000000000", vm.RootSize)
	}
}

func TestCreateVMRootSizeTooSmall(t *testing.T) {
	store, rt, net := setupMocks(t)
	svc := app.NewVMService(store, rt, net)

	_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "tiny-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 1_000_000, // 1M — below 64M minimum
	})
	if err == nil {
		t.Fatal("expected error for root_size below minimum")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `mise run test -- -run TestCreateVMWithRootSize -v ./internal/app/`
Expected: FAIL — validation not implemented, RootSize not set on VM

**Step 3: Implement in `CreateVM`**

In `internal/app/vm_service.go`, add validation after existing checks in `CreateVM`:

```go
const minRootSize = 64 * 1_000_000 // 64M

// After existing validation...
if params.RootSize < 0 {
	return nil, fmt.Errorf("root_size must be positive: %w", domain.ErrValidation)
}
if params.RootSize > 0 && params.RootSize < minRootSize {
	return nil, fmt.Errorf("root_size minimum is 64M: %w", domain.ErrValidation)
}
```

Set the field on the VM struct:

```go
vm := &domain.VM{
	// ... existing fields ...
	RootSize:  params.RootSize,
}
```

Pass `WithRootSize` to the runtime:

```go
if params.RootSize > 0 {
	createOpts = append(createOpts, domain.WithRootSize(params.RootSize))
}
```

**Step 4: Run tests**

Run: `mise run test -- -run TestCreateVM -v ./internal/app/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/app/vm_service.go internal/app/vm_service_test.go
git commit -m "feat(app): validate and pass root_size in CreateVM"
```

---

### Task 5: Apply btrfs quota in containerd runtime

This is where the quota actually gets enforced. After `NewContainer` creates the
snapshot, we call `btrfs qgroup limit` on the snapshot subvolume.

**Files:**
- Modify: `internal/infra/containerd/runtime.go`

**Step 1: Implement quota application**

In `runtime.go`, after the `NewContainer` call in `Create`, add:

```go
if createCfg.RootSize > 0 {
	if err := r.setSnapshotQuota(ctx, id+"-snap", createCfg.RootSize); err != nil {
		// Clean up the container we just created
		container, _ := r.client.LoadContainer(ctx, id)
		if container != nil {
			container.Delete(ctx, client.WithSnapshotCleanup)
		}
		return fmt.Errorf("set root size quota: %w", err)
	}
}
```

Add the helper method. The btrfs snapshotter stores snapshots under
containerd's state directory. We need to find the subvolume path and set the
qgroup limit.

```go
// setSnapshotQuota sets a btrfs qgroup limit on the snapshot's subvolume.
// The snapshot name follows containerd's convention: "<id>-snap".
func (r *Runtime) setSnapshotQuota(ctx context.Context, snapName string, sizeBytes int64) error {
	ctx = r.nsCtx(ctx)

	snapshotter := r.client.SnapshotService(r.snapshotter)
	mounts, err := snapshotter.Mounts(ctx, snapName)
	if err != nil {
		return fmt.Errorf("get snapshot mounts %s: %w", snapName, err)
	}
	if len(mounts) == 0 {
		return fmt.Errorf("no mounts for snapshot %s", snapName)
	}

	// For btrfs snapshotter, the mount source is the subvolume path.
	subvolPath := mounts[0].Source

	// Use the nexus-quota helper to set the qgroup limit (needs btrfs privileges).
	cmd := exec.CommandContext(ctx, "nexus-quota", "set", subvolPath, strconv.FormatInt(sizeBytes, 10))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nexus-quota set %s %d: %s: %w", subvolPath, sizeBytes, string(out), err)
	}

	return nil
}
```

Note: This requires a `nexus-quota` helper binary (like `nexus-netns`) that
runs `btrfs qgroup limit` with the necessary privileges. The helper already
exists in `cmd/nexus-quota/`.

Add `r.snapshotter` field to the Runtime struct and constructor:

```go
type Runtime struct {
	client      *client.Client
	namespace   string
	snapshotter string
}

func New(socketPath, namespace, snapshotter string) (*Runtime, error) {
	c, err := client.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd: %w", err)
	}
	if snapshotter == "" {
		snapshotter = "overlayfs"
	}
	return &Runtime{client: c, namespace: namespace, snapshotter: snapshotter}, nil
}
```

Also add the import for `os/exec` and `strconv`.

**Step 2: Update `NewContainer` call to use the configured snapshotter**

```go
_, err = r.client.NewContainer(ctx, id,
	client.WithImage(img),
	client.WithSnapshotter(r.snapshotter),
	client.WithNewSnapshot(id+"-snap", img),
	client.WithRuntime(runtimeHandler, nil),
	client.WithNewSpec(specOpts...),
)
```

**Step 3: Update all callers of `containerd.New`**

Find where `containerd.New` is called (likely `cmd/daemon.go` or similar) and
add the snapshotter parameter. Check `mise run build` to verify compilation.

**Step 4: Run build**

Run: `mise run build`
Expected: PASS — compiles successfully

**Step 5: Commit**

```bash
git add internal/infra/containerd/runtime.go cmd/
git commit -m "feat(containerd): apply btrfs quota on snapshot via nexus-quota helper"
```

---

### Task 6: Add expand endpoint

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`
- Modify: `internal/infra/httpapi/handler.go`

**Step 1: Write failing test for `ExpandRootSize`**

```go
func TestExpandRootSize(t *testing.T) {
	store, rt, net := setupMocks(t)
	svc := app.NewVMService(store, rt, net)

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "expand-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 1_000_000_000,
	})

	err := svc.ExpandRootSize(context.Background(), vm.ID, 2_000_000_000)
	if err != nil {
		t.Fatalf("ExpandRootSize error: %v", err)
	}

	got, _ := svc.GetVM(context.Background(), vm.ID)
	if got.RootSize != 2_000_000_000 {
		t.Errorf("RootSize = %d, want 2000000000", got.RootSize)
	}
}

func TestExpandRootSizeShrinkFails(t *testing.T) {
	store, rt, net := setupMocks(t)
	svc := app.NewVMService(store, rt, net)

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "shrink-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 2_000_000_000,
	})

	err := svc.ExpandRootSize(context.Background(), vm.ID, 1_000_000_000)
	if err == nil {
		t.Fatal("expected error when shrinking")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `mise run test -- -run TestExpandRoot -v ./internal/app/`
Expected: FAIL — `ExpandRootSize` undefined

**Step 3: Implement `ExpandRootSize`**

In `internal/app/vm_service.go`:

```go
// ExpandRootSize increases the root size quota for a VM.
func (s *VMService) ExpandRootSize(ctx context.Context, ref string, newSize int64) error {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	if vm.RootSize == 0 {
		return fmt.Errorf("VM has no root size limit set: %w", domain.ErrValidation)
	}
	if newSize <= vm.RootSize {
		return fmt.Errorf("new size must be larger than current (%d): %w", vm.RootSize, domain.ErrValidation)
	}

	if err := s.runtime.SetSnapshotQuota(ctx, vm.ID+"-snap", newSize); err != nil {
		return fmt.Errorf("set quota: %w", err)
	}

	if err := s.store.UpdateRootSize(ctx, vm.ID, newSize); err != nil {
		return fmt.Errorf("store update root_size: %w", err)
	}

	log.Info("root size expanded", "id", vm.ID, "old", vm.RootSize, "new", newSize)
	return nil
}
```

This requires adding `SetSnapshotQuota` to the `domain.Runtime` interface:

```go
type Runtime interface {
	// ... existing methods ...
	SetSnapshotQuota(ctx context.Context, snapName string, sizeBytes int64) error
}
```

And exposing `setSnapshotQuota` as a public method on the containerd Runtime.

**Step 4: Add HTTP endpoint**

In `internal/infra/httpapi/handler.go`, add input type:

```go
type PatchVMInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		RootSize string `json:"root_size" doc:"New root size (must be larger than current)"`
	}
}
```

Register the route in `registerVMRoutes`:

```go
huma.Register(api, huma.Operation{
	OperationID: "patch-vm",
	Method:      http.MethodPatch,
	Path:        "/v1/vms/{id}",
	Summary:     "Update VM settings",
	Tags:        []string{"VMs"},
}, func(ctx context.Context, input *PatchVMInput) (*VMOutput, error) {
	if input.Body.RootSize != "" {
		sizeBytes, err := bytesize.Parse(input.Body.RootSize)
		if err != nil {
			return nil, huma.NewError(http.StatusBadRequest, err.Error())
		}
		if err := svc.ExpandRootSize(ctx, input.ID, int64(sizeBytes)); err != nil {
			return nil, mapDomainError(err)
		}
	}
	vm, err := svc.GetVM(ctx, input.ID)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &VMOutput{Body: vmToResponse(vm)}, nil
})
```

**Step 5: Run tests**

Run: `mise run test`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/app/vm_service.go internal/app/vm_service_test.go internal/infra/httpapi/handler.go internal/domain/ports.go
git commit -m "feat: add PATCH /v1/vms/:id for root size expansion"
```

---

### Task 7: Add `root_size` to HTTP create and response

**Files:**
- Modify: `internal/infra/httpapi/handler.go`
- Modify: `internal/infra/httpapi/handler_test.go`

**Step 1: Write failing test**

Add to `internal/infra/httpapi/handler_test.go`:

```go
func TestCreateVMWithRootSize(t *testing.T) {
	// Use existing test helper pattern
	rec := doRequest(h, "POST", "/v1/vms", map[string]any{
		"name": "sized", "role": "agent", "root_size": "1G",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["root_size"] != "1G" {
		t.Errorf("root_size = %v, want 1G", body["root_size"])
	}
}
```

**Step 2: Run to verify failure**

Run: `mise run test -- -run TestCreateVMWithRootSize -v ./internal/infra/httpapi/`
Expected: FAIL

**Step 3: Implement**

Add `RootSize` to `CreateVMInput.Body`:

```go
type CreateVMInput struct {
	Body struct {
		Name     string         `json:"name" doc:"VM name"`
		Role     string         `json:"role" doc:"VM role (agent or service)"`
		Image    string         `json:"image,omitempty" doc:"OCI image"`
		Runtime  string         `json:"runtime,omitempty" doc:"Container runtime handler"`
		DNS      *dnsConfigBody `json:"dns,omitempty" doc:"DNS configuration"`
		RootSize string         `json:"root_size,omitempty" doc:"Root filesystem size limit (e.g. 1G, 500M)"`
	}
}
```

In the create handler, parse and pass through:

```go
var rootSize int64
if input.Body.RootSize != "" {
	sz, err := bytesize.Parse(input.Body.RootSize)
	if err != nil {
		return nil, huma.NewError(http.StatusBadRequest, err.Error())
	}
	rootSize = int64(sz)
}

vm, err := svc.CreateVM(ctx, domain.CreateVMParams{
	// ... existing fields ...
	RootSize: rootSize,
})
```

Add `RootSize` to `vmResponse` and `vmToResponse`:

```go
type vmResponse struct {
	// ... existing fields ...
	RootSize *string `json:"root_size,omitempty" doc:"Root filesystem size limit"`
}

func vmToResponse(vm *domain.VM) vmResponse {
	r := vmResponse{
		// ... existing fields ...
	}
	if vm.RootSize > 0 {
		s := bytesize.Format(uint64(vm.RootSize))
		r.RootSize = &s
	}
	// ...
}
```

Add import for `"github.com/Work-Fort/Nexus/pkg/bytesize"`.

**Step 4: Run tests**

Run: `mise run test`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/infra/httpapi/handler.go internal/infra/httpapi/handler_test.go
git commit -m "feat(api): add root_size to create VM and response"
```

---

### Task 8: Update `recreateContainer` to preserve root size

When drives or devices are attached/detached, the container is recreated. The
root size quota must be reapplied.

**Files:**
- Modify: `internal/app/vm_service.go`

**Step 1: Update `recreateContainer`**

In the `recreateContainer` method, after building `createOpts`, add:

```go
if vm.RootSize > 0 {
	createOpts = append(createOpts, domain.WithRootSize(vm.RootSize))
}
```

**Step 2: Run tests**

Run: `mise run test`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/app/vm_service.go
git commit -m "fix: preserve root_size quota when recreating container"
```

---

### Task 9: Update mock Runtime in tests

The `domain.Runtime` interface now has `SetSnapshotQuota`. Any mock
implementations in tests need updating.

**Files:**
- Modify: `internal/app/vm_service_test.go` (mock runtime)
- Modify: `internal/infra/httpapi/handler_test.go` (mock runtime)

**Step 1: Add `SetSnapshotQuota` to mock**

Find the mock Runtime in the test files and add:

```go
func (m *mockRuntime) SetSnapshotQuota(ctx context.Context, snapName string, sizeBytes int64) error {
	return nil
}
```

**Step 2: Run all tests**

Run: `mise run test`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/app/vm_service_test.go internal/infra/httpapi/handler_test.go
git commit -m "test: add SetSnapshotQuota to mock runtime"
```

---

### Task 10: Final verification

**Step 1: Run all tests**

Run: `mise run test`
Expected: PASS

**Step 2: Build**

Run: `mise run build`
Expected: PASS

**Step 3: Run vet**

Run: `mise run check`
Expected: PASS

**Step 4: Manual smoke test**

Start Nexus with btrfs snapshotter configured:

```bash
mise run run
```

Test the full flow:

```bash
# Create VM with root size
curl -s -X POST http://127.0.0.1:9600/v1/vms \
  -d '{"name":"sized-test","role":"agent","root_size":"1G"}' | jq .
# Verify root_size in response

# Expand
curl -s -X PATCH http://127.0.0.1:9600/v1/vms/sized-test \
  -d '{"root_size":"2G"}' | jq .
# Verify root_size updated

# Try shrink (should fail)
curl -s -X PATCH http://127.0.0.1:9600/v1/vms/sized-test \
  -d '{"root_size":"500M"}' | jq .
# Verify 400 error

# Cleanup
curl -s -X POST http://127.0.0.1:9600/v1/vms/sized-test/stop
curl -s -X DELETE http://127.0.0.1:9600/v1/vms/sized-test
```

**Step 5: Commit any fixes from smoke testing**
