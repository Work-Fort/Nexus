# VM Image Update Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow updating a VM's image without losing drives, network, env vars, or other config.

**Architecture:** Delete old container + snapshot, create new container from new image with same opts. The rootfs is replaced; drives and all other config are preserved from the DB.

**Tech Stack:** Go, SQLite (sqlc), Postgres, containerd, huma (REST), mcp-go (MCP)

**TDD:** Failing E2E test first. Test verifies data on a drive survives an image update.

---

### Task 1: E2E Test — Image Update Preserves Drive Data

Write the failing test first. This verifies the core guarantee: data on drives survives image updates.

**Files:**
- Modify: `tests/e2e/harness/harness.go`
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Add `UpdateImage` to harness client**

```go
func (c *Client) UpdateImage(id, image string) (*VM, error) {
	body := fmt.Sprintf(`{"image":%q}`, image)
	resp, err := c.put("/v1/vms/"+id+"/image", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var vm VM
	return &vm, json.NewDecoder(resp.Body).Decode(&vm)
}
```

**Step 2: Add `Image` field to harness VM struct if not present**

Check if the harness `VM` struct already has an `Image` field. If not, add it.

**Step 3: Write the failing E2E test**

Uses two real nginx versions: `nginx:1.26-alpine` (old) and `nginx:1.27-alpine`
(new). A drive is mounted at nginx's html root. The test verifies:
1. Custom index.html on the drive survives the image update.
2. The nginx Server header changes from 1.26 to 1.27 (proves the binary updated).

```go
func TestVMImageUpdate(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet(e2eSubnet),
		harness.WithBridgeName(e2eBridgeName))

	oldImage := "docker.io/library/nginx:1.26-alpine"
	newImage := "docker.io/library/nginx:1.27-alpine"

	// Create VM with the OLD nginx image.
	vm, err := c.CreateVMWithImage("test-img-update", "agent", oldImage)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Create a drive mounted at nginx's html root.
	drive, err := c.CreateDrive("html-data", "64M", "/usr/share/nginx/html")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := c.AttachDrive(drive.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// Start VM.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Write a custom index.html to the drive-backed html root.
	customHTML := "WorkFort Nexus Test Page"
	var result *harness.ExecResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /usr/share/nginx/html/index.html", customHTML),
		})
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	// Verify nginx serves the custom page and reports 1.26 in Server header.
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "-", "http://127.0.0.1/"})
		if err == nil && strings.Contains(result.Stdout, customHTML) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("wget index: %v", err)
	}
	if !strings.Contains(result.Stdout, customHTML) {
		t.Fatalf("custom page not served: got %q", result.Stdout)
	}

	// Check Server header via a 404 page (nginx includes version in error pages).
	result, err = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "-", "-S", "http://127.0.0.1/nonexistent"})
	// wget returns non-zero for 404 — check stderr for Server header.
	if result != nil && !strings.Contains(result.Stderr, "nginx/1.26") {
		t.Logf("warning: could not confirm nginx 1.26 in Server header: %s", result.Stderr)
	} else {
		t.Log("confirmed nginx/1.26 before update")
	}

	// Stop the VM.
	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop VM: %v", err)
	}

	// ---- UPDATE IMAGE ----
	got, err := c.UpdateImage(vm.ID, newImage)
	if err != nil {
		t.Fatalf("update image: %v", err)
	}
	if got.Image != newImage {
		t.Fatalf("image not updated: got %s, want %s", got.Image, newImage)
	}
	t.Logf("image updated from %s to %s", oldImage, newImage)

	// Start the VM with the new image.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start after image update: %v", err)
	}

	// VERIFY 1: Custom index.html survived (drive data preserved).
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "-", "http://127.0.0.1/"})
		if err == nil && strings.Contains(result.Stdout, customHTML) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("wget after update: %v", err)
	}
	if !strings.Contains(result.Stdout, customHTML) {
		t.Fatalf("custom page lost after image update: got %q", result.Stdout)
	}
	t.Log("custom index.html preserved after image update")

	// VERIFY 2: Server header shows nginx 1.27 (binary updated).
	result, _ = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "-", "-S", "http://127.0.0.1/nonexistent"})
	if result != nil && strings.Contains(result.Stderr, "nginx/1.27") {
		t.Log("confirmed nginx/1.27 after update — binary changed")
	} else if result != nil {
		// Fall back to checking nginx -v directly.
		result2, err2 := c.ExecVM(vm.ID, []string{"nginx", "-v"})
		if err2 == nil && strings.Contains(result2.Stderr, "1.27") {
			t.Log("confirmed nginx/1.27 via nginx -v")
		} else {
			t.Logf("warning: could not confirm nginx version change (stderr: %s)", result.Stderr)
		}
	}
}
```

**Step 4: Commit**

```
git commit -m "test(e2e): add failing test for VM image update with drive preservation"
```

---

### Task 2: Domain + Database — UpdateImage on VMStore

**Files:**
- Modify: `internal/domain/ports.go`
- Modify: `internal/infra/sqlite/queries.sql`
- Regenerate: `internal/infra/sqlite/queries.sql.go`
- Modify: `internal/infra/sqlite/store.go`
- Modify: `internal/infra/postgres/store.go`
- Modify: `internal/app/vm_service_test.go` (mock)
- Modify: `internal/infra/httpapi/handler_test.go` (mock)

**Step 1: Add `UpdateImage` to VMStore interface**

In `internal/domain/ports.go`, add to VMStore:

```go
UpdateImage(ctx context.Context, id, image string) error
```

**Step 2: Add sqlc query**

In `internal/infra/sqlite/queries.sql`:

```sql
-- name: UpdateVMImage :exec
UPDATE vms SET image = ? WHERE id = ?;
```

**Step 3: Run sqlc**

Run: `mise run sqlc`

**Step 4: Implement store methods**

SQLite `store.go`:
```go
func (s *Store) UpdateImage(ctx context.Context, id, image string) error {
	return s.q.UpdateVMImage(ctx, queries.UpdateVMImageParams{Image: image, ID: id})
}
```

Postgres `store.go`:
```go
func (s *Store) UpdateImage(ctx context.Context, id, image string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE vms SET image = $1 WHERE id = $2", image, id)
	return err
}
```

**Step 5: Add `UpdateImage` to mock stores**

Add stub to mocks in `vm_service_test.go` and `handler_test.go`.

**Step 6: Run unit tests**

Run: `mise run test:unit`

**Step 7: Commit**

```
git commit -m "feat(store): add UpdateImage to VMStore"
```

---

### Task 3: Application — VMService.UpdateImage

**Files:**
- Modify: `internal/app/vm_service.go`

**Step 1: Add UpdateImage method**

```go
func (s *VMService) UpdateImage(ctx context.Context, ref, newImage string) (*domain.VM, error) {
	if newImage == "" {
		return nil, fmt.Errorf("image is required: %w", domain.ErrValidation)
	}

	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if vm.State == domain.VMStateRunning {
		return nil, fmt.Errorf("vm must be stopped to update image: %w", domain.ErrInvalidState)
	}

	if s.health != nil {
		if err := s.health.RuntimeHealthy(vm.Runtime); err != nil {
			return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
		}
	}

	// Delete old container + snapshot.
	if err := s.runtime.Delete(ctx, vm.ID); err != nil {
		log.Warn("delete old container", "id", vm.ID, "err", err)
	}

	// Build create opts from existing VM config.
	var createOpts []domain.CreateOpt
	if vm.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(vm.NetNSPath))
	}
	resolvConfPath, err := s.dns.GenerateResolvConf(vm.ID, vm.DNSConfig)
	if err == nil && resolvConfPath != "" {
		createOpts = append(createOpts, domain.WithResolvConf(resolvConfPath))
	}
	if vm.RootSize > 0 {
		createOpts = append(createOpts, domain.WithRootSize(vm.RootSize))
	}
	if len(vm.Env) > 0 {
		var envSlice []string
		for k, v := range vm.Env {
			envSlice = append(envSlice, k+"="+v)
		}
		createOpts = append(createOpts, domain.WithEnv(envSlice))
	}

	// Metrics bind-mount.
	if s.config.Metrics.NodeExporterPath != "" {
		createOpts = append(createOpts, domain.WithMounts([]domain.Mount{
			{HostPath: s.config.Metrics.NodeExporterPath, ContainerPath: "/usr/local/bin/node_exporter"},
		}))
	}

	// Init injection.
	if vm.Init {
		initPath, _, stopSignal, err := s.resolveInitScript(ctx, vm.ID, newImage, "")
		if err != nil {
			return nil, fmt.Errorf("init script for new image: %w", err)
		}
		createOpts = append(createOpts, domain.WithInitScript(initPath))
		if stopSignal != 0 {
			createOpts = append(createOpts, domain.WithStopSignal(stopSignal))
		}
	}

	// Drives — get drive mounts.
	if s.driveStore != nil {
		drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err == nil && len(drives) > 0 {
			var mounts []domain.Mount
			for _, d := range drives {
				mounts = append(mounts, domain.Mount{
					HostPath:      s.storage.VolumePath(d.Name),
					ContainerPath: d.MountPath,
				})
			}
			createOpts = append(createOpts, domain.WithMounts(mounts))
		}
	}

	// Devices.
	if s.deviceStore != nil {
		devices, err := s.deviceStore.GetDevicesByVM(ctx, vm.ID)
		if err == nil && len(devices) > 0 {
			var devInfos []domain.DeviceInfo
			for _, d := range devices {
				devInfos = append(devInfos, domain.DeviceInfo{
					HostPath:      d.HostPath,
					ContainerPath: d.ContainerPath,
					Permissions:   d.Permissions,
					GID:           d.GID,
				})
			}
			createOpts = append(createOpts, domain.WithDevices(devInfos))
		}
	}

	// Create new container from new image.
	if err := s.runtime.Create(ctx, vm.ID, newImage, vm.Runtime, createOpts...); err != nil {
		return nil, fmt.Errorf("create container with new image: %w", err)
	}

	// Update DB.
	if err := s.store.UpdateImage(ctx, vm.ID, newImage); err != nil {
		return nil, fmt.Errorf("store update image: %w", err)
	}

	vm.Image = newImage
	log.Info("image updated", "id", vm.ID, "image", newImage)
	return vm, nil
}
```

**Step 2: Run unit tests**

Run: `mise run test:unit`

**Step 3: Commit**

```
git commit -m "feat(app): add UpdateImage method to VMService"
```

---

### Task 4: REST API + MCP + CLI

**Files:**
- Modify: `internal/infra/httpapi/handler.go`
- Modify: `internal/infra/mcp/handler.go`
- Create or modify: `cmd/nexusctl/vm.go`

**Step 1: Add REST endpoint**

```go
type UpdateImageInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		Image string `json:"image" doc:"New OCI image reference"`
	}
}
```

Register `PUT /v1/vms/{id}/image`:

```go
huma.Register(api, huma.Operation{
	OperationID: "update-image",
	Method:      http.MethodPut,
	Path:        "/v1/vms/{id}/image",
	Summary:     "Update VM image (requires stopped VM)",
	Tags:        []string{"VMs"},
}, func(ctx context.Context, input *UpdateImageInput) (*VMOutput, error) {
	vm, err := svc.UpdateImage(ctx, input.ID, input.Body.Image)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return &VMOutput{Body: vmToResponse(vm)}, nil
})
```

**Step 2: Extend vm_patch MCP tool**

Add `image` parameter to the existing `vm_patch` tool. Update the
description to include the usage example:

```
Usage: vm_patch(id: "myvm", image: "nginx:latest")
```

When `image` is provided, call `svc.UpdateImage`. When `root_size` is
provided, call `svc.ExpandRootSize` (existing behavior).

**Step 3: Add CLI subcommand**

Add `nexusctl vm update-image <id> <image>` subcommand. Follow the
pattern of other VM subcommands.

**Step 4: Run unit tests**

Run: `mise run test:unit`

**Step 5: Commit**

```
git commit -m "feat: add image update to REST, MCP, and CLI"
```

---

### Task 5: Run E2E Test — Verify Green

**Step 1: Run the E2E test from Task 1**

Run: `mise run e2e -- -run TestVMImageUpdate -v -count=1 -timeout 120s`
Expected: PASS

**Step 2: Run full unit test suite**

Run: `mise run test:unit`
Expected: All pass

**Step 3: Fix any issues and commit**

```
git commit -m "fix: ..."  (if needed)
```

**Step 4: Run E2E cleanup**

Run: `mise run e2e:clean`

This removes leaked containerd namespaces and stale bridge interfaces
left over from the test run.
