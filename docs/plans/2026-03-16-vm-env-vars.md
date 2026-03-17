# VM Environment Variables Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add settable, updateable environment variables to VMs with full REST/MCP/CLI parity.

**Architecture:** Env vars stored as JSON map in SQLite/Postgres, merged on top of image env vars at container creation. Container is always recreated on start to apply current env vars. Rootfs snapshot and drives are preserved across recreation.

**Tech Stack:** Go, SQLite (sqlc), Postgres, containerd, huma (REST), mcp-go (MCP)

**TDD:** Every task starts with a failing test. E2E tests verify env vars survive container recreation and are visible inside the VM.

---

### Task 1: E2E Test — Env Vars Set at Creation and Visible in VM

Write the end-to-end test first. This test will fail until all layers are implemented.

**Files:**
- Modify: `tests/e2e/nexus_test.go`
- Modify: `tests/e2e/harness/harness.go`

**Step 1: Add `Env` field to harness VM struct**

In `tests/e2e/harness/harness.go:512`, add to `VM struct`:

```go
type VM struct {
	// ... existing fields ...
	Shell           string            `json:"shell"`
	Env             map[string]string `json:"env,omitempty"`
}
```

**Step 2: Add `CreateVMWithEnv` to harness client**

```go
func (c *Client) CreateVMWithEnv(name, tag, image string, env map[string]string) (*VM, error) {
	tagsJSON, _ := json.Marshal([]string{tag})
	envJSON, _ := json.Marshal(env)
	body := fmt.Sprintf(`{"name":%q,"tags":%s,"image":%q,"env":%s}`,
		name, tagsJSON, image, envJSON)
	resp, err := c.post("/v1/vms", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	var vm VM
	return &vm, json.NewDecoder(resp.Body).Decode(&vm)
}
```

**Step 3: Add `UpdateEnv` to harness client**

```go
func (c *Client) UpdateEnv(id string, env map[string]string) (*VM, error) {
	envJSON, _ := json.Marshal(map[string]any{"env": env})
	resp, err := c.put("/v1/vms/"+id+"/env", string(envJSON))
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

**Step 4: Write the failing E2E test**

In `tests/e2e/nexus_test.go`, add:

```go
func TestVMEnvVars(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet(e2eSubnet),
		harness.WithBridgeName(e2eBridgeName))

	// Create VM with env vars.
	env := map[string]string{"MY_VAR": "hello", "OTHER": "world"}
	vm, err := c.CreateVMWithEnv("test-env", "agent",
		"docker.io/library/nginx:alpine", env)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Verify env vars are visible inside the VM.
	var result *harness.ExecResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"printenv", "MY_VAR"})
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec printenv: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "hello" {
		t.Fatalf("MY_VAR: got %q, want %q", strings.TrimSpace(result.Stdout), "hello")
	}

	// Verify env vars in API response.
	got, err := c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.Env["MY_VAR"] != "hello" || got.Env["OTHER"] != "world" {
		t.Fatalf("env in API: got %v, want MY_VAR=hello OTHER=world", got.Env)
	}

	// Stop, update env, restart — verify new env is applied.
	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop VM: %v", err)
	}
	updated, err := c.UpdateEnv(vm.ID, map[string]string{
		"MY_VAR": "updated",
		"NEW_KEY": "new_value",
	})
	if err != nil {
		t.Fatalf("update env: %v", err)
	}
	if updated.Env["MY_VAR"] != "updated" {
		t.Fatalf("updated env: got %v", updated.Env)
	}

	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start after env update: %v", err)
	}

	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"printenv", "MY_VAR"})
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec printenv after update: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "updated" {
		t.Fatalf("MY_VAR after update: got %q, want %q",
			strings.TrimSpace(result.Stdout), "updated")
	}

	// Verify OLD var is gone and NEW var exists.
	result, _ = c.ExecVM(vm.ID, []string{"printenv", "OTHER"})
	if result != nil && result.ExitCode == 0 {
		t.Fatal("OTHER should not exist after env replacement")
	}
	result, err = c.ExecVM(vm.ID, []string{"printenv", "NEW_KEY"})
	if err != nil {
		t.Fatalf("exec printenv NEW_KEY: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "new_value" {
		t.Fatalf("NEW_KEY: got %q, want %q",
			strings.TrimSpace(result.Stdout), "new_value")
	}

	t.Log("env vars verified: create, update, and container recreation all work")
}
```

**Step 5: Run test to verify it fails**

Run: `mise run e2e -- -run TestVMEnvVars -v -count=1 -timeout 120s`
Expected: FAIL (env field not recognized by API)

**Step 6: Commit**

```
git add tests/e2e/nexus_test.go tests/e2e/harness/harness.go
git commit -m "test(e2e): add failing test for VM environment variables"
```

---

### Task 2: Domain — Add Env to VM and CreateVMParams

**Files:**
- Modify: `internal/domain/vm.go:51-72` (VM struct)
- Modify: `internal/domain/vm.go:75-87` (CreateVMParams)
- Modify: `internal/domain/ports.go:12-25` (VMStore interface)

**Step 1: Add `Env` field to VM struct**

In `internal/domain/vm.go:51`, add after `ScriptOverride`:

```go
Env            map[string]string // user-supplied environment variables
```

**Step 2: Add `Env` field to CreateVMParams**

In `internal/domain/vm.go:75`, add after `TemplateName`:

```go
Env          map[string]string // environment variables
```

**Step 3: Add `UpdateEnv` to VMStore interface**

In `internal/domain/ports.go`, add to VMStore:

```go
UpdateEnv(ctx context.Context, id string, env map[string]string) error
```

**Step 4: Add `Env` to CreateConfig**

In `internal/domain/ports.go:48`, add to CreateConfig:

```go
Env []string // KEY=VALUE environment variables
```

**Step 5: Add `WithEnv` functional option**

```go
func WithEnv(env []string) CreateOpt {
	return func(c *CreateConfig) { c.Env = env }
}
```

**Step 6: Commit**

```
git commit -m "feat(domain): add Env field to VM, CreateVMParams, and VMStore"
```

---

### Task 3: Database — Migration, Queries, Store Methods

**Files:**
- Create: `internal/infra/sqlite/migrations/014_add_vm_env.sql`
- Modify: `internal/infra/sqlite/queries.sql`
- Regenerate: `internal/infra/sqlite/queries.sql.go` (via `mise run sqlc`)
- Modify: `internal/infra/sqlite/store.go`
- Modify: `internal/infra/postgres/store.go`

**Step 1: Write SQLite migration**

Create `internal/infra/sqlite/migrations/014_add_vm_env.sql`:

```sql
-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
ALTER TABLE vms ADD COLUMN env TEXT NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE vms DROP COLUMN env;
```

**Step 2: Add sqlc query**

In `internal/infra/sqlite/queries.sql`, add:

```sql
-- name: UpdateVMEnv :exec
UPDATE vms SET env = ? WHERE id = ?;
```

**Step 3: Update InsertVM query to include env**

Update the existing InsertVM query to include the env column.

**Step 4: Run sqlc**

Run: `mise run sqlc`

**Step 5: Implement SQLite store methods**

In `internal/infra/sqlite/store.go`, add `UpdateEnv` method. Parse JSON on read (Get/List), marshal on write (Create/UpdateEnv).

**Step 6: Implement Postgres store methods**

In `internal/infra/postgres/store.go`, add `UpdateEnv` with raw SQL. Same JSON handling.

**Step 7: Update mock stores**

Add `UpdateEnv` to mock stores in:
- `internal/app/vm_service_test.go`
- `internal/infra/httpapi/handler_test.go`

**Step 8: Run unit tests**

Run: `mise run test:unit`
Expected: PASS

**Step 9: Commit**

```
git commit -m "feat(store): add env column and UpdateEnv to VMStore"
```

---

### Task 4: Runtime — Env Vars in Container Creation + Always Recreate

**Files:**
- Modify: `internal/infra/containerd/runtime.go:121-255` (Create)
- Modify: `internal/infra/containerd/runtime.go:550-574` (Start)

**Step 1: Apply user env vars in Create**

In `runtime.go` Create method, after the image env vars (line 141-142), merge user-supplied env vars:

```go
if len(cfg.Env) > 0 {
	specOpts = append(specOpts, oci.WithEnv(cfg.Env))
}
// User-supplied env vars override image defaults.
if len(createCfg.Env) > 0 {
	specOpts = append(specOpts, oci.WithEnv(createCfg.Env))
}
```

**Step 2: Change Start to always recreate the container**

Replace `runtime.Start` to:
1. Load the container and read its image + labels.
2. Kill and delete any stale task.
3. Delete the container (WITHOUT snapshot cleanup).
4. Recreate the container reusing the existing snapshot.
5. Create new task and start.

The key change: `Start` now accepts `CreateOpt` arguments so the caller can pass updated env vars:

```go
func (r *Runtime) Start(ctx context.Context, id string, opts ...domain.CreateOpt) error {
```

Update the `Runtime` interface in `domain/ports.go` to match.

**Step 3: Run unit tests**

Run: `mise run test:unit`
Expected: PASS

**Step 4: Commit**

```
git commit -m "feat(runtime): merge user env vars and recreate container on start"
```

---

### Task 5: Application — Wire Env Through VMService

**Files:**
- Modify: `internal/app/vm_service.go:131` (CreateVM)
- Modify: `internal/app/vm_service.go:280` (StartVM)
- Add: `UpdateEnv` method to VMService

**Step 1: Pass env to runtime.Create in CreateVM**

In `CreateVM`, convert `params.Env` map to `[]string{"KEY=VALUE"}` and pass via `domain.WithEnv(envSlice)`.

**Step 2: Pass env to runtime.Start in StartVM**

In `StartVM`, read the VM's current env from the store and pass to `runtime.Start` via `domain.WithEnv(envSlice)`.

**Step 3: Add UpdateEnv method**

Follow the `UpdateRestartPolicy` pattern at line 492:

```go
func (s *VMService) UpdateEnv(ctx context.Context, ref string, env map[string]string) (*domain.VM, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateEnv(ctx, vm.ID, env); err != nil {
		return nil, fmt.Errorf("store update env: %w", err)
	}
	vm.Env = env
	log.Info("env updated", "id", vm.ID, "count", len(env))
	return vm, nil
}
```

**Step 4: Run unit tests**

Run: `mise run test:unit`
Expected: PASS

**Step 5: Commit**

```
git commit -m "feat(app): wire env vars through CreateVM, StartVM, and UpdateEnv"
```

---

### Task 6: REST API — Create and Update Endpoints

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

**Step 1: Add env to VM create input**

Add `Env map[string]string` to the create VM request body struct.

**Step 2: Add env to VM response**

Add `Env map[string]string` to `vmToResponse`.

**Step 3: Add update env endpoint**

Follow the `update-restart-policy` pattern at line 625:

```go
type UpdateEnvInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		Env map[string]string `json:"env" doc:"Environment variables"`
	}
}
```

Register: `PUT /v1/vms/{id}/env`

**Step 4: Run unit tests**

Run: `mise run test:unit`
Expected: PASS

**Step 5: Commit**

```
git commit -m "feat(httpapi): add env to VM create and PUT /v1/vms/{id}/env endpoint"
```

---

### Task 7: MCP — vm_create env param and vm_env tool

**Files:**
- Modify: `internal/infra/mcp/handler.go`

**Step 1: Add env parameter to vm_create**

Add `env` string parameter (JSON object) to the `vm_create` tool. Parse it as `map[string]string` in the handler.

**Step 2: Add vm_env tool**

```go
s.AddTool(mcp.NewTool("vm_env",
	mcp.WithDescription("Get or set environment variables for a VM. Usage: vm_env(id: \"myvm\", env: {\"KEY\": \"value\"})"),
	mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
	mcp.WithString("env", mcp.Description("Env vars as JSON object — omit to get current")),
), ...)
```

When `env` is provided: parse JSON, call `svc.UpdateEnv`, return VM.
When `env` is omitted: call `svc.GetVM`, return just the env map.

**Step 3: Run unit tests**

Run: `mise run test:unit`
Expected: PASS

**Step 4: Commit**

```
git commit -m "feat(mcp): add env parameter to vm_create and vm_env tool"
```

---

### Task 8: Run E2E Test — Verify Green

**Step 1: Run the E2E test from Task 1**

Run: `mise run e2e -- -run TestVMEnvVars -v -count=1 -timeout 120s`
Expected: PASS — env vars set at creation, visible via exec, updated, and applied after restart.

**Step 2: Run full test suite**

Run: `mise run test:unit`
Expected: All pass

**Step 3: Commit any fixes**

If any issues found, fix with additional commits.

**Step 4: Final commit**

```
git commit -m "feat: VM environment variables — complete implementation"
```

---

### Task 9: CLI — nexusctl vm env

**Files:**
- Modify: `cmd/nexusctl/vm.go` (or create `cmd/nexusctl/env.go`)

**Step 1: Add `vm env` subcommand**

```
nexusctl vm env <id>                    # show current env vars
nexusctl vm env <id> KEY=value ...      # set env vars
nexusctl vm env <id> --clear            # remove all env vars
```

**Step 2: Run manually to verify**

```
nexusctl vm env passport
nexusctl vm env passport DB_URL=postgres://...
```

**Step 3: Commit**

```
git commit -m "feat(nexusctl): add vm env subcommand"
```
