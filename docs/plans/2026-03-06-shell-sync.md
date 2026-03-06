# Shell Sync Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect the root user's default login shell from inside a running VM and persist it to the VM's `shell` field, both on-demand and automatically on first start.

**Architecture:** New `SyncShell` service method execs `getent passwd root` inside the VM via the existing `ExecVM` path, parses field 7 from the colon-delimited passwd output, validates it's an absolute path, and calls `store.UpdateShell`. `StartVM` fires `SyncShell` in a background goroutine when `vm.Shell` is empty. An explicit `POST /v1/vms/{id}/sync-shell` endpoint exposes the operation to API clients.

**Tech Stack:** Go, huma v2 (existing HTTP framework)

**Depends on:** Feature #7 (Terminal Access) — provides `VM.Shell` field, `UpdateShell` store method, `shell` column in SQLite.

---

### Task 1: Write SyncShell Unit Tests

**Files:**
- Modify: `internal/app/vm_service_test.go`

**Step 1: Add UpdateShell to mockStore**

The mock store needs an `UpdateShell` method to satisfy the `VMStore` interface
(added by feature #7). Add after `UpdateRestartPolicy` (around line 110):

```go
func (m *mockStore) UpdateShell(_ context.Context, id, shell string) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.Shell = shell
	return nil
}
```

**Step 2: Add configurable Exec to mockRuntime**

The existing `mockRuntime.Exec` always returns `"ok\n"`. We need per-test
control over exec output. Replace the hardcoded mock (around line 147):

```go
type mockRuntime struct {
	containers map[string]bool // id -> running
	execResult *domain.ExecResult
	execErr    error
}

func newMockRuntime() *mockRuntime {
	return &mockRuntime{
		containers: make(map[string]bool),
		execResult: &domain.ExecResult{ExitCode: 0, Stdout: "ok\n"},
	}
}

func (m *mockRuntime) Exec(_ context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	if m.execErr != nil {
		return nil, m.execErr
	}
	return m.execResult, nil
}
```

**Step 3: Write the SyncShell tests**

Add at the end of `internal/app/vm_service_test.go`:

```go
func TestSyncShell(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/bash\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		// Pre-create a running VM with no shell set.
		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateRunning,
		}
		store.vms[vm.ID] = vm

		got, err := svc.SyncShell(context.Background(), "vm-1")
		if err != nil {
			t.Fatalf("SyncShell: %v", err)
		}
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash", got.Shell)
		}
	})

	t.Run("no-op when shell unchanged", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/bash\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateRunning,
			Shell: "/bin/bash",
		}
		store.vms[vm.ID] = vm

		got, err := svc.SyncShell(context.Background(), "vm-1")
		if err != nil {
			t.Fatalf("SyncShell: %v", err)
		}
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash", got.Shell)
		}
	})

	t.Run("not running", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm

		_, err := svc.SyncShell(context.Background(), "vm-1")
		if !errors.Is(err, domain.ErrInvalidState) {
			t.Errorf("err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("exec failure", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execErr = fmt.Errorf("exec failed")
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateRunning,
		}
		store.vms[vm.ID] = vm

		_, err := svc.SyncShell(context.Background(), "vm-1")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		cases := []struct {
			name   string
			stdout string
		}{
			{"too few fields", "root:x:0:0\n"},
			{"empty shell", "root:x:0:0:root:/root:\n"},
			{"relative path", "root:x:0:0:root:/root:bash\n"},
			{"empty output", ""},
			{"non-zero exit", ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				store := newMockStore()
				rt := newMockRuntime()
				exitCode := 0
				if tc.name == "non-zero exit" {
					exitCode = 1
				}
				rt.execResult = &domain.ExecResult{
					ExitCode: exitCode,
					Stdout:   tc.stdout,
				}
				svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

				vm := &domain.VM{
					ID: "vm-1", Name: "test", State: domain.VMStateRunning,
				}
				store.vms[vm.ID] = vm

				_, err := svc.SyncShell(context.Background(), "vm-1")
				if err == nil {
					t.Fatal("expected error for malformed output")
				}
			})
		}
	})
}
```

**Step 4: Run tests to verify they fail**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestSyncShell -v`
Expected: FAIL — `svc.SyncShell` method doesn't exist yet.

**Step 5: Commit**

```bash
git add internal/app/vm_service_test.go
git commit -m "test(app): add SyncShell unit tests"
```

---

### Task 2: Implement SyncShell Service Method

**Files:**
- Modify: `internal/app/vm_service.go`

**Step 1: Add the SyncShell method**

Add after `ExecStreamVM` (around line 327):

```go
// SyncShell detects the root user's default shell from inside a running VM
// and persists it to the shell field. Returns the updated VM.
func (s *VMService) SyncShell(ctx context.Context, ref string) (*domain.VM, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	result, err := s.runtime.Exec(ctx, vm.ID, []string{"getent", "passwd", "root"})
	if err != nil {
		return nil, fmt.Errorf("exec getent: %w", err)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("getent exited %d: %s", result.ExitCode, result.Stderr)
	}

	shell, err := parseShellFromPasswd(result.Stdout)
	if err != nil {
		return nil, err
	}

	if shell != vm.Shell {
		if err := s.store.UpdateShell(ctx, vm.ID, shell); err != nil {
			return nil, fmt.Errorf("update shell: %w", err)
		}
	}

	return s.store.Get(ctx, vm.ID)
}

// parseShellFromPasswd extracts the shell (field 7) from a passwd-format line.
func parseShellFromPasswd(output string) (string, error) {
	line := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	if line == "" {
		return "", fmt.Errorf("empty passwd output: %w", domain.ErrValidation)
	}
	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return "", fmt.Errorf("malformed passwd line (%d fields): %w", len(fields), domain.ErrValidation)
	}
	shell := fields[6]
	if shell == "" {
		return "", fmt.Errorf("empty shell in passwd: %w", domain.ErrValidation)
	}
	if !strings.HasPrefix(shell, "/") {
		return "", fmt.Errorf("shell %q is not an absolute path: %w", shell, domain.ErrValidation)
	}
	return shell, nil
}
```

**Step 2: Run tests to verify they pass**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestSyncShell -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/app/vm_service.go
git commit -m "feat(app): add SyncShell method with passwd parsing"
```

---

### Task 3: Add Auto-Sync to StartVM

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`

**Step 1: Write the auto-sync test**

Add to `internal/app/vm_service_test.go`:

```go
func TestStartVM_AutoSyncShell(t *testing.T) {
	t.Run("syncs shell when empty", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/bash\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		// Create a stopped VM with no shell.
		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-1"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		// Auto-sync runs in a goroutine; give it a moment.
		time.Sleep(100 * time.Millisecond)

		got := store.vms["vm-1"]
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash", got.Shell)
		}
	})

	t.Run("skips sync when shell already set", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/zsh\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
			Shell: "/bin/bash",
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-1"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		time.Sleep(100 * time.Millisecond)

		got := store.vms["vm-1"]
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash (unchanged)", got.Shell)
		}
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestStartVM_AutoSyncShell -v`
Expected: FAIL — `StartVM` doesn't trigger auto-sync yet.

**Step 3: Add auto-sync to StartVM**

In `internal/app/vm_service.go`, in the `StartVM` method, add after the log
line `log.Info("vm started", "id", vm.ID)` (around line 220) and before the
`return nil`:

```go
	if vm.Shell == "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := s.SyncShell(ctx, vm.ID); err != nil {
				log.Warn("auto shell sync failed", "vm", vm.ID, "err", err)
			}
		}()
	}
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestStartVM_AutoSyncShell -v`
Expected: PASS

**Step 5: Run all app tests to check for regressions**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/app/vm_service.go internal/app/vm_service_test.go
git commit -m "feat(app): auto-sync shell on first VM start"
```

---

### Task 4: Add HTTP Endpoint

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

**Step 1: Add the sync-shell route**

In `internal/infra/httpapi/handler.go`, find where VM routes are registered
(inside `registerVMRoutes`). Add after the `exec-stream-vm` registration
(around line 559, before `// --- Drive routes ---`):

```go
	huma.Register(api, huma.Operation{
		OperationID: "sync-vm-shell",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/sync-shell",
		Summary:     "Detect and sync VM shell",
		Description: "Detects the root user's default shell inside the running VM and persists it.",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *VMPathInput) (*VMOutput, error) {
		vm, err := svc.SyncShell(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &VMOutput{Body: vmToResponse(vm)}, nil
	})
```

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat(httpapi): add POST /v1/vms/{id}/sync-shell endpoint"
```

---

### Task 5: Add E2E Harness Helper

**Files:**
- Modify: `tests/e2e/harness/harness.go`

**Step 1: Add SyncShell to the E2E client**

In `tests/e2e/harness/harness.go`, add after the `ExecStreamVM` method:

```go
// SyncShell detects and persists the VM's root shell.
func (c *Client) SyncShell(id string) (*VM, error) {
	resp, err := c.post("/v1/vms/"+id+"/sync-shell", "")
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

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./tests/e2e/...`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "feat(e2e): add SyncShell harness helper"
```

---

### Task 6: Add E2E Tests

**Files:**
- Modify: `tests/e2e/vm_test.go` (or create `tests/e2e/shell_test.go`)

**Step 1: Write the E2E tests**

Check if `tests/e2e/vm_test.go` exists. If yes, add to it. If not, create
`tests/e2e/shell_test.go`:

```go
func TestSyncShell(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("sync-shell-test", "agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	got, err := c.SyncShell(vm.ID)
	if err != nil {
		t.Fatalf("sync shell: %v", err)
	}
	if got.Shell == "" {
		t.Error("Shell is empty after sync")
	}
	if !strings.HasPrefix(got.Shell, "/") {
		t.Errorf("Shell = %q, expected absolute path", got.Shell)
	}
}

func TestSyncShell_StoppedVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("sync-shell-stopped", "agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = c.SyncShell(vm.ID)
	if err == nil {
		t.Fatal("expected error for stopped VM")
	}
}
```

**Step 2: Run E2E tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && mise run e2e`
Expected: PASS (requires feature #7 to be implemented first for the `Shell`
field to exist in the harness `VM` type).

**Step 3: Commit**

```bash
git add tests/e2e/
git commit -m "test(e2e): add shell sync integration tests"
```

---

### Task 7: Verify Everything

**Step 1: Run all unit tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && mise run test`
Expected: PASS

**Step 2: Run the linter**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && golangci-lint run ./...`
Expected: PASS (or only pre-existing warnings)

**Step 3: Build all binaries**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && mise run build`
Expected: PASS

**Step 4: Verify the endpoint manually (if daemon is runnable)**

```bash
mise run run &
# Create and start a VM, then:
curl -X POST http://localhost:9600/v1/vms/<vm-id>/sync-shell | jq .shell
# Expected: "/bin/bash" or "/bin/ash" (depends on image)
```

**Step 5: Commit any final fixes**

If any fixes were needed, commit them:

```bash
git add -A
git commit -m "fix: address issues found during shell sync verification"
```
