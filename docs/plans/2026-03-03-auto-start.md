# Auto-Start on Boot Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restore previously-running VMs on daemon startup and monitor for crashes with automatic restart via per-VM restart policy and strategy.

**Architecture:** Add `restart_policy` (none/on-boot/always) and `restart_strategy` (immediate/backoff/fixed) fields to the VM. On daemon startup, a `RestoreVMs` method handles boot recovery. A background goroutine subscribes to containerd task exit events and restarts VMs with `policy=always`. The crash monitor uses the containerd v2 `Subscribe` API filtered to `TaskExit` events in the nexus namespace.

**Tech Stack:** Go 1.26, sqlc (code gen from SQL), goose (migrations), containerd v2 client `Subscribe` + `typeurl.UnmarshalAny`, `containerd/api/events.TaskExit`

**Reference:** Design doc at `docs/auto-start-design.md`.

---

### Task 1: Add restart_policy and restart_strategy to Domain Model

**Files:**
- Modify: `internal/domain/vm.go`

**Step 1: Add types and constants**

Add after the `VMStateStopped` constant block (after line 33):

```go
// RestartPolicy controls when a VM is automatically (re)started.
type RestartPolicy string

const (
	RestartPolicyNone   RestartPolicy = "none"
	RestartPolicyOnBoot RestartPolicy = "on-boot"
	RestartPolicyAlways RestartPolicy = "always"
)

// ValidRestartPolicy returns true if p is a recognized restart policy.
func ValidRestartPolicy(p RestartPolicy) bool {
	return p == RestartPolicyNone || p == RestartPolicyOnBoot || p == RestartPolicyAlways
}

// RestartStrategy controls the timing of automatic restarts.
type RestartStrategy string

const (
	RestartStrategyImmediate RestartStrategy = "immediate"
	RestartStrategyBackoff   RestartStrategy = "backoff"
	RestartStrategyFixed     RestartStrategy = "fixed"
)

// ValidRestartStrategy returns true if s is a recognized restart strategy.
func ValidRestartStrategy(s RestartStrategy) bool {
	return s == RestartStrategyImmediate || s == RestartStrategyBackoff || s == RestartStrategyFixed
}
```

**Step 2: Add fields to VM struct**

Add `RestartPolicy` and `RestartStrategy` fields to the `VM` struct (after `RootSize`):

```go
	RestartPolicy   RestartPolicy   // none, on-boot, always
	RestartStrategy RestartStrategy // immediate, backoff, fixed
```

**Step 3: Add fields to CreateVMParams**

Add to the `CreateVMParams` struct (after `RootSize`):

```go
	RestartPolicy   RestartPolicy
	RestartStrategy RestartStrategy
```

**Step 4: Verify compilation**

```bash
go build ./internal/domain/...
```

Expected: success.

**Step 5: Commit**

```bash
git add internal/domain/vm.go
git commit -m "feat(domain): add RestartPolicy and RestartStrategy types to VM"
```

---

### Task 2: Database Migration

**Files:**
- Create: `internal/infra/sqlite/migrations/008_add_vm_restart.sql`

**Step 1: Create migration file**

Create `internal/infra/sqlite/migrations/008_add_vm_restart.sql`:

```sql
-- +goose Up
ALTER TABLE vms ADD COLUMN restart_policy TEXT NOT NULL DEFAULT 'none' CHECK (restart_policy IN ('none', 'on-boot', 'always'));
ALTER TABLE vms ADD COLUMN restart_strategy TEXT NOT NULL DEFAULT 'backoff' CHECK (restart_strategy IN ('immediate', 'backoff', 'fixed'));

-- +goose Down
-- SQLite doesn't support DROP COLUMN before 3.35.0; recreate if needed.
```

**Step 2: Verify compilation**

```bash
go build ./internal/infra/sqlite/...
```

Expected: success (embedded migration picked up automatically).

**Step 3: Commit**

```bash
git add internal/infra/sqlite/migrations/008_add_vm_restart.sql
git commit -m "feat(sqlite): add restart_policy and restart_strategy columns"
```

---

### Task 3: Update sqlc Queries and Store

**Files:**
- Modify: `internal/infra/sqlite/queries.sql`
- Regenerate: `internal/infra/sqlite/queries.sql.go` and `internal/infra/sqlite/models.go`
- Modify: `internal/infra/sqlite/store.go`
- Modify: `internal/domain/ports.go`

**Step 1: Update SQL queries**

In `internal/infra/sqlite/queries.sql`, update every VM SELECT to include the new columns. Add `restart_policy, restart_strategy` to the column list of these queries: `InsertVM`, `GetVM`, `GetVMByName`, `ListVMs`, `ListVMsByRole`, `ResolveVM`.

Update `InsertVM`:

```sql
-- name: InsertVM :exec
INSERT INTO vms (id, name, role, image, runtime, state, created_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
```

Update `GetVM`:

```sql
-- name: GetVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy
FROM vms WHERE id = ?;
```

Update `GetVMByName`:

```sql
-- name: GetVMByName :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy
FROM vms WHERE name = ?;
```

Update `ListVMs`:

```sql
-- name: ListVMs :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy
FROM vms ORDER BY created_at DESC;
```

Update `ListVMsByRole`:

```sql
-- name: ListVMsByRole :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy
FROM vms WHERE role = ? ORDER BY created_at DESC;
```

Update `ResolveVM`:

```sql
-- name: ResolveVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy
FROM vms WHERE id = ? OR name = ?;
```

Add a new query for updating restart policy:

```sql
-- name: UpdateVMRestartPolicy :exec
UPDATE vms SET restart_policy = ?, restart_strategy = ? WHERE id = ?;
```

**Step 2: Regenerate sqlc**

```bash
sqlc generate
```

Expected: `models.go` and `queries.sql.go` updated with new `RestartPolicy` and `RestartStrategy` fields on the `Vm` struct.

**Step 3: Update vmFromRow in store.go**

In `internal/infra/sqlite/store.go`, add to `vmFromRow` (after `RootSize` assignment around line 471):

```go
	vm.RestartPolicy = domain.RestartPolicy(row.RestartPolicy)
	vm.RestartStrategy = domain.RestartStrategy(row.RestartStrategy)
```

**Step 4: Update Store.Create in store.go**

In the `Create` method, update the `InsertVMParams` to include the new fields:

```go
	return s.q.InsertVM(ctx, InsertVMParams{
		ID:              vm.ID,
		Name:            vm.Name,
		Role:            string(vm.Role),
		Image:           vm.Image,
		Runtime:         vm.Runtime,
		State:           string(vm.State),
		CreatedAt:       vm.CreatedAt.UTC().Format(timeFormat),
		Ip:              vm.IP,
		Gateway:         vm.Gateway,
		NetnsPath:       vm.NetNSPath,
		DnsServers:      dnsServers,
		DnsSearch:       dnsSearch,
		RootSize:        vm.RootSize,
		RestartPolicy:   string(vm.RestartPolicy),
		RestartStrategy: string(vm.RestartStrategy),
	})
```

**Step 5: Add UpdateRestartPolicy to store.go**

Add a new method:

```go
func (s *Store) UpdateRestartPolicy(ctx context.Context, id string, policy domain.RestartPolicy, strategy domain.RestartStrategy) error {
	return s.q.UpdateVMRestartPolicy(ctx, UpdateVMRestartPolicyParams{
		RestartPolicy:   string(policy),
		RestartStrategy: string(strategy),
		ID:              id,
	})
}
```

**Step 6: Add UpdateRestartPolicy to VMStore interface**

In `internal/domain/ports.go`, add to the `VMStore` interface:

```go
	UpdateRestartPolicy(ctx context.Context, id string, policy RestartPolicy, strategy RestartStrategy) error
```

**Step 7: Verify compilation**

```bash
go build ./...
```

Expected: success.

**Step 8: Commit**

```bash
git add internal/infra/sqlite/queries.sql internal/infra/sqlite/queries.sql.go internal/infra/sqlite/models.go internal/infra/sqlite/store.go internal/domain/ports.go
git commit -m "feat(sqlite): update queries and store for restart policy fields"
```

---

### Task 4: Update CreateVM and Add UpdateRestartPolicy in VMService

**Files:**
- Modify: `internal/app/vm_service.go`

**Step 1: Update CreateVM to handle restart fields**

In `CreateVM` (around line 110, after the `RootSize` validation), add validation:

```go
	if params.RestartPolicy == "" {
		params.RestartPolicy = domain.RestartPolicyNone
	}
	if !domain.ValidRestartPolicy(params.RestartPolicy) {
		return nil, fmt.Errorf("invalid restart_policy %q: %w", params.RestartPolicy, domain.ErrValidation)
	}
	if params.RestartStrategy == "" {
		params.RestartStrategy = domain.RestartStrategyBackoff
	}
	if !domain.ValidRestartStrategy(params.RestartStrategy) {
		return nil, fmt.Errorf("invalid restart_strategy %q: %w", params.RestartStrategy, domain.ErrValidation)
	}
```

In the VM struct initialization (around line 111), add:

```go
		RestartPolicy:   params.RestartPolicy,
		RestartStrategy: params.RestartStrategy,
```

**Step 2: Add UpdateRestartPolicy method**

Add after `ExpandRootSize`:

```go
// UpdateRestartPolicy changes the restart policy and strategy for a VM.
func (s *VMService) UpdateRestartPolicy(ctx context.Context, ref string, policy domain.RestartPolicy, strategy domain.RestartStrategy) (*domain.VM, error) {
	if !domain.ValidRestartPolicy(policy) {
		return nil, fmt.Errorf("invalid restart_policy %q: %w", policy, domain.ErrValidation)
	}
	if !domain.ValidRestartStrategy(strategy) {
		return nil, fmt.Errorf("invalid restart_strategy %q: %w", strategy, domain.ErrValidation)
	}

	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	if err := s.store.UpdateRestartPolicy(ctx, vm.ID, policy, strategy); err != nil {
		return nil, fmt.Errorf("store update restart policy: %w", err)
	}

	vm.RestartPolicy = policy
	vm.RestartStrategy = strategy
	log.Info("restart policy updated", "id", vm.ID, "policy", policy, "strategy", strategy)
	return vm, nil
}
```

**Step 3: Verify compilation**

```bash
go build ./...
```

Expected: success.

**Step 4: Commit**

```bash
git add internal/app/vm_service.go
git commit -m "feat(app): handle restart policy in CreateVM and add UpdateRestartPolicy"
```

---

### Task 5: HTTP API — Create VM and Restart Policy Endpoint

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

**Step 1: Add restart fields to CreateVMInput**

Add to `CreateVMInput.Body` (after `RootSize`):

```go
		RestartPolicy   string `json:"restart_policy,omitempty" doc:"Restart policy (none, on-boot, always)" default:"none"`
		RestartStrategy string `json:"restart_strategy,omitempty" doc:"Restart strategy (immediate, backoff, fixed)" default:"backoff"`
```

**Step 2: Add restart fields to vmResponse**

Add to `vmResponse` (after `RootSize`):

```go
	RestartPolicy   string `json:"restart_policy" doc:"Restart policy"`
	RestartStrategy string `json:"restart_strategy" doc:"Restart strategy"`
```

**Step 3: Update vmToResponse**

Add to `vmToResponse` (after the `RootSize` block):

```go
	r.RestartPolicy = string(vm.RestartPolicy)
	r.RestartStrategy = string(vm.RestartStrategy)
```

**Step 4: Pass restart fields in create-vm handler**

In the `create-vm` handler, add to the `CreateVMParams`:

```go
			RestartPolicy:   domain.RestartPolicy(input.Body.RestartPolicy),
			RestartStrategy: domain.RestartStrategy(input.Body.RestartStrategy),
```

**Step 5: Add restart-policy input type and endpoint**

Add a new input type (after `AttachDeviceInput`):

```go
type UpdateRestartPolicyInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		RestartPolicy   string `json:"restart_policy" doc:"Restart policy (none, on-boot, always)"`
		RestartStrategy string `json:"restart_strategy" doc:"Restart strategy (immediate, backoff, fixed)"`
	}
}
```

Add the endpoint in `registerVMRoutes` (after the `patch-vm` registration):

```go
	huma.Register(api, huma.Operation{
		OperationID: "update-restart-policy",
		Method:      http.MethodPut,
		Path:        "/v1/vms/{id}/restart-policy",
		Summary:     "Update VM restart policy",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *UpdateRestartPolicyInput) (*VMOutput, error) {
		vm, err := svc.UpdateRestartPolicy(ctx, input.ID,
			domain.RestartPolicy(input.Body.RestartPolicy),
			domain.RestartStrategy(input.Body.RestartStrategy))
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &VMOutput{Body: vmToResponse(vm)}, nil
	})
```

**Step 6: Verify compilation**

```bash
go build ./...
```

Expected: success.

**Step 7: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat(api): add restart_policy fields to create-vm and PUT restart-policy endpoint"
```

---

### Task 6: Boot Recovery — RestoreVMs Method

**Files:**
- Create: `internal/app/restart.go`

**Step 1: Implement RestoreVMs**

Create `internal/app/restart.go`:

```go
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// RestoreVMs handles boot recovery. For each VM:
//   - policy=none + state=running → mark as stopped (daemon crashed)
//   - policy=on-boot or always → restart regardless of previous state
func (s *VMService) RestoreVMs(ctx context.Context) {
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		log.Error("restore: list vms", "err", err)
		return
	}

	var restored, cleaned int
	for _, vm := range vms {
		switch vm.RestartPolicy {
		case domain.RestartPolicyOnBoot, domain.RestartPolicyAlways:
			// Best-effort stop stale task (may still be alive in containerd).
			if err := s.runtime.Stop(ctx, vm.ID); err != nil {
				log.Debug("restore: stop stale task", "id", vm.ID, "err", err)
			}
			if err := s.runtime.Start(ctx, vm.ID); err != nil {
				log.Error("restore: start vm", "id", vm.ID, "name", vm.Name, "err", err)
				// Mark as stopped so state is honest.
				s.store.UpdateState(ctx, vm.ID, domain.VMStateStopped, time.Now().UTC()) //nolint:errcheck
				continue
			}
			if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateRunning, time.Now().UTC()); err != nil {
				log.Error("restore: update state", "id", vm.ID, "err", err)
				continue
			}
			restored++
			log.Info("vm restored", "id", vm.ID, "name", vm.Name, "policy", vm.RestartPolicy)

		case domain.RestartPolicyNone:
			if vm.State == domain.VMStateRunning {
				// Daemon crashed — mark as stopped.
				if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateStopped, time.Now().UTC()); err != nil {
					log.Error("restore: mark stopped", "id", vm.ID, "err", err)
					continue
				}
				// Best-effort stop stale task.
				if err := s.runtime.Stop(ctx, vm.ID); err != nil {
					log.Debug("restore: stop stale task", "id", vm.ID, "err", err)
				}
				cleaned++
				log.Info("vm marked stopped", "id", vm.ID, "name", vm.Name)
			}
		}
	}

	if restored > 0 || cleaned > 0 {
		log.Info("boot recovery complete", "restored", restored, "cleaned", cleaned)
	}
}
```

**Step 2: Verify compilation**

```bash
go build ./internal/app/...
```

Expected: success.

**Step 3: Commit**

```bash
git add internal/app/restart.go
git commit -m "feat(app): add RestoreVMs boot recovery method"
```

---

### Task 7: Crash Monitor — WatchExits and Background Goroutine

**Files:**
- Modify: `internal/domain/ports.go` (add WatchExits to Runtime interface)
- Modify: `internal/infra/containerd/runtime.go` (implement WatchExits)
- Modify: `internal/app/restart.go` (add StartCrashMonitor)

**Step 1: Add WatchExits to Runtime interface**

In `internal/domain/ports.go`, add to the `Runtime` interface:

```go
	WatchExits(ctx context.Context, onExit func(containerID string, exitCode uint32)) error
```

**Step 2: Implement WatchExits in containerd runtime**

Add to `internal/infra/containerd/runtime.go`:

```go
// WatchExits subscribes to task exit events in this runtime's namespace and
// calls onExit for each container init process that exits. Blocks until ctx
// is canceled. Exec process exits (e.ID != e.ContainerID) are filtered out.
func (r *Runtime) WatchExits(ctx context.Context, onExit func(containerID string, exitCode uint32)) error {
	filter := fmt.Sprintf("namespace==%s,topic==\"/tasks/exit\"", r.namespace)
	ch, errs := r.client.Subscribe(ctx, filter)

	for {
		select {
		case env := <-ch:
			if env == nil {
				return nil
			}
			v, err := typeurl.UnmarshalAny(env.Event)
			if err != nil {
				continue
			}
			e, ok := v.(*apievents.TaskExit)
			if !ok {
				continue
			}
			// Only handle init process exits, not exec process exits.
			if e.ID != e.ContainerID {
				continue
			}
			onExit(e.ContainerID, e.ExitStatus)

		case err := <-errs:
			if err == nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("event stream: %w", err)
		}
	}
}
```

Add these imports to `runtime.go`:

```go
	apievents "github.com/containerd/containerd/api/events"
	"github.com/containerd/typeurl/v2"
```

**Step 3: Promote containerd/api to direct dependency**

```bash
go get github.com/containerd/containerd/api
go get github.com/containerd/typeurl/v2
```

**Step 4: Add StartCrashMonitor to restart.go**

Add to `internal/app/restart.go`:

```go
// backoffState tracks per-VM restart backoff.
type backoffState struct {
	lastFailure time.Time
	delay       time.Duration
}

const (
	backoffInitial  = 1 * time.Second
	backoffMax      = 60 * time.Second
	backoffReset    = 30 * time.Second
	fixedRestartDelay = 5 * time.Second
)

// StartCrashMonitor runs the crash monitoring loop in a goroutine. It
// subscribes to containerd task exit events and restarts VMs with
// restart_policy=always using their configured strategy. Cancel ctx to stop.
func (s *VMService) StartCrashMonitor(ctx context.Context) {
	backoffs := make(map[string]*backoffState)

	go func() {
		err := s.runtime.WatchExits(ctx, func(containerID string, exitCode uint32) {
			vm, err := s.store.Get(ctx, containerID)
			if err != nil {
				log.Debug("crash monitor: vm not found", "container_id", containerID)
				return
			}
			if vm.RestartPolicy != domain.RestartPolicyAlways {
				// Not auto-restart — just mark as stopped.
				s.store.UpdateState(ctx, vm.ID, domain.VMStateStopped, time.Now().UTC()) //nolint:errcheck
				log.Info("vm exited", "id", vm.ID, "name", vm.Name, "exit_code", exitCode)
				return
			}

			// Apply restart strategy.
			switch vm.RestartStrategy {
			case domain.RestartStrategyFixed:
				select {
				case <-time.After(fixedRestartDelay):
				case <-ctx.Done():
					return
				}

			case domain.RestartStrategyBackoff:
				bs, ok := backoffs[vm.ID]
				if !ok {
					bs = &backoffState{delay: backoffInitial}
					backoffs[vm.ID] = bs
				}
				if time.Since(bs.lastFailure) > backoffReset {
					bs.delay = backoffInitial // stable long enough, reset
				}
				bs.lastFailure = time.Now()

				select {
				case <-time.After(bs.delay):
				case <-ctx.Done():
					return
				}

				// Double delay for next time, capped.
				bs.delay *= 2
				if bs.delay > backoffMax {
					bs.delay = backoffMax
				}

			case domain.RestartStrategyImmediate:
				// No delay.
			}

			if err := s.runtime.Start(ctx, vm.ID); err != nil {
				log.Error("crash monitor: restart failed", "id", vm.ID, "name", vm.Name, "err", err)
				return
			}
			if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateRunning, time.Now().UTC()); err != nil {
				log.Error("crash monitor: update state", "id", vm.ID, "err", err)
				return
			}
			log.Info("vm restarted", "id", vm.ID, "name", vm.Name, "exit_code", exitCode, "strategy", vm.RestartStrategy)

			// Reset backoff on successful restart.
			if vm.RestartStrategy == domain.RestartStrategyBackoff {
				// Don't reset delay here — it resets after backoffReset of stability.
			}
		})
		if err != nil && ctx.Err() == nil {
			log.Error("crash monitor stopped", "err", err)
		}
	}()
}
```

**Step 5: Verify compilation**

```bash
go build ./...
```

Expected: success.

**Step 6: Commit**

```bash
git add internal/domain/ports.go internal/infra/containerd/runtime.go internal/app/restart.go go.mod go.sum
git commit -m "feat: add crash monitor with containerd task exit event subscription"
```

---

### Task 8: Wire into Daemon Startup

**Files:**
- Modify: `cmd/daemon.go`

**Step 1: Add RestoreVMs and StartCrashMonitor calls**

In `cmd/daemon.go`, after the `SyncDNS` call (line 163-165) and before `httpapi.NewHandler` (line 167), add:

```go
			svc.RestoreVMs(context.Background())

			monitorCtx, monitorCancel := context.WithCancel(context.Background())
			defer monitorCancel()
			svc.StartCrashMonitor(monitorCtx)
```

The `monitorCancel` will be called during shutdown via `defer`, stopping the crash monitor goroutine before the containerd connection is closed.

**Step 2: Verify compilation**

```bash
go build ./...
```

Expected: success.

**Step 3: Commit**

```bash
git add cmd/daemon.go
git commit -m "feat(daemon): wire RestoreVMs and StartCrashMonitor into startup"
```

---

### Task 9: Unit Tests — Domain Validation and Backoff Logic

**Files:**
- Create: `internal/domain/vm_test.go`
- Create: `internal/app/restart_test.go`

**Step 1: Write domain validation tests**

Create `internal/domain/vm_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
package domain

import "testing"

func TestValidRestartPolicy(t *testing.T) {
	tests := []struct {
		policy RestartPolicy
		want   bool
	}{
		{RestartPolicyNone, true},
		{RestartPolicyOnBoot, true},
		{RestartPolicyAlways, true},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidRestartPolicy(tt.policy); got != tt.want {
			t.Errorf("ValidRestartPolicy(%q) = %v, want %v", tt.policy, got, tt.want)
		}
	}
}

func TestValidRestartStrategy(t *testing.T) {
	tests := []struct {
		strategy RestartStrategy
		want     bool
	}{
		{RestartStrategyImmediate, true},
		{RestartStrategyBackoff, true},
		{RestartStrategyFixed, true},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidRestartStrategy(tt.strategy); got != tt.want {
			t.Errorf("ValidRestartStrategy(%q) = %v, want %v", tt.strategy, got, tt.want)
		}
	}
}
```

**Step 2: Run domain tests**

```bash
go test -v ./internal/domain/...
```

Expected: PASS.

**Step 3: Commit**

```bash
git add internal/domain/vm_test.go
git commit -m "test(domain): add restart policy and strategy validation tests"
```

---

### Task 10: Update E2E Harness Client

**Files:**
- Modify: `tests/e2e/harness/harness.go`

**Step 1: Add restart policy fields to harness VM type**

In `tests/e2e/harness/harness.go`, add to the `VM` struct (after `StoppedAt`):

```go
	RestartPolicy   string `json:"restart_policy"`
	RestartStrategy string `json:"restart_strategy"`
```

**Step 2: Add CreateVMWithRestartPolicy client method**

Add after `CreateVMWithImage`:

```go
func (c *Client) CreateVMWithRestartPolicy(name, role, policy, strategy string) (*VM, error) {
	body := fmt.Sprintf(`{"name":%q,"role":%q,"restart_policy":%q,"restart_strategy":%q}`,
		name, role, policy, strategy)
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

**Step 3: Add UpdateRestartPolicy client method**

```go
func (c *Client) UpdateRestartPolicy(id, policy, strategy string) (*VM, error) {
	body := fmt.Sprintf(`{"restart_policy":%q,"restart_strategy":%q}`, policy, strategy)
	resp, err := c.put("/v1/vms/"+id+"/restart-policy", body)
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

**Step 4: Add put helper**

Add a `put` helper method (after the `delete` helper):

```go
func (c *Client) put(path, body string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, c.base+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}
```

**Step 5: Verify compilation**

```bash
cd tests/e2e && go build ./... && cd ../..
```

Expected: success.

**Step 6: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "test(e2e): add restart policy methods to harness client"
```

---

### Task 11: E2E Tests — Crash Restart, Boot Recovery, No-Policy Cleanup

**Files:**
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Add TestCrashRestart**

```go
func TestCrashRestart(t *testing.T) {
	d, c := startDaemon(t)

	// Create VM with always restart policy and immediate strategy for fast test.
	vm, err := c.CreateVMWithRestartPolicy("test-crash-restart", "agent", "always", "immediate")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Kill the containerd task externally.
	killCmd := exec.Command("ctr", "-n", d.Namespace(), "tasks", "kill", vm.ID, "--signal", "SIGKILL")
	if out, err := killCmd.CombinedOutput(); err != nil {
		t.Fatalf("ctr tasks kill: %v: %s", err, out)
	}

	// Wait for the crash monitor to restart the VM.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			t.Fatalf("get VM: %v", err)
		}
		if got.State == "running" {
			t.Log("VM restarted after crash")
			return // success
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM did not restart within 10s after task kill")
}
```

**Step 2: Add TestBootRecoveryKill9**

This test requires manual daemon lifecycle management (can't use the `startDaemon` helper which auto-cleans up).

```go
func TestBootRecoveryKill9(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	// Start first daemon instance.
	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithRestartPolicy("test-boot-recovery", "agent", "always", "immediate")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Kill the daemon with SIGKILL (simulates crash — no graceful shutdown).
	d1.Kill()

	// Start a second daemon on the same addr, namespace, and state dir.
	// StartDaemon creates a new namespace each time, so we need to reuse.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// The boot recovery should have restarted the VM.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if got.State == "running" {
			t.Log("VM restored after daemon kill -9")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM not restored to running within 10s after daemon restart")
}

func TestNoPolicyCleanupKill9(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	// Default policy is "none".
	vm, err := c.CreateVM("test-no-policy-cleanup", "agent")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Verify it's running.
	got, err := c.GetVM(vm.ID)
	if err != nil || got.State != "running" {
		d1.Stop()
		t.Fatalf("VM should be running, state=%s err=%v", got.State, err)
	}

	d1.Kill()

	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// The boot recovery should have marked the VM as stopped.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if got.State == "stopped" {
			t.Log("VM correctly marked as stopped after daemon kill -9 (policy=none)")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM not marked as stopped within 10s after daemon restart")
}
```

**Step 3: Add Kill and StartDaemonWithNamespace to harness**

In `tests/e2e/harness/harness.go`, add a `Kill` method to `Daemon`:

```go
// Kill sends SIGKILL to the daemon (simulates crash). Does NOT clean up
// namespace or XDG dir — those are reused by the next daemon instance.
func (d *Daemon) Kill() {
	if d.cmd.Process != nil {
		d.cmd.Process.Kill()
		d.cmd.Wait()
	}
}

// XDGDir returns the XDG temp directory used by this daemon.
func (d *Daemon) XDGDir() string { return d.xdgDir }
```

Add `StartDaemonWithNamespace`:

```go
// StartDaemonWithNamespace starts a daemon reusing an existing namespace and
// XDG directory. Used for testing boot recovery after daemon crash.
func StartDaemonWithNamespace(binary, binDir, addr, namespace, xdgDir string, opts ...DaemonOption) (*Daemon, error) {
	cfg := &daemonConfig{}
	for _, o := range opts {
		o(cfg)
	}

	args := []string{
		"daemon",
		"--listen", addr,
		"--namespace", namespace,
		"--log-level", "disabled",
		fmt.Sprintf("--network-enabled=%t", cfg.networkEnabled),
		fmt.Sprintf("--dns-enabled=%t", cfg.dnsEnabled),
	}
	if cfg.runtime != "" {
		args = append(args, "--runtime", cfg.runtime)
	}
	if cfg.drivesDir != "" {
		args = append(args, "--drives-dir", cfg.drivesDir)
	}

	var stderrBuf bytes.Buffer

	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+xdgDir+"/config",
		"XDG_STATE_HOME="+xdgDir+"/state",
		"PATH="+binDir+":"+os.Getenv("PATH"),
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start daemon: %w", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return &Daemon{
				cmd:       cmd,
				addr:      addr,
				xdgDir:    xdgDir,
				namespace: namespace,
				stderr:    &stderrBuf,
			}, nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	cmd.Process.Kill()
	cmd.Wait()
	return nil, fmt.Errorf("daemon did not become ready on %s within 10s", addr)
}
```

Override `cleanup` in `Kill` scenario — modify the existing `cleanup` method to not remove xdgDir or namespace if `Kill` was used. Simplest approach: make the `Daemon` track whether it owns cleanup. Add a `ownsCleanup` field:

Actually, simpler: just modify `Kill()` to NOT call cleanup. The `StopFatal` on `d2` will handle cleanup of the namespace since `d2` has the same namespace.

**Step 4: Run E2E tests**

```bash
go test -v -run "TestCrashRestart|TestBootRecovery|TestNoPolicyCleanup" -count=1 ./tests/e2e/
```

Expected: PASS.

**Step 5: Commit**

```bash
git add tests/e2e/harness/harness.go tests/e2e/nexus_test.go
git commit -m "test(e2e): add crash restart, boot recovery, and no-policy cleanup tests"
```

---

### Task 12: Verify Full Build and Run

**Step 1: Run all unit tests**

```bash
mise run test
```

Expected: all tests pass.

**Step 2: Build all binaries**

```bash
mise run build
```

Expected: success.

**Step 3: Run E2E suite**

```bash
mise run e2e
```

Expected: all tests pass including the new restart tests.

**Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: address issues found during full build verification"
```

**Step 5: Merge to master**

```bash
git checkout master
git merge --ff-only <branch-name>
git checkout <branch-name>
```
