# Terminal Access Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Interactive TTY console for running VMs via WebSocket, usable by both xterm.js and nexusctl.

**Architecture:** New `ExecConsole` method on the Runtime interface returns a `ConsoleSession` handle with stdin/stdout/resize/close. A raw WebSocket handler on the same `http.ServeMux` upgrades the connection and bridges I/O between the WebSocket and the console session. Per-VM `shell` field controls the default command.

**Tech Stack:** Go, containerd v2 (`cio.WithStreams`, `cio.WithTerminal`, `process.Resize`), gorilla/websocket, huma v2 (existing, not used for WebSocket)

---

### Task 1: Add ConsoleSession to Domain

**Files:**
- Create: `internal/domain/console.go`

**Step 1: Create the ConsoleSession type**

Create `internal/domain/console.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import (
	"context"
	"io"
)

// ConsoleSession represents an interactive TTY session inside a VM.
type ConsoleSession struct {
	Stdin  io.WriteCloser
	Stdout io.Reader
	Wait   func() (int, error)
	Resize func(ctx context.Context, w, h uint32) error
	Close  func()
}
```

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./internal/domain/...`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/domain/console.go
git commit -m "feat(domain): add ConsoleSession type"
```

---

### Task 2: Add Shell Field to VM Domain

**Files:**
- Modify: `internal/domain/vm.go:36-51`
- Modify: `internal/domain/vm.go:53-61`

**Step 1: Add Shell to VM struct**

In `internal/domain/vm.go`, add `Shell` field to the `VM` struct after `RootSize`
(line 47):

```go
Shell    string    // default shell for console, empty = /bin/sh
```

**Step 2: Add Shell to CreateVMParams**

In the same file, add `Shell` to `CreateVMParams` after `RootSize` (line 60):

```go
Shell    string
```

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/domain/vm.go
git commit -m "feat(domain): add Shell field to VM and CreateVMParams"
```

---

### Task 3: Add ExecConsole to Runtime Interface

**Files:**
- Modify: `internal/domain/ports.go:25-34`

**Step 1: Add ExecConsole to the Runtime interface**

In `internal/domain/ports.go`, add `ExecConsole` after `ExecStream` (or after
`Exec` if `ExecStream` hasn't been added yet):

```go
ExecConsole(ctx context.Context, id string, cmd []string, cols, rows uint16) (*ConsoleSession, error)
```

**Step 2: Verify the interface change is recognized**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: Compilation error — containerd `Runtime` struct doesn't implement
`ExecConsole` yet. That's expected; Task 5 fixes it.

**Step 3: Commit**

```bash
git add internal/domain/ports.go
git commit -m "feat(domain): add ExecConsole to Runtime interface"
```

---

### Task 4: Add Shell Migration and SQLite Queries

**Files:**
- Create: `internal/infra/sqlite/migrations/008_add_vm_shell.sql`
- Modify: `internal/infra/sqlite/queries.sql`

**Step 1: Create migration 008**

Create `internal/infra/sqlite/migrations/008_add_vm_shell.sql`:

```sql
-- +goose Up
ALTER TABLE vms ADD COLUMN shell TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE vms DROP COLUMN shell;
```

**Important:** Check the existing migrations directory first. If migration 008
already exists (e.g. from the auto-start feature), use the next available number
(009, etc.).

**Step 2: Update all VM SELECT queries to include shell**

In `internal/infra/sqlite/queries.sql`, add `shell` to every VM SELECT column
list. There are 5 queries that select VM columns:

- `GetVM` (line 8)
- `GetVMByName` (line 12)
- `ListVMs` (line 16)
- `ListVMsByRole` (line 20)
- `ResolveVM` (line 106)

For each, add `, shell` after `root_size` in the SELECT list. Example for `GetVM`:

```sql
-- name: GetVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, shell
FROM vms WHERE id = ?;
```

**Step 3: Update InsertVM to include shell**

Update the `InsertVM` query (line 3-5) to include `shell`:

```sql
-- name: InsertVM :exec
INSERT INTO vms (id, name, role, image, runtime, state, created_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, shell)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
```

**Step 4: Add UpdateVMShell query**

Add after `UpdateVMRootSize` (line 33):

```sql
-- name: UpdateVMShell :exec
UPDATE vms SET shell = ? WHERE id = ?;
```

**Step 5: Regenerate sqlc**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && sqlc generate`
Expected: Regenerates `internal/infra/sqlite/models.go` and
`internal/infra/sqlite/queries.sql.go` with the new `Shell` field.

**Step 6: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: Compilation errors in `store.go` — `vmFromRow` and `Create` don't
handle the `Shell` field yet. Fixed in Task 5.

**Step 7: Commit**

```bash
git add internal/infra/sqlite/migrations/ internal/infra/sqlite/queries.sql internal/infra/sqlite/models.go internal/infra/sqlite/queries.sql.go
git commit -m "feat(sqlite): add shell column and update VM queries"
```

---

### Task 5: Update SQLite Store for Shell Field

**Files:**
- Modify: `internal/infra/sqlite/store.go`

**Step 1: Update vmFromRow**

In `internal/infra/sqlite/store.go`, update `vmFromRow` (around line 460) to
include `Shell`:

```go
func vmFromRow(row Vm) (*domain.VM, error) {
	vm := &domain.VM{
		ID:        row.ID,
		Name:      row.Name,
		Role:      domain.VMRole(row.Role),
		State:     domain.VMState(row.State),
		Image:     row.Image,
		Runtime:   row.Runtime,
		IP:        row.Ip,
		Gateway:   row.Gateway,
		NetNSPath: row.NetnsPath,
		RootSize:  row.RootSize,
		Shell:     row.Shell,
	}
	// ... rest unchanged
```

**Step 2: Update Store.Create**

In the `Create` method (around line 90), add `Shell` to the `InsertVMParams`:

```go
return s.q.InsertVM(ctx, InsertVMParams{
	// ... existing fields ...
	RootSize:   vm.RootSize,
	Shell:      vm.Shell,
})
```

**Step 3: Add UpdateShell method to Store**

Add after the existing `UpdateRootSize` method:

```go
func (s *Store) UpdateShell(ctx context.Context, id, shell string) error {
	return s.q.UpdateVMShell(ctx, UpdateVMShellParams{
		Shell: shell,
		ID:    id,
	})
}
```

**Step 4: Add UpdateShell to VMStore interface**

In `internal/domain/ports.go`, add to the `VMStore` interface (after
`UpdateRootSize`):

```go
UpdateShell(ctx context.Context, id, shell string) error
```

**Step 5: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: Still fails — containerd Runtime doesn't implement `ExecConsole` yet.
But `store.go` should compile cleanly.

**Step 6: Commit**

```bash
git add internal/infra/sqlite/store.go internal/domain/ports.go
git commit -m "feat(sqlite): wire shell field into store and VMStore interface"
```

---

### Task 6: Implement ExecConsole in Containerd Runtime

**Files:**
- Modify: `internal/infra/containerd/runtime.go`

**Step 1: Add gorilla/websocket dependency**

This task doesn't need websocket yet, but add the dependency now since it's
needed later:

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go get github.com/gorilla/websocket`

**Step 2: Add ExecConsole method**

Add the following method to `internal/infra/containerd/runtime.go`, after the
existing `ExecStream` method (or after `Exec` if `ExecStream` hasn't been added):

```go
// ExecConsole creates an interactive TTY exec session and returns a handle
// for bidirectional I/O. The caller is responsible for calling Close.
func (r *Runtime) ExecConsole(ctx context.Context, id string, cmd []string, cols, rows uint16) (*domain.ConsoleSession, error) {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get task %s: %w", id, err)
	}

	spec, err := container.Spec(ctx)
	if err != nil {
		return nil, fmt.Errorf("get spec %s: %w", id, err)
	}

	pspec := *spec.Process
	pspec.Args = cmd
	pspec.Terminal = true
	pspec.ConsoleSize = &specs.Box{
		Height: uint(rows),
		Width:  uint(cols),
	}

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	execID := fmt.Sprintf("%s-tty-%s", id, nxid.New())
	proc, err := task.Exec(ctx, execID, &pspec,
		cio.NewCreator(cio.WithFIFODir(os.TempDir()), cio.WithStreams(stdinR, stdoutW, nil), cio.WithTerminal),
	)
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		return nil, fmt.Errorf("exec console in %s: %w", id, err)
	}

	if err := proc.Start(ctx); err != nil {
		proc.Delete(ctx) //nolint:errcheck
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		return nil, fmt.Errorf("start console exec %s: %w", id, err)
	}

	return &domain.ConsoleSession{
		Stdin:  stdinW,
		Stdout: stdoutR,
		Wait: func() (int, error) {
			ch, err := proc.Wait(ctx)
			if err != nil {
				return -1, err
			}
			status := <-ch
			stdoutW.Close() // signal EOF to reader
			return int(status.ExitCode()), nil
		},
		Resize: func(rctx context.Context, w, h uint32) error {
			return proc.Resize(rctx, w, h)
		},
		Close: func() {
			proc.Kill(ctx, syscall.SIGKILL) //nolint:errcheck
			proc.Delete(ctx)                //nolint:errcheck
			stdinR.Close()
			stdinW.Close()
			stdoutR.Close()
			stdoutW.Close()
		},
	}, nil
}
```

**Key implementation notes for the engineer:**
- `Terminal: true` tells containerd to allocate a PTY. Stdout and stderr merge
  into a single stream (standard PTY behavior), so we pass `nil` for stderr.
- `cio.WithTerminal` must be paired with `cio.WithStreams` — it sets the IO
  config's `Terminal` flag.
- `io.Pipe()` connects the containerd FIFOs to the caller. The containerd shim
  reads from `stdinR` and writes to `stdoutW`.
- `Wait` closes `stdoutW` on exit so the stdout reader gets EOF.
- `Close` force-kills the process — used when the WebSocket disconnects.
- `ConsoleSize` uses `specs.Box{Height, Width}` with `uint` type.

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS — Runtime interface is now satisfied.

**Step 4: Commit**

```bash
git add internal/infra/containerd/runtime.go go.mod go.sum
git commit -m "feat(containerd): implement ExecConsole with PTY support"
```

---

### Task 7: Add VMService Methods (Shell + Console)

**Files:**
- Modify: `internal/app/vm_service.go`

**Step 1: Wire Shell into CreateVM**

In `internal/app/vm_service.go`, in the `CreateVM` method, add `Shell` to the VM
struct construction (around line 111-119):

```go
vm := &domain.VM{
	ID:        nxid.New(),
	Name:      params.Name,
	Role:      params.Role,
	State:     domain.VMStateCreated,
	Image:     params.Image,
	Runtime:   params.Runtime,
	RootSize:  params.RootSize,
	Shell:     params.Shell,
	CreatedAt: time.Now().UTC(),
}
```

**Step 2: Add UpdateShell method**

Add after `ExpandRootSize`:

```go
// UpdateShell sets the default shell for console sessions.
func (s *VMService) UpdateShell(ctx context.Context, ref, shell string) (*domain.VM, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateShell(ctx, vm.ID, shell); err != nil {
		return nil, fmt.Errorf("update shell: %w", err)
	}
	return s.store.Get(ctx, vm.ID)
}
```

**Step 3: Add ExecConsoleVM method**

Add after `ExecStreamVM` (or after `ExecVM`):

```go
// ExecConsoleVM opens an interactive TTY console in the VM.
func (s *VMService) ExecConsoleVM(ctx context.Context, ref string, cmd []string, cols, rows uint16) (*domain.ConsoleSession, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	// Shell resolution: explicit cmd > VM shell field > /bin/sh
	if len(cmd) == 0 {
		shell := vm.Shell
		if shell == "" {
			shell = "/bin/sh"
		}
		cmd = []string{shell}
	}

	return s.runtime.ExecConsole(ctx, vm.ID, cmd, cols, rows)
}
```

You'll need to add `"io"` to the imports if not already present (it may already
be there from `ExecStreamVM`).

**Step 4: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/app/vm_service.go
git commit -m "feat(app): add UpdateShell and ExecConsoleVM methods"
```

---

### Task 8: Add Shell to HTTP API (Create + Patch + Response)

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

**Step 1: Add Shell to CreateVMInput**

In `internal/infra/httpapi/handler.go`, add `Shell` to `CreateVMInput.Body`
(after `RootSize`, around line 32):

```go
Shell    string `json:"shell,omitempty" doc:"Default shell for console sessions"`
```

**Step 2: Add Shell to PatchVMInput**

Add `Shell` to `PatchVMInput.Body` (after `RootSize`, around line 47):

```go
Shell *string `json:"shell,omitempty" doc:"Default shell for console sessions"`
```

Use `*string` so we can distinguish "not provided" from "set to empty string"
(empty string means reset to default `/bin/sh`).

**Step 3: Add Shell to vmResponse**

Add `Shell` to the `vmResponse` struct (after `RootSize`, around line 153):

```go
Shell string `json:"shell,omitempty" doc:"Default shell for console sessions"`
```

**Step 4: Update vmToResponse**

In the `vmToResponse` function, add after the `RootSize` block:

```go
r.Shell = vm.Shell
```

**Step 5: Wire Shell into CreateVM handler**

In the `create-vm` handler (around line 318), add `Shell` to `CreateVMParams`:

```go
vm, err := svc.CreateVM(ctx, domain.CreateVMParams{
	Name:      input.Body.Name,
	Role:      domain.VMRole(input.Body.Role),
	Image:     input.Body.Image,
	Runtime:   input.Body.Runtime,
	DNSConfig: dnsCfg,
	RootSize:  rootSize,
	Shell:     input.Body.Shell,
})
```

**Step 6: Wire Shell into PatchVM handler**

In the `patch-vm` handler (around line 441), add shell handling before the
`GetVM` call:

```go
if input.Body.Shell != nil {
	if _, err := svc.UpdateShell(ctx, input.ID, *input.Body.Shell); err != nil {
		return nil, mapDomainError(err)
	}
}
```

**Step 7: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 8: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat(httpapi): add shell field to create, patch, and response"
```

---

### Task 9: Add WebSocket Console Endpoint

**Files:**
- Create: `internal/infra/httpapi/console.go`
- Modify: `internal/infra/httpapi/handler.go:276-288`

**Step 1: Create the console handler**

Create `internal/infra/httpapi/console.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/charmbracelet/log"
	"github.com/gorilla/websocket"

	"github.com/Work-Fort/Nexus/internal/app"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type resizeMsg struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

func handleConsole(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		// Parse optional query params.
		var cmd []string
		if q := r.URL.Query().Get("cmd"); q != "" {
			cmd = []string{q}
		}
		cols := uint16(80)
		rows := uint16(24)
		if c, err := strconv.ParseUint(r.URL.Query().Get("cols"), 10, 16); err == nil && c > 0 {
			cols = uint16(c)
		}
		if ro, err := strconv.ParseUint(r.URL.Query().Get("rows"), 10, 16); err == nil && ro > 0 {
			rows = uint16(ro)
		}

		// Validate VM before upgrading — allows returning proper HTTP errors.
		sess, err := svc.ExecConsoleVM(r.Context(), id, cmd, cols, rows)
		if err != nil {
			log.Error("console exec", "vm", id, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer sess.Close()

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Error("websocket upgrade", "err", err)
			return
		}
		defer ws.Close()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// Goroutine: read from PTY stdout → write to WebSocket.
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := sess.Stdout.Read(buf)
				if err != nil {
					cancel()
					return
				}
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					cancel()
					return
				}
			}
		}()

		// Goroutine: wait for process exit → send exit event, close WebSocket.
		go func() {
			exitCode, _ := sess.Wait()
			exitMsg, _ := json.Marshal(map[string]any{"type": "exit", "exit_code": exitCode})
			ws.WriteMessage(websocket.TextMessage, exitMsg) //nolint:errcheck
			cancel()
		}()

		// Main loop: read from WebSocket → write to PTY stdin or resize.
		for {
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				return
			}

			if msgType == websocket.TextMessage {
				var msg resizeMsg
				if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 {
					sess.Resize(ctx, msg.Cols, msg.Rows) //nolint:errcheck
					continue
				}
			}

			// Everything else is stdin input.
			if _, err := sess.Stdin.Write(data); err != nil {
				return
			}
		}
	}
}
```

**Step 2: Register the WebSocket route**

In `internal/infra/httpapi/handler.go`, update `NewHandler` (around line 276-288)
to register the WebSocket route on the mux before returning:

```go
func NewHandler(svc *app.VMService) http.Handler {
	mux := http.NewServeMux()
	config := huma.DefaultConfig("Nexus API", "1.0.0")
	api := humago.New(mux, config)

	registerVMRoutes(api, svc)
	registerDriveRoutes(api, svc)
	registerDeviceRoutes(api, svc)
	registerNetworkRoutes(api, svc)
	registerBackupRoutes(api, svc)

	// WebSocket endpoints (not supported by huma).
	mux.HandleFunc("GET /v1/vms/{id}/console", handleConsole(svc))

	return mux
}
```

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/infra/httpapi/console.go internal/infra/httpapi/handler.go
git commit -m "feat(httpapi): add WebSocket console endpoint"
```

---

### Task 10: E2E Harness — Add Console Client

**Files:**
- Modify: `tests/e2e/harness/harness.go`

**Step 1: Add gorilla/websocket to test dependencies**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go get github.com/gorilla/websocket`

If already added in Task 6, this is a no-op.

**Step 2: Add ConsoleSession type and ConsoleVM method**

Add after the existing `ExecStreamVM` method (or after `ExecVM`):

```go
// ConsoleSession wraps a WebSocket connection to a VM console.
type ConsoleSession struct {
	ws *websocket.Conn
}

// ConsoleVM opens a WebSocket console to the VM.
func (c *Client) ConsoleVM(id string, cols, rows int) (*ConsoleSession, error) {
	// Convert http:// to ws://
	wsURL := "ws" + strings.TrimPrefix(c.base, "http") +
		fmt.Sprintf("/v1/vms/%s/console?cols=%d&rows=%d", id, cols, rows)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial console: %w", err)
	}
	return &ConsoleSession{ws: ws}, nil
}

// Send writes data to the console stdin.
func (cs *ConsoleSession) Send(data string) error {
	return cs.ws.WriteMessage(websocket.TextMessage, []byte(data))
}

// Resize sends a resize message.
func (cs *ConsoleSession) Resize(cols, rows int) error {
	msg, _ := json.Marshal(map[string]any{"type": "resize", "cols": cols, "rows": rows})
	return cs.ws.WriteMessage(websocket.TextMessage, msg)
}

// ReadAll reads all messages until the WebSocket closes or an exit event is
// received. Returns collected output and the exit code.
func (cs *ConsoleSession) ReadAll() (output string, exitCode int, err error) {
	exitCode = -1
	for {
		msgType, data, err := cs.ws.ReadMessage()
		if err != nil {
			return output, exitCode, nil // connection closed
		}
		if msgType == websocket.TextMessage {
			var msg struct {
				Type     string `json:"type"`
				ExitCode int    `json:"exit_code"`
			}
			if json.Unmarshal(data, &msg) == nil && msg.Type == "exit" {
				return output, msg.ExitCode, nil
			}
		}
		if msgType == websocket.BinaryMessage {
			output += string(data)
		}
	}
}

// Close closes the WebSocket connection.
func (cs *ConsoleSession) Close() error {
	return cs.ws.Close()
}
```

You'll need to add `"github.com/gorilla/websocket"` to the import block.

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./tests/e2e/...`
Expected: PASS

**Step 4: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "test(harness): add WebSocket console client"
```

---

### Task 11: E2E Tests — Console Access

**Files:**
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Add the console test**

Add this test to `tests/e2e/nexus_test.go`:

```go
func TestConsole(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("console-test", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Open console session.
	sess, err := c.ConsoleVM(vm.ID, 80, 24)
	if err != nil {
		t.Fatalf("ConsoleVM: %v", err)
	}
	defer sess.Close()

	// Send a command and exit.
	if err := sess.Send("echo hello-console\n"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := sess.Send("exit\n"); err != nil {
		t.Fatalf("send exit: %v", err)
	}

	output, exitCode, err := sess.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "hello-console") {
		t.Errorf("output missing 'hello-console', got: %q", output)
	}
}

func TestConsoleResize(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("console-resize", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	sess, err := c.ConsoleVM(vm.ID, 80, 24)
	if err != nil {
		t.Fatalf("ConsoleVM: %v", err)
	}
	defer sess.Close()

	// Resize should not error.
	if err := sess.Resize(120, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}

	// Verify the terminal still works after resize.
	if err := sess.Send("echo resize-ok\n"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := sess.Send("exit\n"); err != nil {
		t.Fatalf("send exit: %v", err)
	}

	output, exitCode, err := sess.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "resize-ok") {
		t.Errorf("output missing 'resize-ok', got: %q", output)
	}
}

func TestConsoleCustomShell(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("console-shell", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Open console with explicit command override.
	wsURL := "ws" + strings.TrimPrefix(c.BaseURL(), "http") +
		fmt.Sprintf("/v1/vms/%s/console?cmd=/bin/sh&cols=80&rows=24", vm.ID)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	ws.WriteMessage(websocket.TextMessage, []byte("echo cmd-override\n"))  //nolint:errcheck
	ws.WriteMessage(websocket.TextMessage, []byte("exit\n"))               //nolint:errcheck

	// Read until exit or timeout.
	var output string
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			break
		}
		output += string(data)
		if strings.Contains(output, "cmd-override") {
			break
		}
	}

	if !strings.Contains(output, "cmd-override") {
		t.Errorf("output missing 'cmd-override', got: %q", output)
	}
}
```

You'll need to add `"github.com/gorilla/websocket"` to the import block of the
test file. Also add a `BaseURL()` method to the harness `Client` if it doesn't
exist:

In `tests/e2e/harness/harness.go`, add:

```go
// BaseURL returns the base HTTP URL of the API.
func (c *Client) BaseURL() string {
	return c.base
}
```

**Step 2: Run the E2E tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./tests/e2e/ -run TestConsole -v -count=1 -timeout 120s`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/e2e/nexus_test.go tests/e2e/harness/harness.go
git commit -m "test(e2e): add console WebSocket tests"
```

---

### Task 12: Full Verification

**Step 1: Run the full build**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 2: Run unit tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/... -v -count=1`
Expected: PASS

**Step 3: Run E2E tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./tests/e2e/ -v -count=1 -timeout 300s`
Expected: PASS

**Step 4: Manual test with websocat**

```bash
# Install websocat if needed: cargo install websocat
# Start a VM and get its ID, then:
websocat ws://localhost:7777/v1/vms/<vm-id>/console?cols=80&rows=24
```

You should get an interactive shell. Type commands and see output. Press Ctrl-D
or type `exit` to end the session.
