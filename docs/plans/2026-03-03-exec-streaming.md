# Exec Streaming Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stream command output from running VMs via Server-Sent Events alongside the existing buffered exec endpoint.

**Architecture:** New `ExecStream` method on the `Runtime` interface passes caller-supplied `io.Writer` values to containerd's `cio.WithStreams`, letting bytes flow incrementally. The HTTP layer uses huma's `sse.Register` to deliver stdout/stderr/exit events to clients.

**Tech Stack:** Go, containerd v2 client (`cio.WithStreams`), huma v2 SSE (`github.com/danielgtaylor/huma/v2/sse`)

---

### Task 1: Add ExecStream to Runtime Interface

**Files:**
- Modify: `internal/domain/ports.go:25-34`

**Step 1: Add ExecStream to the Runtime interface**

In `internal/domain/ports.go`, add `ExecStream` to the `Runtime` interface, right after the existing `Exec` method on line 30:

```go
ExecStream(ctx context.Context, id string, cmd []string, stdout, stderr io.Writer) (int, error)
```

The full `Runtime` interface should become:

```go
type Runtime interface {
	Create(ctx context.Context, id, image, runtimeHandler string, opts ...CreateOpt) error
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	Exec(ctx context.Context, id string, cmd []string) (*ExecResult, error)
	ExecStream(ctx context.Context, id string, cmd []string, stdout, stderr io.Writer) (int, error)
	SetSnapshotQuota(ctx context.Context, snapName string, sizeBytes int64) error
	ExportImage(ctx context.Context, imageRef string, w io.Writer) error
	ImportImage(ctx context.Context, reader io.Reader) (string, error)
}
```

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: Compilation error — containerd `Runtime` struct doesn't implement the new method yet. That's expected; we fix it in Task 2.

**Step 3: Commit**

```bash
git add internal/domain/ports.go
git commit -m "feat(domain): add ExecStream to Runtime interface"
```

---

### Task 2: Implement ExecStream in Containerd Runtime

**Files:**
- Modify: `internal/infra/containerd/runtime.go`

**Step 1: Add ExecStream method**

Add the following method to `internal/infra/containerd/runtime.go`, right after the existing `Exec` method (after line 407):

```go
// ExecStream runs a command inside the running container's task and streams
// output to the provided writers. Returns the exit code when the process exits.
func (r *Runtime) ExecStream(ctx context.Context, id string, cmd []string, stdout, stderr io.Writer) (int, error) {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return -1, fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return -1, fmt.Errorf("get task %s: %w", id, err)
	}

	spec, err := container.Spec(ctx)
	if err != nil {
		return -1, fmt.Errorf("get spec %s: %w", id, err)
	}

	pspec := *spec.Process
	pspec.Args = cmd

	execID := fmt.Sprintf("%s-exec-%s", id, nxid.New())
	proc, err := task.Exec(ctx, execID, &pspec,
		cio.NewCreator(cio.WithFIFODir(os.TempDir()), cio.WithStreams(nil, stdout, stderr)),
	)
	if err != nil {
		return -1, fmt.Errorf("exec in %s: %w", id, err)
	}

	if err := proc.Start(ctx); err != nil {
		return -1, fmt.Errorf("start exec %s: %w", id, err)
	}

	ch, err := proc.Wait(ctx)
	if err != nil {
		return -1, fmt.Errorf("wait exec %s: %w", id, err)
	}
	status := <-ch

	proc.Delete(ctx) //nolint:errcheck // best-effort cleanup

	return int(status.ExitCode()), nil
}
```

This is nearly identical to the existing `Exec` method — the only difference is:
- Instead of `bytes.Buffer` for stdout/stderr, it accepts `io.Writer` parameters.
- Returns `(int, error)` instead of `(*ExecResult, error)` since the callers
  already have the writers.

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS — the `Runtime` interface is now satisfied.

**Step 3: Commit**

```bash
git add internal/infra/containerd/runtime.go
git commit -m "feat(containerd): implement ExecStream with caller-supplied writers"
```

---

### Task 3: Add ExecStreamVM to VMService

**Files:**
- Modify: `internal/app/vm_service.go`

**Step 1: Add ExecStreamVM method**

Add the following method to `internal/app/vm_service.go`, right after the existing `ExecVM` method (after line 290):

```go
// ExecStreamVM runs a command in the VM and streams output to the provided writers.
// Returns the exit code when the process exits.
func (s *VMService) ExecStreamVM(ctx context.Context, ref string, cmd []string, stdout, stderr io.Writer) (int, error) {
	if len(cmd) == 0 {
		return -1, fmt.Errorf("cmd is required: %w", domain.ErrValidation)
	}

	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return -1, err
	}
	if vm.State != domain.VMStateRunning {
		return -1, domain.ErrInvalidState
	}

	return s.runtime.ExecStream(ctx, vm.ID, cmd, stdout, stderr)
}
```

You'll also need to add `"io"` to the import block if it's not already there.

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/app/vm_service.go
git commit -m "feat(app): add ExecStreamVM method"
```

---

### Task 4: Add SSE Endpoint

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

This is the most involved task. We use huma's `sse.Register` to create the
streaming endpoint.

**Step 1: Add the SSE import**

Add `"github.com/danielgtaylor/huma/v2/sse"` to the import block in
`internal/infra/httpapi/handler.go`. Also add `"fmt"` and `"io"` and `"sync"` if
not already imported.

**Step 2: Add the sseWriter adapter**

Add this type somewhere in `internal/infra/httpapi/handler.go` (e.g. after the
`execResponse` type around line 183):

```go
// sseWriter adapts an SSE sender into an io.Writer. Each Write call sends one
// SSE event with the given event type.
type sseWriter struct {
	send      sse.Sender
	eventType string
	mu        *sync.Mutex
}

func (w *sseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.send(sse.Message{Data: string(p)}, w.eventType); err != nil {
		return 0, err
	}
	return len(p), nil
}
```

**Step 3: Register the SSE endpoint**

Add the following at the end of `registerVMRoutes` (before the closing brace),
after the `patch-vm` handler:

```go
type ExecStreamEvent struct {
	Data string `json:"data"`
}

type ExecStreamExitEvent struct {
	ExitCode int `json:"exit_code"`
}

sse.Register(api, huma.Operation{
	OperationID: "exec-stream-vm",
	Method:      http.MethodPost,
	Path:        "/v1/vms/{id}/exec/stream",
	Summary:     "Stream command output from a VM",
	Tags:        []string{"VMs"},
}, map[string]any{
	"stdout": ExecStreamEvent{},
	"stderr": ExecStreamEvent{},
	"exit":   ExecStreamExitEvent{},
}, func(ctx context.Context, input *ExecVMInput, send sse.Sender) {
	var mu sync.Mutex
	stdoutW := &sseWriter{send: send, eventType: "stdout", mu: &mu}
	stderrW := &sseWriter{send: send, eventType: "stderr", mu: &mu}

	exitCode, err := svc.ExecStreamVM(ctx, input.ID, input.Body.Cmd, stdoutW, stderrW)
	if err != nil {
		mu.Lock()
		send(sse.Message{Data: ExecStreamExitEvent{ExitCode: -1}}, "exit") //nolint:errcheck
		mu.Unlock()
		return
	}

	mu.Lock()
	send(sse.Message{Data: ExecStreamExitEvent{ExitCode: exitCode}}, "exit") //nolint:errcheck
	mu.Unlock()
})
```

**Important notes:**
- We reuse the existing `ExecVMInput` type (same path param + body `{"cmd": [...]}`).
- The `sseWriter` uses a mutex because containerd may write to stdout and stderr
  concurrently from separate goroutines. SSE is a single stream, so writes must
  be serialized.
- Errors from `ExecStreamVM` (e.g. VM not running) are sent as an exit event
  with code -1. The huma SSE handler has already started the response at this
  point, so we can't return an HTTP error status.

**Step 4: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

If the `sse.Sender` function signature doesn't match (check `sse.Sender` type —
it's `func(sse.Message) error` with event type set via `Message.Type` field),
adjust the `sseWriter` accordingly. The huma SSE `Message` struct is:

```go
type Message struct {
	ID    int
	Data  any
	Retry int
}
```

And `Sender` is `func(Message) error`. The event type is set by the map key in
`sse.Register`'s `eventTypeMap`. Check the huma SSE docs — if `Sender` takes
only `Message`, the event type is inferred from the `Data` type matching the
map. In that case, adjust the approach:

**Alternative sseWriter if Sender is `func(Message) error`:**

```go
type stdoutData struct {
	Data string `json:"data"`
}
type stderrData struct {
	Data string `json:"data"`
}
type exitData struct {
	ExitCode int `json:"exit_code"`
}
```

Register with:
```go
map[string]any{
	"stdout": stdoutData{},
	"stderr": stderrData{},
	"exit":   exitData{},
}
```

And the writer becomes:
```go
type sseWriter struct {
	send    sse.Sender
	makeMsg func(string) sse.Message
	mu      *sync.Mutex
}

func (w *sseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.send(w.makeMsg(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
```

With:
```go
stdoutW := &sseWriter{
	send: send,
	makeMsg: func(s string) sse.Message {
		return sse.Message{Data: stdoutData{Data: s}}
	},
	mu: &mu,
}
stderrW := &sseWriter{
	send: send,
	makeMsg: func(s string) sse.Message {
		return sse.Message{Data: stderrData{Data: s}}
	},
	mu: &mu,
}
```

The huma SSE library determines the event type by matching the concrete type of
`Message.Data` against the `eventTypeMap`. So `stdoutData{}` → event type
`"stdout"`, `stderrData{}` → `"stderr"`, `exitData{}` → `"exit"`.

**Use this alternative approach** — it's the correct huma SSE pattern.

**Step 5: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat(httpapi): add SSE exec streaming endpoint"
```

---

### Task 5: Unit Test — ExecStreamVM Rejects Stopped VMs

**Files:**
- Modify: existing VM service test file, or create `internal/app/vm_service_test.go` if it doesn't exist

**Step 1: Find the existing test file**

Run: `find internal/app -name '*_test.go'`

If no test file exists, create `internal/app/vm_service_test.go`.

**Step 2: Write the failing test**

```go
func TestExecStreamVM_RejectsStoppedVM(t *testing.T) {
	// Create a mock store that returns a stopped VM
	store := &mockVMStore{
		resolveVM: &domain.VM{
			ID:    "vm-1",
			Name:  "test",
			State: domain.VMStateStopped,
		},
	}
	svc := &app.VMService{} // need to construct with mock store

	var stdout, stderr bytes.Buffer
	_, err := svc.ExecStreamVM(context.Background(), "vm-1", []string{"ls"}, &stdout, &stderr)
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}
```

Adapt this to use whatever mock/test infrastructure exists in the project. Check
if there are existing tests under `internal/app/` for patterns.

If `VMService` fields are unexported (they are — `store`, `runtime` etc.), you
may need to either:
- Use the existing test helpers if they exist, or
- Test through the HTTP layer instead, or
- Add a constructor that accepts a mock store for testing.

Check the project for existing test patterns before implementing. If there's no
easy way to unit-test this in isolation, skip this step and rely on E2E tests
(Task 7).

**Step 3: Run the test**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestExecStreamVM -v`
Expected: PASS (or skip if decided to rely on E2E)

**Step 4: Commit**

```bash
git add internal/app/
git commit -m "test(app): ExecStreamVM rejects stopped VMs"
```

---

### Task 6: E2E Harness — Add ExecStreamVM Client

**Files:**
- Modify: `tests/e2e/harness/harness.go`

**Step 1: Add SSE event types**

Add these types near the existing `ExecResult` type in `tests/e2e/harness/harness.go`:

```go
// SSEEvent represents a parsed SSE event from the exec stream endpoint.
type SSEEvent struct {
	Type string // "stdout", "stderr", or "exit"
	Data string // raw data field
}
```

**Step 2: Add ExecStreamVM client method**

Add after the existing `ExecVM` method (around line 361):

```go
func (c *Client) ExecStreamVM(id string, cmd []string) ([]SSEEvent, error) {
	cmdJSON, _ := json.Marshal(cmd)
	body := fmt.Sprintf(`{"cmd":%s}`, cmdJSON)
	resp, err := c.post("/v1/vms/"+id+"/exec/stream", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return parseSSEStream(resp.Body)
}

// parseSSEStream reads an SSE stream and returns all events.
func parseSSEStream(r io.Reader) ([]SSEEvent, error) {
	var events []SSEEvent
	var currentType, currentData string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			currentType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			currentData = strings.TrimPrefix(line, "data: ")
		case line == "":
			if currentType != "" {
				events = append(events, SSEEvent{Type: currentType, Data: currentData})
				currentType = ""
				currentData = ""
			}
		}
	}
	// Handle final event if stream ends without trailing blank line
	if currentType != "" {
		events = append(events, SSEEvent{Type: currentType, Data: currentData})
	}

	return events, scanner.Err()
}
```

You'll need to add `"bufio"` to the import block.

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./tests/e2e/...`
Expected: PASS

**Step 4: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "test(harness): add ExecStreamVM SSE client"
```

---

### Task 7: E2E Test — Stream Exec

**Files:**
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Add the streaming exec test**

Add this test to `tests/e2e/nexus_test.go`, after the existing exec-related tests:

```go
func TestExecStream(t *testing.T) {
	d := startDaemon(t)
	c := d.Client()

	// Create and start a VM.
	vm := c.CreateVMFatal(t, "stream-test", "agent")
	c.StartVMFatal(t, vm.ID)
	waitRunning(t, c, vm.ID)

	// Stream exec: echo to stdout.
	events, err := c.ExecStreamVM(vm.ID, []string{"echo", "hello world"})
	if err != nil {
		t.Fatalf("ExecStreamVM: %v", err)
	}

	// Must have at least one stdout event and exactly one exit event.
	var gotStdout bool
	var exitEvent *harness.SSEEvent
	for i := range events {
		switch events[i].Type {
		case "stdout":
			gotStdout = true
		case "exit":
			exitEvent = &events[i]
		}
	}

	if !gotStdout {
		t.Fatal("expected at least one stdout event")
	}
	if exitEvent == nil {
		t.Fatal("expected an exit event")
	}
	if !strings.Contains(exitEvent.Data, `"exit_code":0`) && !strings.Contains(exitEvent.Data, `"exit_code": 0`) {
		t.Fatalf("expected exit_code 0, got: %s", exitEvent.Data)
	}

	// Stream exec: write to stderr.
	events, err = c.ExecStreamVM(vm.ID, []string{"sh", "-c", "echo err >&2"})
	if err != nil {
		t.Fatalf("ExecStreamVM stderr: %v", err)
	}

	var gotStderr bool
	for i := range events {
		if events[i].Type == "stderr" {
			gotStderr = true
		}
	}
	if !gotStderr {
		t.Fatal("expected at least one stderr event")
	}

	// Stream exec: non-zero exit code.
	events, err = c.ExecStreamVM(vm.ID, []string{"sh", "-c", "exit 42"})
	if err != nil {
		t.Fatalf("ExecStreamVM exit 42: %v", err)
	}

	exitEvent = nil
	for i := range events {
		if events[i].Type == "exit" {
			exitEvent = &events[i]
		}
	}
	if exitEvent == nil {
		t.Fatal("expected an exit event")
	}
	if !strings.Contains(exitEvent.Data, `"exit_code":42`) && !strings.Contains(exitEvent.Data, `"exit_code": 42`) {
		t.Fatalf("expected exit_code 42, got: %s", exitEvent.Data)
	}
}
```

Note: `startDaemon`, `waitRunning`, `CreateVMFatal`, `StartVMFatal` are existing
helpers — check the test file for exact signatures. Adjust the test to match
the existing patterns (e.g. if `startDaemon` takes different args, or if
`waitRunning` has a different name).

**Step 2: Run the E2E test**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./tests/e2e/ -run TestExecStream -v -count=1 -timeout 120s`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/e2e/nexus_test.go
git commit -m "test(e2e): add exec streaming tests"
```

---

### Task 8: Full Verification

**Step 1: Run the full build**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 2: Run unit tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/... -v -count=1`
Expected: PASS

**Step 3: Run E2E tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./tests/e2e/ -v -count=1 -timeout 300s`
Expected: PASS

**Step 4: Verify OpenAPI docs**

Start the daemon (`mise run run`) and visit `http://localhost:7777/docs`. Verify
that `POST /v1/vms/{id}/exec/stream` appears in the API docs with the correct
SSE event types.

**Step 5: Manual test**

```bash
# Start a VM (assumes one exists and is running)
curl -N -X POST http://localhost:7777/v1/vms/<vm-id>/exec/stream \
  -H 'Content-Type: application/json' \
  -d '{"cmd":["sh","-c","for i in 1 2 3; do echo line $i; sleep 0.5; done"]}'
```

Expected: Three `stdout` events arrive incrementally, followed by one `exit` event.
