# MCP Streaming Exec Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace `vm_exec` with a streaming implementation that sends output notifications during execution, and remove the redundant `vm_exec_stream` tool.

**Architecture:** Notification-sending `io.Writer` wrappers in the MCP handler + notification interception in the mcp-bridge. No new domain types or service methods.

**Tech Stack:** mcp-go `SendNotificationToClient`, JSON-RPC, SSE

---

### Task 1: Add notification interception to mcp-bridge

**Files:**
- Modify: `cmd/nexusctl/mcp_bridge.go`
- Create: `cmd/nexusctl/mcp_bridge_test.go`

**Step 1: Write the failing test**

No unit test file exists for mcp_bridge yet. Create one:

```go
// cmd/nexusctl/mcp_bridge_test.go
package main

import (
	"testing"
)

func TestHandleStreamingNotification_Stdout(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"run_command.stdout","params":{"chunk":"hello\n"}}`
	if !handleStreamingNotification(payload) {
		t.Fatal("expected true for run_command.stdout")
	}
}

func TestHandleStreamingNotification_Stderr(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"run_command.stderr","params":{"chunk":"warn\n"}}`
	if !handleStreamingNotification(payload) {
		t.Fatal("expected true for run_command.stderr")
	}
}

func TestHandleStreamingNotification_OtherMethod(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`
	if handleStreamingNotification(payload) {
		t.Fatal("expected false for non-streaming notification")
	}
}

func TestHandleStreamingNotification_InvalidJSON(t *testing.T) {
	if handleStreamingNotification("not json") {
		t.Fatal("expected false for invalid JSON")
	}
}

func TestHandleStreamingNotification_ToolResult(t *testing.T) {
	payload := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`
	if handleStreamingNotification(payload) {
		t.Fatal("expected false for tool result (no method field)")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/nexusctl/ -run TestHandleStreamingNotification -v`
Expected: FAIL — `handleStreamingNotification` undefined

**Step 3: Write the implementation**

Add to `cmd/nexusctl/mcp_bridge.go`:

```go
import "encoding/json"

// handleStreamingNotification checks if a JSON-RPC message is a
// run_command.stdout or run_command.stderr notification. If so, it
// writes the chunk text to stderr (visible to the user) and returns
// true so the caller skips forwarding raw JSON to stdout.
func handleStreamingNotification(payload string) bool {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Chunk string `json:"chunk"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return false
	}
	switch msg.Method {
	case "run_command.stdout":
		os.Stderr.WriteString(msg.Params.Chunk) //nolint:errcheck
		return true
	case "run_command.stderr":
		os.Stderr.WriteString(msg.Params.Chunk) //nolint:errcheck
		return true
	}
	return false
}
```

**Step 4: Wire into SSE handling**

In `runMCPBridge`, inside the SSE `data:` line handling, call
`handleStreamingNotification` before writing to stdout:

```go
if strings.HasPrefix(sseLine, "data: ") {
	payload := sseLine[len("data: "):]
	if handleStreamingNotification(payload) {
		continue
	}
	os.Stdout.WriteString(payload)
	os.Stdout.Write([]byte{'\n'})
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./cmd/nexusctl/ -run TestHandleStreamingNotification -v`
Expected: PASS (all 5 tests)

**Step 6: Build to verify compilation**

Run: `mise run build`
Expected: Clean build

**Step 7: Commit**

```bash
git add cmd/nexusctl/mcp_bridge.go cmd/nexusctl/mcp_bridge_test.go
git commit -m "feat(mcp-bridge): intercept run_command streaming notifications

Write stdout/stderr chunk text to stderr so users see streaming
output during MCP tool execution. Non-streaming SSE payloads pass
through to stdout unchanged."
```

---

### Task 2: Add notification-sending writers to MCP handler

**Files:**
- Create: `internal/infra/mcp/notify_writer.go`
- Create: `internal/infra/mcp/notify_writer_test.go`

**Step 1: Write the failing test**

```go
// internal/infra/mcp/notify_writer_test.go
package mcp

import (
	"bytes"
	"testing"
)

func TestNotifyWriter_Write(t *testing.T) {
	var buf bytes.Buffer
	w := &notifyWriter{buf: &buf}
	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5, got %d", n)
	}
	if buf.String() != "hello" {
		t.Fatalf("expected 'hello', got %q", buf.String())
	}
}

func TestNotifyWriter_MultipleWrites(t *testing.T) {
	var buf bytes.Buffer
	w := &notifyWriter{buf: &buf}
	w.Write([]byte("hello "))
	w.Write([]byte("world"))
	if buf.String() != "hello world" {
		t.Fatalf("expected 'hello world', got %q", buf.String())
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/infra/mcp/ -run TestNotifyWriter -v`
Expected: FAIL — `notifyWriter` undefined

**Step 3: Write the notifyWriter type**

Create `internal/infra/mcp/notify_writer.go`:

```go
package mcp

import (
	"bytes"
	"context"

	"github.com/mark3labs/mcp-go/server"
)

// notifyWriter is an io.Writer that sends each write as a JSON-RPC
// notification via the MCP server, and also accumulates the data in
// a buffer for the final tool result.
type notifyWriter struct {
	srv    *server.MCPServer
	ctx    context.Context
	method string // "run_command.stdout" or "run_command.stderr"
	buf    *bytes.Buffer
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	if w.srv != nil && w.ctx != nil {
		_ = w.srv.SendNotificationToClient(w.ctx, w.method, map[string]any{
			"chunk": string(p),
		})
	}
	return len(p), nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/infra/mcp/ -run TestNotifyWriter -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/infra/mcp/notify_writer.go internal/infra/mcp/notify_writer_test.go
git commit -m "feat(mcp): add notifyWriter for streaming exec notifications"
```

---

### Task 3: Replace vm_exec and remove vm_exec_stream

**Files:**
- Modify: `internal/infra/mcp/handler.go`

**Step 1: Replace vm_exec implementation**

In `registerVMExecTools`, replace the `vm_exec` tool handler. Current
implementation calls `svc.ExecVM` — change to use `svc.ExecStreamVM`
with `notifyWriter`:

```go
// vm_exec
s.AddTool(mcp.NewTool("vm_exec",
	mcp.WithDescription("Execute a command in a running VM"),
	mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
	mcp.WithString("cmd", mcp.Description("Command as JSON array (e.g. [\"ls\",\"-la\"])"), mcp.Required()),
), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, errRes := requireString(req, "id")
	if errRes != nil {
		return errRes, nil
	}
	cmdStr, errRes := requireString(req, "cmd")
	if errRes != nil {
		return errRes, nil
	}

	var cmd []string
	if err := json.Unmarshal([]byte(cmdStr), &cmd); err != nil {
		return errResult(fmt.Errorf("cmd must be a JSON array of strings: %w", err))
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutW := &notifyWriter{srv: s, ctx: ctx, method: "run_command.stdout", buf: &stdoutBuf}
	stderrW := &notifyWriter{srv: s, ctx: ctx, method: "run_command.stderr", buf: &stderrBuf}
	exitCode, err := svc.ExecStreamVM(ctx, id, cmd, stdoutW, stderrW)
	if err != nil {
		return errResult(err)
	}

	return jsonResult(map[string]any{
		"exit_code": exitCode,
		"stdout":    stdoutBuf.String(),
		"stderr":    stderrBuf.String(),
	})
})
```

**Step 2: Remove vm_exec_stream tool registration**

Delete the entire `vm_exec_stream` tool registration block (the second
`s.AddTool` call in `registerVMExecTools`).

**Step 3: Build and verify**

Run: `mise run build`
Expected: Clean build

**Step 4: Run unit and e2e tests**

Run: `mise run test && mise run e2e`
Expected: All tests pass. The MCP e2e test (`TestMCP`) calls `vm_exec`
and expects `{"exit_code":0,"stdout":"..."}` — the new `map[string]any`
result produces these exact keys, so no test changes needed.

**Step 5: Commit**

```bash
git add internal/infra/mcp/handler.go
git commit -m "feat(mcp): replace vm_exec with streaming implementation

vm_exec now uses ExecStreamVM with notifyWriter, sending
run_command.stdout/run_command.stderr notifications as output
arrives. Removes redundant vm_exec_stream tool.

The tool result still contains the full buffered output for
standard MCP clients that don't handle notifications."
```

---

### Task 4: E2E verification

**Step 1: Build**

Run: `mise run build`

**Step 2: Manual test via MCP**

Start the daemon, create and start a test VM, then test via the MCP tool:

```bash
# In one terminal: start daemon
mise run run

# In another: call vm_exec through MCP bridge
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' | build/nexusctl mcp-bridge

# Then call vm_exec with a slow command
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vm_exec","arguments":{"id":"<vm-name>","cmd":"[\"/bin/sh\",\"-c\",\"for i in 1 2 3 4 5; do echo line$i; sleep 1; done\"]"}}}' | build/nexusctl mcp-bridge
```

Expected: Chunk text appears on stderr as the command runs, then the
JSON-RPC result appears on stdout with full output.

**Step 3: Commit any fixes**

If manual testing reveals issues, fix and commit.
