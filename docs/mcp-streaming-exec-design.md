# MCP Streaming Exec Design

Approved design for feature #18 from `docs/remaining-features.md`.

## Summary

Replace `vm_exec` with a streaming implementation and remove
`vm_exec_stream`. The single `vm_exec` tool uses `ExecStreamVM` under
the hood, sending `run_command.stdout` / `run_command.stderr` JSON-RPC
notifications as chunks arrive. The mcp-bridge intercepts these
notifications and writes chunk text to stderr, making output visible to
the user during execution.

## Problem

MCP tool calls block until the tool returns a result. When `vm_exec`
runs a 10-second command, the user sees nothing for 10 seconds, then
gets all the output at once. This is unusable for long-running commands
and makes it impossible to tell if a command is stuck or working.

Two tools (`vm_exec` and `vm_exec_stream`) exist for the same operation.
The streaming version buffers into `bytes.Buffer` anyway, making it
identical to the buffered version in practice. One tool should do both.

## Prototype Findings

1. **MCP notifications flow through SSE** — mcp-go's
   `SendNotificationToClient` sends JSON-RPC notifications as SSE `data:`
   lines during the tool call.
2. **mcp-bridge can intercept notifications** — by checking the `method`
   field of each SSE payload before forwarding to stdout.
3. **Writing chunks to stderr works** — stderr output appears in real-time
   in Claude Code's Bash tool (which runs the mcp-bridge process). Slight
   initial buffering (~1-4 seconds) from Claude Code's polling, but output
   is clean text, not raw JSON.
4. **The tool result still returns normally** — accumulated output in the
   final `CallToolResult` for MCP clients that don't handle notifications.

## Design

### mcp-bridge Changes

Add `handleStreamingNotification` to `cmd/nexusctl/mcp_bridge.go`. For each
SSE `data:` payload, before forwarding to stdout:

1. Try to parse as JSON with `method` and `params.chunk` fields.
2. If method is `run_command.stdout` or `run_command.stderr`, write the
   chunk text to `os.Stderr` and skip forwarding the raw JSON to stdout.
3. Otherwise, forward to stdout as before.

Both stdout and stderr chunks go to `os.Stderr` — the bridge's stderr is
the user's terminal. The bridge's stdout is reserved for JSON-RPC responses
back to the MCP client.

### MCP Handler Changes

Replace both `vm_exec` and `vm_exec_stream` with a single `vm_exec` tool
in `internal/infra/mcp/handler.go`:

1. Use `svc.ExecStreamVM` (not `svc.ExecVM`).
2. Create notification-sending `io.Writer` wrappers that call
   `server.SendNotificationToClient` with method `run_command.stdout` /
   `run_command.stderr` and `{"chunk": "<text>"}` params.
3. Also tee output into `bytes.Buffer` for the final result.
4. Return accumulated output as the tool result.

The `io.Writer` wrapper:

```go
type notifyWriter struct {
    srv    *server.MCPServer
    ctx    context.Context
    method string // "run_command.stdout" or "run_command.stderr"
    buf    *bytes.Buffer
}

func (w *notifyWriter) Write(p []byte) (int, error) {
    w.buf.Write(p)
    _ = w.srv.SendNotificationToClient(w.ctx, w.method, map[string]any{
        "chunk": string(p),
    })
    return len(p), nil
}
```

### What Changes

- `vm_exec` — switches from `ExecVM` to `ExecStreamVM` with notification
  writers. Same tool name, same parameters, but now streams output.
- `vm_exec_stream` — removed entirely.
- `registerVMExecTools` — simplified to register only `vm_exec`.

### What Stays the Same

- The SSE HTTP endpoint (`/v1/vms/{id}/exec/stream`) — unchanged
- `nexusctl exec --stream` CLI — unchanged, already works perfectly
- The final tool result format — same `{exit_code, stdout, stderr}` JSON

### What MCP Clients See

- **Notification-aware clients** (via mcp-bridge): streaming chunks on
  stderr during execution, plus the full result at the end.
- **Standard MCP clients**: same behavior as today — tool blocks, returns
  full result. Notifications are silently ignored by clients that don't
  handle them.

## Testing

- **Unit**: `handleStreamingNotification` correctly identifies and extracts
  chunks from `run_command.stdout`/`run_command.stderr` notifications,
  returns false for other messages.
- **E2E**: Call `vm_exec` via the test harness MCP client, verify the
  result contains expected stdout/stderr/exit_code (notification delivery
  is best verified manually via mcp-bridge).
