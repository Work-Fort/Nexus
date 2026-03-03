# Terminal Access Design

Approved design for feature #7 from `docs/remaining-features.md`.

## Summary

Interactive TTY console for running VMs via WebSocket. One-shot sessions —
process dies when the connection closes. Works with both xterm.js (browser)
and nexusctl (CLI). Uses gorilla/websocket registered directly on the
`http.ServeMux` alongside huma routes.

## Runtime Interface

New method on `domain.Runtime`:

```go
ExecConsole(ctx context.Context, id string, cmd []string, cols, rows uint16) (*ConsoleSession, error)
```

Returns a session handle:

```go
type ConsoleSession struct {
    Stdin  io.WriteCloser
    Stdout io.Reader
    Wait   func() (int, error)   // blocks until process exits, returns exit code
    Resize func(ctx context.Context, w, h uint32) error
    Close  func()                // kills process + cleanup
}
```

The containerd implementation creates an exec process with `Terminal: true` and
`ConsoleSize`, wires up FIFOs via `cio.WithStreams` + `cio.WithTerminal`, starts
the process, and returns the session. With `Terminal: true`, stdout and stderr
merge into a single stream (standard PTY behavior).

`ConsoleSession` lives in `domain/` — plain struct with closures, no containerd
types leak out.

## WebSocket Endpoint

`GET /v1/vms/{id}/console?cmd=<optional>&cols=80&rows=24`

Registered directly on `http.ServeMux` (huma does not support WebSocket).
Uses gorilla/websocket for the HTTP upgrade.

### Message Protocol

| Direction | Frame type | Content | Meaning |
|-----------|-----------|---------|---------|
| Client → Server | Text | raw keystrokes | stdin input |
| Client → Server | Text | `{"type":"resize","cols":80,"rows":24}` | terminal resize |
| Server → Client | Binary | raw bytes | stdout (merged stdout+stderr) |
| Server → Client | Text | `{"type":"exit","exit_code":0}` | process exited (final) |

**Distinguishing stdin from resize:** If a client text frame is valid JSON with
`"type":"resize"`, it's a resize command. Everything else is stdin. Raw
keystrokes are never valid JSON with a `type` field.

### Handler Flow

1. Resolve VM by ID/name, validate it's running.
2. Determine shell: query param `cmd` > VM's `shell` field from DB > `/bin/sh`.
3. Upgrade to WebSocket.
4. Call `runtime.ExecConsole(ctx, id, cmd, cols, rows)`.
5. Two goroutines: one reads WebSocket → stdin/resize, the other reads
   stdout → WebSocket.
6. Process exits → send exit event, close WebSocket.
7. WebSocket closes first → `session.Close()` kills the process.

## Shell Resolution

New `shell` field on the VM (string, default empty).

Resolution order:

1. Query param `cmd` — client override.
2. VM's `shell` field — set via create or update API.
3. Fallback — `/bin/sh`.

### Data Model

```sql
ALTER TABLE vms ADD COLUMN shell TEXT NOT NULL DEFAULT '';
```

### API Changes

- `POST /v1/vms` — optional `"shell": "/bin/bash"` in create body.
- `PATCH /v1/vms/{id}` — update shell (add `shell` to `PatchVMInput`).
- VM response — new `"shell"` field (omitted if empty).

## Testing

- **Unit**: WebSocket handler rejects stopped VMs (HTTP error before upgrade).
  Shell resolution: query param > DB > fallback.
- **E2E**: Connect WebSocket, send keystrokes, receive output, verify exit event.
  Test resize via JSON frame. Test shell override via `?cmd=/bin/sh`.
  Harness gets a `ConsoleVM` client using gorilla/websocket.
