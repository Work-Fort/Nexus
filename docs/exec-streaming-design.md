# Exec Streaming Design

Approved design for feature #6 from `docs/remaining-features.md`.

## Summary

Stream command output from a running VM via Server-Sent Events. New
`POST /v1/vms/{id}/exec/stream` endpoint alongside the existing buffered
exec endpoint. Debug/convenience — not a CI pipeline.

## Runtime Interface

New method on `domain.Runtime`:

```go
ExecStream(ctx context.Context, id string, cmd []string, stdout, stderr io.Writer) (int, error)
```

The containerd implementation passes the caller-supplied `io.Writer` values
directly to `cio.WithStreams` instead of `bytes.Buffer`. Bytes flow from
containerd FIFOs into the writers incrementally. Returns the exit code when
the process exits.

The existing `Exec` method stays unchanged.

## VMService

New `ExecStreamVM` method validates the VM is running, then delegates to
`runtime.ExecStream`. Same validation as `ExecVM`.

## SSE Endpoint

`POST /v1/vms/{id}/exec/stream`

Same input as existing exec (`{"cmd": [...]}`). Response is
`text/event-stream` with three event types:

| Event type | Data | When |
|-----------|------|------|
| `stdout` | raw text chunk | Each write to stdout |
| `stderr` | raw text chunk | Each write to stderr |
| `exit` | `{"exit_code": 0}` | Process exits (final event) |

Example stream:

```
event: stdout
data: total 42

event: stderr
data: warning: something

event: exit
data: {"exit_code": 0}
```

Uses `sse.Register` from `huma/v2/sse`. Two `io.Writer` adapters convert
writes into SSE events. After `ExecStreamVM` returns, a final `exit` event
carries the exit code.

The existing `POST /v1/vms/{id}/exec` endpoint is unchanged.

## Testing

- **Unit**: `ExecStreamVM` rejects stopped VMs.
- **E2E**: Stream exec producing stdout, stderr, and incremental output.
  Harness gets `ExecStreamVM` client that reads SSE events into a slice.
