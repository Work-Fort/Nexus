# MCP Endpoint Design

Approved design for feature #8 from `docs/remaining-features.md`.

## Summary

HTTP streaming MCP server exposing REST-equivalent functions as MCP tools.
New infrastructure adapter at `internal/infra/mcp/` alongside the existing
`httpapi` adapter. Both call `*app.VMService` — the MCP adapter translates
between JSON-RPC tool calls and service methods.

Uses [mcp-go](https://github.com/mark3labs/mcp-go) (agreed with Sharkfin
team lead and TPM in `#mcp-integration`). Streamable HTTP transport at
`/mcp`.

## Architecture

New package `internal/infra/mcp/` with a single constructor:

```go
func NewHandler(svc *app.VMService) http.Handler
```

Internally creates an `mcp.Server` via `server.NewMCPServer`, registers
tools, and wraps it with `server.NewStreamableHTTPServer`. The returned
handler is mounted on the shared `http.ServeMux` in `daemon.go` alongside
the `httpapi` handler.

No new domain types or ports. The MCP adapter is pure infrastructure —
it only calls existing `VMService` methods and maps results to MCP tool
responses.

## Tool Surface

24 tools with full REST parity:

| Tool | VMService Method | Notes |
|------|-----------------|-------|
| `vm_create` | `CreateVM` | |
| `vm_list` | `ListVMs` | Optional `role` filter |
| `vm_get` | `GetVM` | |
| `vm_delete` | `DeleteVM` | |
| `vm_start` | `StartVM` | |
| `vm_stop` | `StopVM` | |
| `vm_exec` | `ExecVM` | Buffered exec |
| `vm_exec_stream` | `ExecStreamVM` | Returns concatenated output |
| `vm_export` | `ExportVM` | Returns base64 |
| `vm_import` | `ImportVM` | Accepts base64 |
| `vm_patch` | `ExpandRootSize` | |
| `vm_restart_policy` | `UpdateRestartPolicy` | |
| `drive_create` | `CreateDrive` | |
| `drive_list` | `ListDrives` | |
| `drive_get` | `GetDrive` | |
| `drive_delete` | `DeleteDrive` | |
| `drive_attach` | `AttachDrive` | |
| `drive_detach` | `DetachDrive` | |
| `device_create` | `CreateDevice` | |
| `device_list` | `ListDevices` | |
| `device_get` | `GetDevice` | |
| `device_delete` | `DeleteDevice` | |
| `device_attach` | `AttachDevice` | |
| `device_detach` | `DetachDevice` | |

Each tool is registered with `mcp.NewTool` + `mcp.WithString` /
`mcp.WithNumber` / `mcp.WithBoolean` for parameters. Tool handlers
extract parameters from `mcp.CallToolRequest`, call the corresponding
`VMService` method, and return `mcp.CallToolResult` with JSON-marshalled
content.

Initial release: tools only. Resources and prompts deferred.

## Daemon Wiring

In `daemon.go` (or wherever the `http.ListenAndServe` is configured):

```go
mux := http.NewServeMux()
mux.Handle("/", httpapi.NewHandler(svc))
mux.Handle("/mcp", mcpHandler.NewHandler(svc))
```

Both adapters share the same mux and listen address. No new ports or
processes.

## Testing

- **Unit tests**: Use mcp-go's in-process client (`server.NewTestClient`
  or direct `server.ServeHTTP`) to call tools without a real HTTP server.
  Verify parameter validation, error mapping, and response structure.
- **E2E tests**: HTTP POST to `/mcp` with JSON-RPC payloads. Harness gets
  an `MCPCall` helper that sends a `tools/call` request and returns the
  parsed result.
