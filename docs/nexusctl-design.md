# nexusctl Design

Approved design for feature #9 from `docs/remaining-features.md`.

## Summary

Separate CLI binary (`cmd/nexusctl/`) for remote interaction with a running
Nexus daemon. Talks exclusively over HTTP/WebSocket — never touches the
filesystem directly. A public `client/` package provides the typed Go HTTP
client that nexusctl, E2E tests, and external consumers (Sharkfin, cloud
provisioner) all import.

The `nexus` binary keeps `daemon`, `export`, and `import` commands.
`nexus export/import` operates on the filesystem directly and works with
or without the daemon running. `nexusctl export/import` operates over the
API and requires a running daemon.

## Architecture

Two binaries, one module:

- **`nexus`** — server-side. `nexus daemon` runs the server.
  `nexus export` / `nexus import` operate on btrfs snapshots and sqlite
  directly, with or without the daemon.
- **`nexusctl`** — remote client. Connects to a running daemon via
  HTTP/WebSocket. All API operations, TTY access, MCP bridge.
- **`client/`** — public Go client library. Zero dependency on daemon
  internals. Defines its own param/response types.

## Command Tree

```
nexusctl
├── vm list [--role=<role>] [--json]
├── vm get <id>
├── vm create <name> --role=<role> [--image=...] [--root-size=...] [--restart-policy=...]
├── vm delete <id>
├── vm start <id>
├── vm stop <id>
├── vm export <id> [--include-devices] -o <file>
├── vm import <file> [--strict-devices]
├── exec <vm> [--stream] -- <cmd...>
├── drive list / get / create / delete / attach / detach
├── device list / get / create / delete / attach / detach
├── console <vm> [--cmd=<shell>]
├── network reset
├── mcp-bridge
└── version
```

## Client Package

`client/` is a typed Go HTTP client mirroring the REST API:

```go
c, err := client.New("http://127.0.0.1:9600")
vm, err := c.CreateVM(ctx, client.CreateVMParams{...})
vms, err := c.ListVMs(ctx, client.ListVMsFilter{...})
vm, err := c.GetVM(ctx, "my-vm")
err = c.StartVM(ctx, "my-vm")
result, err := c.ExecVM(ctx, "my-vm", []string{"ls"})
err = c.ExportVM(ctx, "my-vm", includeDevices, outputWriter)
importResult, err := c.ImportVM(ctx, archiveReader, strictDevices)
conn, err := c.Console(ctx, "my-vm", client.ConsoleOpts{...})
```

- Param/response types defined in `client/`, not imported from `internal/`.
- Export writes to `io.Writer`, import reads from `io.Reader` — CLI handles
  file I/O.
- `Console()` returns a `*websocket.Conn`. nexusctl wraps it with terminal
  raw mode and resize handling.
- Typed errors: `client.ErrNotFound`, `client.ErrConflict`, etc., mapped
  from HTTP status codes.

## Console

`nexusctl console <vm>` provides interactive terminal access via WebSocket:

- Puts local terminal into raw mode (`golang.org/x/term`)
- Sends keystrokes as WebSocket text frames
- Receives stdout as binary frames, writes to local terminal
- Detects `SIGWINCH`, sends JSON resize frames
- `~.` escape sequence disconnects (like SSH)
- On process exit, restores terminal and exits with the VM process's
  exit code

## MCP Bridge

`nexusctl mcp-bridge` is a transparent stdio-to-HTTP proxy:

- Reads newline-delimited JSON-RPC from stdin
- POSTs each message to `/mcp` on the daemon
- Writes HTTP response body to stdout
- Runs until stdin EOF
- Stateless — no session management, no message parsing

Used by agent VMs so Claude Code can access Nexus tools via the MCP
protocol.

## Output Formatting

- Table by default using `text/tabwriter` (stdlib)
- `--json` flag outputs raw API response
- Each command defines its own table columns

## Configuration

Viper precedence:

1. `--addr` flag
2. `NEXUS_ADDR` environment variable
3. `~/.config/nexus/nexusctl.toml`
4. Default: `http://127.0.0.1:9600`

## Testing

- **Client package**: Unit tests with `net/http/httptest` mock server.
  Verify request construction and response parsing.
- **CLI layer**: No dedicated tests — thin enough that client tests
  provide sufficient coverage.
- **Future**: E2E harness can migrate to import `client/` instead of
  hand-rolled HTTP helpers.
