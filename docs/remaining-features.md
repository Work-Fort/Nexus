# Remaining Features

Tracking document for features needed before Nexus is called by other services
(Sharkfin, Combine, cloud provisioner).

## 1. Webhook Cleanup

Remove Sharkfin-specific code (`SharkfinWebhook`, `HandleWebhook`,
`POST /webhooks/sharkfin`). Nexus doesn't know or care who's calling — it offers
interaction patterns:

- **Fire-and-forget** — "ensure this VM is running" (idempotent start)
- **Synchronous CRUD** — create, start, stop, delete VMs/drives/devices
- **Lifecycle with callback** — create VM, run something, notify caller when done

Sharkfin, Combine, and the cloud provisioner are all regular API clients.
Produce API documentation for the Sharkfin team lead.

## 2. VM Root Size

VM creation needs a `size` argument for root filesystem size. May already be
implemented — needs verification and test coverage.

## 3. E2E Test Suite

Separate binary following Sharkfin's test harness pattern:

- Separate Go module in `tests/e2e/` with own `go.mod`
- `TestMain` builds the binary once with `-race`
- Harness library manages daemon lifecycle, XDG isolation, cleanup
- `StopFatal` checks race detector output
- Temp XDG dirs per test — never touches production state
- HTTP client wrapping the REST API
- `mise.toml` `e2e` task depends on `build`

## 4. Backup/Restore

Self-contained portable export package:

- VM config (name, role, image, DNS config) + drive data (btrfs snapshots)
- Devices optional in export (off by default)
- On import: if devices included but host nodes don't exist, warn by default,
  error only if caller explicitly requested device restoration
- Import recreates everything to a startable state
- VM must be stopped for consistent snapshot
- Designed for cloud provisioner use case (upload to another Nexus instance)

## 5. Auto-Start on Boot

- On daemon startup, restore previously-running VMs to running state
- Optional "always run" flag — Nexus ensures the VM is running (restart on
  crash, start on boot)

## 6. Basic Exec Streaming

Simple command output from a running VM. Debug/convenience — not a full CI
pipeline. Combine uses an in-VM agent for CI orchestration; Nexus doesn't need
to be in that data path.

## 7. Terminal Access

TTY/console access per VM. Must survive Nexus restarts. Research needed:
Kata/containerd shim may already hold the TTY FDs independently of the client
process, making this straightforward.

## 8. MCP Endpoint

HTTP streaming MCP server exposing REST-equivalent functions:

- VM lifecycle (create, start, stop, delete)
- Drive CRUD + attach/detach
- Device CRUD + attach/detach
- Exec, terminal access

## 9. nexusctl

Command-line utility for interacting with Nexus instances:

- REST/WebSocket client for all API operations
- VM TTY access (depends on terminal access research)
- stdio-to-HTTP MCP bridge (same pattern as Sharkfin's `mcp-bridge`)

## 10. VM Tags

Add tagging support for VMs (was present in the Rust version, missed in the Go
port). Tags replace the `role` field as the way to organize and categorize VMs
(e.g. `agent`, `ci-runner`, `dev`). Once tags exist, `role` becomes redundant.
