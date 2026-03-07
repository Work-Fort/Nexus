# Remaining Features

Tracking document for features needed before Nexus is called by other services
(Sharkfin, Combine, cloud provisioner).

## 1. Webhook Cleanup ✅

[Plan](plans/2026-03-02-webhook-cleanup.md)

Remove Sharkfin-specific code (`SharkfinWebhook`, `HandleWebhook`,
`POST /webhooks/sharkfin`). Nexus doesn't know or care who's calling — it offers
interaction patterns:

- **Fire-and-forget** — "ensure this VM is running" (idempotent start)
- **Synchronous CRUD** — create, start, stop, delete VMs/drives/devices
- **Lifecycle with callback** — create VM, run something, notify caller when done

Sharkfin, Combine, and the cloud provisioner are all regular API clients.
Produce API documentation for the Sharkfin team lead.

## 2. VM Root Size ✅

[Design](vm-root-size-design.md) · [Plan](plans/2026-03-02-vm-root-size.md)

VM creation needs a `size` argument for root filesystem size. May already be
implemented — needs verification and test coverage.

## 3. E2E Test Suite ✅

[Design](e2e-test-suite-design.md) · [Plan](plans/2026-03-02-e2e-test-suite.md)

Separate binary following Sharkfin's test harness pattern:

- Separate Go module in `tests/e2e/` with own `go.mod`
- `TestMain` builds the binary once with `-race`
- Harness library manages daemon lifecycle, XDG isolation, cleanup
- `StopFatal` checks race detector output
- Temp XDG dirs per test — never touches production state
- HTTP client wrapping the REST API
- `mise.toml` `e2e` task depends on `build`

## 4. Backup/Restore ✅

[Design](backup-restore-design.md) · [Plan](plans/2026-03-02-backup-restore.md)

Self-contained portable export package:

- VM config (name, role, image, DNS config) + drive data (btrfs snapshots)
- Devices optional in export (off by default)
- On import: if devices included but host nodes don't exist, warn by default,
  error only if caller explicitly requested device restoration
- Import recreates everything to a startable state
- VM must be stopped for consistent snapshot
- Designed for cloud provisioner use case (upload to another Nexus instance)

## 5. Auto-Start on Boot ✅

[Design](auto-start-design.md) · [Plan](plans/2026-03-03-auto-start.md)

- On daemon startup, restore previously-running VMs to running state
- Optional "always run" flag — Nexus ensures the VM is running (restart on
  crash, start on boot)

## 6. Basic Exec Streaming ✅

[Design](exec-streaming-design.md) · [Plan](plans/2026-03-03-exec-streaming.md)

Simple command output from a running VM. Debug/convenience — not a full CI
pipeline. Combine uses an in-VM agent for CI orchestration; Nexus doesn't need
to be in that data path.

## 7. Terminal Access ✅

[Design](terminal-access-design.md) · [Plan](plans/2026-03-03-terminal-access.md)

TTY/console access per VM. Must survive Nexus restarts. Research needed:
Kata/containerd shim may already hold the TTY FDs independently of the client
process, making this straightforward.

## 8. MCP Endpoint ✅

[Design](mcp-endpoint-design.md) · [Plan](plans/2026-03-03-mcp-endpoint.md)

HTTP streaming MCP server exposing REST-equivalent functions:

- VM lifecycle (create, start, stop, delete)
- Drive CRUD + attach/detach
- Device CRUD + attach/detach
- Exec, terminal access

## 9. nexusctl ✅

[Design](nexusctl-design.md) · [Plan](plans/2026-03-05-nexusctl.md)

Command-line utility for interacting with Nexus instances:

- REST/WebSocket client for all API operations
- VM TTY access (depends on terminal access research)
- stdio-to-HTTP MCP bridge (same pattern as Sharkfin's `mcp-bridge`)

## 10. VM Tags

[Design](vm-tags-design.md) · [Plan](plans/2026-03-06-vm-tags.md)

Add tagging support for VMs (was present in the Rust version, missed in the Go
port). Tags replace the `role` field as the way to organize and categorize VMs
(e.g. `agent`, `ci-runner`, `dev`). Once tags exist, `role` becomes redundant.

## 11. Shell Sync from VM Rootfs

[Design](shell-sync-design.md) · [Plan](plans/2026-03-06-shell-sync.md)

Add an endpoint/operation to sync the system-set default shell from the VM
rootfs (e.g. probe `/etc/shells` or `/etc/passwd`) into the VM's `shell` field
in the DB.

## 12. VM Observability

[Design](vm-observability-design.md) · [Plan](plans/2026-03-06-vm-observability.md)

Nexus needs to observe in-VM events (e.g. disk quota `ENOSPC`, resource
pressure) and notify callers. Two angles: outbound webhooks so Nexus can push
lifecycle/resource events to callers, and a Prometheus/k8s observability stack
inside VMs for metrics collection. Came up during VM root size design — callers
need to know when a VM hits its quota so they can expand or take action.

---

## Investigate

Things to look into — not yet committed features.

- **Noop pattern for optional subsystems** — `VMService` nil-checks `driveStore`,
  `deviceStore`, and `dns` throughout its methods. The noop adapter pattern
  already exists for some infra packages (`dns/noop.go`, `storage/noop.go`).
  Investigated: only ~11 of 23 nil-checks can be eliminated by noops. The 7
  "gate" checks (`== nil` returning `ErrValidation`) must stay regardless. Not
  worth the added abstraction. One small win: wire `dns.NoopManager` by default
  in the constructor to eliminate 5 dns nil-checks with zero new code.

- **Docker/OCI image caching** — Investigate where containerd caches pulled
  images and how to manage cache size, eviction, and pre-warming. Currently
  every `vm_create` with a new image triggers a full pull.
