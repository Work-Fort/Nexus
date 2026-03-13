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

## 10. VM Tags ✅

[Design](vm-tags-design.md) · [Plan](plans/2026-03-06-vm-tags.md)

Add tagging support for VMs (was present in the Rust version, missed in the Go
port). Tags replace the `role` field as the way to organize and categorize VMs
(e.g. `agent`, `ci-runner`, `dev`). Once tags exist, `role` becomes redundant.

## 11. Shell Sync from VM Rootfs ✅

[Design](shell-sync-design.md) · [Plan](plans/2026-03-06-shell-sync.md)

Add an endpoint/operation to sync the system-set default shell from the VM
rootfs (e.g. probe `/etc/shells` or `/etc/passwd`) into the VM's `shell` field
in the DB.

## 12. VM Observability ✅

[Design](vm-observability-design.md) · [Plan](plans/2026-03-06-vm-observability.md)

Nexus needs to observe in-VM events (e.g. disk quota `ENOSPC`, resource
pressure) and notify callers. Two angles: outbound webhooks so Nexus can push
lifecycle/resource events to callers, and a Prometheus/k8s observability stack
inside VMs for metrics collection. Came up during VM root size design — callers
need to know when a VM hits its quota so they can expand or take action.

## 13. Provisioning Templates ✅

[Design](provisioning-templates-design.md) · [Plan](plans/2026-03-07-provisioning-templates.md)

Reusable shell scripts stored in the database that bootstrap init systems
(OpenRC, systemd) into container images. Templates are a first-class CRUD
resource with full REST and MCP API surface.

- Auto-detect distro from image filesystem (`/etc/os-release`)
- Built-in defaults seeded on first run: Alpine/OpenRC, Ubuntu/systemd, Arch/systemd
- VM creation with `init: true` auto-selects matching template
- Per-VM script override without forking the shared template
- E2E tests with real images (no mocks)

## 14. Live VM Snapshots ✅

[Design](plans/2026-03-07-live-snapshots-design.md) · [Plan](plans/2026-03-07-live-snapshots.md)

Point-in-time btrfs COW snapshots of running VMs (drives + rootfs). Snapshots
are crash-consistent (equivalent to power failure — journaled guest filesystems
recover automatically).

- Snapshot while VM is running — no downtime
- Rollback: stop VM, restore rootfs + drives from snapshot, restart
- Clone: fork a snapshot into a new independent VM with new identity/network
- Live export: no longer requires stopping the VM (temp snapshot under the hood)
- Manual retention only — no automatic expiry or scheduling
- Requires btrfs storage backend; noop backend returns clear error

## 15. Automatic Firewall Forwarding ✅

[Design](firewall-forwarding-design.md) · [Plan](plans/2026-03-07-firewall-forwarding.md)

Automatically manage iptables FORWARD rules so VMs can reach external
services even when a host firewall (UFW, firewalld) is active. CNI's
bridge plugin handles NAT but not FORWARD rules — host firewalls DROP
forwarded traffic by default.

- Extend `nexus-cni-exec` with `setup-forwarding` / `teardown-forwarding`
- Uses `coreos/go-iptables` (works with both legacy iptables and iptables-nft)
- Rules applied on daemon start, removed on shutdown
- Own `NEXUS-FORWARD` chain inserted at top of FORWARD
- Remove obsolete `nexus setup` command (superseded by helper binaries)

## 16. Host DNS Resolution for `.nexus` ✅

[Design](plans/2026-03-07-host-dns-design.md) · [Plan](plans/2026-03-07-host-dns.md)

Resolve `*.nexus` from the host so tools like `curl`, `ping`, and browsers
can reach VMs by name. Split DNS — only `.nexus` queries route to CoreDNS,
all other DNS is unaffected.

**Approach:** CoreDNS dual-binds the `nexus` zone to `127.0.0.100`
(host) and the bridge gateway (VMs). The daemon registers split DNS
routing with systemd-resolved via D-Bus (`godbus/dbus`). Same pattern
as Tailscale, recommended by the systemd VPN documentation.

- Configurable domain list (`--dns-domains`, default `nexus`). `nexus`
  always included. Users can add vanity domains (e.g. `work-fort`)
- Loopback `127.0.0.100` serves configured zones only — catch-all
  forwarder stays on gateway only
- Hosts file generates aliases for all domains: `myvm.nexus myvm.work-fort`
- Daemon calls resolved D-Bus API directly: `SetLinkDNS`,
  `SetLinkDomains(~nexus, ~work-fort, ...)`, `SetLinkDefaultRoute(false)`
- Works on any systemd distro regardless of networkd vs NetworkManager
  (Arch, Ubuntu desktop/server, Fedora)
- Best-effort — failure logs warning, VMs unaffected
- Self-healing on crash: resolved auto-clears when `nexus0` disappears
- Package ships polkit rule for resolved D-Bus authorization
- Subnet-independent: loopback address is fixed, bridge IP can change

## 17. Internal Cleanup ✅

Small code quality improvements discovered during investigation. No new
features — just removing unnecessary work and dead patterns.

**DNS nil-check cleanup:** Done in `8e0611c`. Added `NoopDNSManager` to
`internal/domain/ports.go`, defaulted in `NewVMService` constructor,
removed 9 nil-checks across `vm_service.go`, `snapshot.go`, `backup.go`.
Deleted `internal/infra/dns/noop.go`.

**Avoid double image pull:** Done in `e5af0e9`. Extracted `pullImage`
helper that checks `GetImage` (local) before falling back to `Pull`.
Both `Create` and `DetectDistro` use it — second call is a fast local
lookup instead of a registry round-trip.

## 18. MCP Streaming Exec ✅

[Design](mcp-streaming-exec-design.md) · [Plan](plans/2026-03-08-mcp-streaming-exec.md)

Make `vm_exec` stream output while the command runs. The tool switches
from `ExecVM` to `ExecStreamVM`, sending `run_command.stdout` /
`run_command.stderr` JSON-RPC notifications as chunks arrive. The
mcp-bridge intercepts these notifications and writes chunk text to
stderr, so users see streaming output during execution.

- Notification-sending `io.Writer` wrappers in the MCP handler
- `handleStreamingNotification` in mcp-bridge to intercept and display chunks
- Tool result still returns full buffered output for standard MCP clients

## 19. Health Service ✅

[Design](health-service-design.md)

Global health service that tracks system component status with periodic
background checks. Provides degraded service — if Kata is misconfigured,
block Kata/Firecracker VMs but allow runc.

- `HealthCheck` interface with name, interval, and check method
- Background goroutines per check, cached results behind RWMutex
- `GET /health` endpoint: 200 healthy, 218 degraded, 503 unhealthy
- Initial checks: Kata kernel (Anvil 6.19.6), containerd, disk space
- VM creation gates on runtime health before proceeding
- AUR package ships Anvil kernel and Kata config override

## 20. Network Migration on Restart

When Nexus restarts with network configuration changes (e.g. adding the
loopback CNI plugin), existing VMs retain their old network namespace
configuration. VMs created before the change are stuck without the fix
until manually recreated.

Needed behavior:
- Gracefully shut down running VMs when Nexus stops
- On restart, detect network config changes (CNI plugin list, subnet, etc.)
- Rebuild network namespaces for existing VMs with the new config
- Restart VMs that were running before shutdown

## Notes

- `TestKill9ThenStartNonePolicy` in `tests/e2e/restart_test.go` may be flaky
  under load. Passed 10/10 in isolation but failed once during a full suite run.
  The test calls `StartVM` then immediately `GetVM` expecting `state=running` —
  may need a polling loop. Needs further investigation to confirm.
