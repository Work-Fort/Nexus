# Health Service Design

Global health service that tracks the status of system components, runs
checks periodically in the background, and provides degraded service when
subsystems are unavailable.

## Architecture

The health service is a domain-level component in `internal/app/` that
maintains a registry of health checks. Each check runs independently on
its own interval in a background goroutine, caching the latest result.
Consumers (VM creation, `/health` endpoint) read the cached state — they
never trigger checks themselves.

```
HealthService (background goroutines)
│
│  periodic (per-check interval):
│    ├── "kata-kernel"  (every 30s) → cache result
│    ├── "containerd"   (every 15s) → cache result
│    └── "disk-space"   (every 60s) → cache result
│
│  on startup:
│    └── run all checks once, log results
│
├── Status()                       → aggregate cached state
├── RuntimeHealthy(runtime string) → bool (VM creation gating)
└── GET /health                    → reads cached state
```

Results are stored behind a `sync.RWMutex`-protected map. Reads are fast;
writes happen only when a background check completes.

## Health Status Levels

Each check reports one of three statuses:

| Status   | Meaning                                        |
|----------|------------------------------------------------|
| healthy  | Component is fully operational                 |
| degraded | Component partially unavailable, service usable|
| unhealthy| Critical failure, service cannot function       |

Aggregate status follows worst-case: any `unhealthy` → aggregate unhealthy,
any `degraded` → aggregate degraded, otherwise healthy.

## HTTP Endpoint

`GET /health` returns JSON with per-check status:

```json
{
  "status": "degraded",
  "checks": {
    "containerd": {"status": "healthy", "message": "connected"},
    "kata-kernel": {"status": "degraded", "message": "kernel not found at /usr/share/nexus/vmlinux"},
    "disk-space": {"status": "healthy", "message": "12.4 GB free"}
  }
}
```

HTTP status codes:

- **200** — all checks healthy
- **218** — at least one check degraded, no checks unhealthy
- **503** — at least one check unhealthy (critical failure)

## Initial Health Checks

### Kata Kernel

Validates that Kata is configured to use the Anvil kernel.

- Parse `/etc/kata-containers/configuration.toml`, fall back to
  `/opt/kata/share/defaults/kata-containers/configuration.toml`
- Extract `kernel` value from `[hypervisor.qemu]` or `[hypervisor.firecracker]`
- Verify the file exists at that path
- Verify the filename contains the expected Anvil version (compiled into
  the binary, initially `6.19.6`)
- Healthy → Anvil kernel configured and file exists
- Degraded → wrong kernel or missing file (Kata/Firecracker VMs blocked,
  runc still works)

### Containerd

Verifies containerd is reachable and responsive.

- Ping the containerd socket (lightweight `Version()` call)
- Healthy → reachable
- Unhealthy → unreachable (nothing works, 503)

### Disk Space

Checks available disk space on state and drives directories.

- `syscall.Statfs` on the state directory and drives directory
- Reports the lower of the two
- Healthy → sufficient free space
- Degraded → below warning threshold (e.g. 100 MB free)
- Unhealthy → critically low (e.g. 10 MB free)

## VM Creation Gating

`VMService.CreateVM` consults the health service before proceeding:

- Calls `health.RuntimeHealthy("io.containerd.kata.v2")`
- If the Kata kernel check is degraded, Kata and Firecracker runtime
  requests return **503** with message:
  `"runtime io.containerd.kata.v2 unavailable: Anvil kernel not configured (expected version 6.19.6)"`
- runc creation proceeds normally regardless of Kata health
- If containerd is unhealthy, all VM creation fails with 503

## Health Check Interface

```go
type HealthCheck interface {
    Name() string
    Interval() time.Duration
    Check(ctx context.Context) CheckResult
}

type CheckResult struct {
    Status  HealthStatus // healthy, degraded, unhealthy
    Message string
}
```

New checks are registered with the health service at daemon startup.
Each backend (containerd, future Firecracker-direct) registers its own
relevant checks.

## Configuration

- `--kata-kernel-version` flag (default: compiled-in `6.19.6`) — the
  expected Anvil kernel version for the health check
- Kata config paths are well-known — no flag needed

## AUR Package Changes

- Add Anvil kernel as a `source` entry (GitHub release asset from
  `Work-Fort/Anvil`, version 6.19.6, placeholder checksum)
- Install kernel binary to `/usr/share/nexus/vmlinux`
- Install `/etc/kata-containers/configuration.toml` — copy of Kata's
  default QEMU config with `kernel = "/usr/share/nexus/vmlinux"`
- Mark the config as a backup file so pacman preserves user modifications

## Future Extensibility

- New runtime backends (e.g. Firecracker-direct for serverless) register
  their own health checks via the same `HealthCheck` interface
- The health service is runtime-agnostic — it doesn't know what the checks
  do, only their name, interval, and result
- Additional checks (network health, DNS, kernel modules) can be added
  without changing the health service itself
