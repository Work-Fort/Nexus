# E2E Test Guide

Operational guide for running and writing Nexus end-to-end tests.

## Prerequisites

- **containerd** running (socket at `/run/containerd/containerd.sock`)
- **btrfs filesystem** for snapshot and drive tests
- **dev-setcap-loop** running in a separate terminal for helper capabilities
- **OCI images** pulled (alpine:latest and nginx:alpine are used by tests)

No sudo is needed to run tests. Privileged operations are delegated to helper
binaries that receive capabilities from `dev-setcap-loop`.

## Building and Running

```bash
# Build all binaries (also downloads node_exporter to build/)
mise run build

# Start dev-setcap-loop in a separate terminal
sudo ./scripts/dev-setcap-loop.sh

# Run the full E2E suite
mise run e2e

# Run specific tests
cd tests/e2e && go test -v -count=1 -parallel 1 -timeout 10m -run TestConsole .

# Clean up leaked containerd namespaces after crashes
mise run e2e:clean
```

The `mise run build` task runs `build:deps` first, which downloads `node_exporter`
to `build/`. The E2E tests use `build/node_exporter` for metrics tests and
`build/nexus-netns` / `build/nexus-cni-exec` for networking tests (these need
capabilities set by dev-setcap-loop).

## Test Files

| File | Tests | Description |
|------|-------|-------------|
| `nexus_test.go` | VM lifecycle, exec, drives, devices, console, MCP, error cases | Core functionality |
| `restart_test.go` | Restart policies, crash recovery, daemon kill -9 | Auto-start and recovery |
| `snapshot_test.go` | Create, delete, clone, restore, cascade delete | Btrfs snapshots |
| `backup_test.go` | Export/import with drives, cross-daemon, name conflicts | VM backup/restore |
| `metrics_test.go` | Prometheus service discovery targets | VM observability |

## Architecture

### TestMain

`TestMain` in `nexus_test.go` builds all Nexus binaries (with `-race`) to a
temp directory before any tests run. Package-level vars `nexusBin` and `binDir`
point to the compiled binary and helper directory.

### Per-Test Isolation

Each test starts its own daemon instance with:
- A random containerd namespace (`nexus-e2e-<8hex>`)
- Temp XDG directories for config and state
- A free TCP port

Tests run sequentially (`-parallel 1`) to avoid resource contention with
containerd.

### Cleanup

`t.Cleanup` calls `d.StopFatal(t)` which:
1. Sends SIGTERM, waits 5s for exit
2. Checks daemon stderr for `DATA RACE` and fails the test if found
3. Kills remaining containerd tasks and deletes containers in the test namespace
4. Removes the temp XDG directories

## Image Selection: alpine vs nginx:alpine

**This is the most common source of E2E test failures.**

The default VM image is `alpine:latest`. When started with containerd's NullIO
(no attached stdin), alpine's `/bin/sh` exits immediately. The VM transitions
from `running` to `stopped` before the test can interact with it.

**Rule: Any test that needs the VM to stay running must use `nginx:alpine`.**

nginx:alpine has a long-running master process that keeps the container alive
regardless of stdin attachment.

```go
// WRONG — container exits immediately, exec/console will fail with "invalid state transition"
vm, err := c.CreateVM("my-test", "agent")

// CORRECT — nginx master process keeps container alive
vm, err := c.CreateVMWithImage("my-test", "agent", "docker.io/library/nginx:alpine")
```

### When to use which image

| Use Case | Image | Why |
|----------|-------|-----|
| Create, list, delete (no start) | Default (alpine) | VM is never started |
| Start/stop lifecycle | `nginx:alpine` | Need VM to stay in running state |
| Exec commands | `nginx:alpine` | Need running container for exec |
| Console sessions | `nginx:alpine` | Need running container for console |
| Drive/device attach/detach (no start) | Default (alpine) | VM is never started |
| Drive verification inside VM | `nginx:alpine` | Need to exec `mount` inside VM |
| Export/import | `nginx:alpine` | Need running VM to write marker files |
| Snapshot create/delete (no start) | Default (alpine) | Snapshots work on stopped VMs |
| MCP lifecycle with exec | `nginx:alpine` | Need running container for vm_exec |

## Networking

By default, the test harness starts daemons with `--network-enabled=false` and
`--dns-enabled=false`. Most tests don't need networking.

Tests that need VM IP addresses (e.g., Prometheus targets) use the
`startNetworkedDaemon` helper in `metrics_test.go`:

```go
func startNetworkedDaemon(t *testing.T, extraOpts ...harness.DaemonOption) (*harness.Daemon, *harness.Client) {
    requireNetworking(t)  // skips if build/ helpers are missing

    netnsHelper, _ := filepath.Abs("../../build/nexus-netns")
    cniExecBin, _ := filepath.Abs("../../build/nexus-cni-exec")

    opts := []harness.DaemonOption{
        harness.WithNetworkEnabled(true),
        harness.WithNetNSHelper(netnsHelper),
        harness.WithCNIExecBin(cniExecBin),
    }
    // ...
}
```

This points at the `build/` copies of network helpers which have capabilities
set by dev-setcap-loop. The freshly-compiled copies in the temp test directory
don't have capabilities, so they can't create network namespaces.

**Enable networking only where needed.** Don't add it to every test — it slows
them down and adds failure modes.

## Btrfs Tests

Snapshot and backup tests require a btrfs filesystem. They use `requireBtrfs(t)`
which skips the test if the working directory isn't on btrfs.

The `startBtrfsDaemon` helper in `snapshot_test.go`:
- Sets `WithBaseDir(".")` to place temp dirs on the btrfs filesystem
- Uses `WithSnapshotter("btrfs")` for containerd's btrfs snapshotter
- Points at `build/nexus-btrfs` for the helper with `CAP_SYS_ADMIN`
- Handles btrfs subvolume cleanup in `t.Cleanup`

## Harness Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `WithNetworkEnabled(bool)` | `false` | Enable CNI networking |
| `WithDNSEnabled(bool)` | `false` | Enable CoreDNS |
| `WithRuntime(string)` | daemon default | Container runtime handler |
| `WithDrivesDir(string)` | auto | Override drives directory |
| `WithSnapshotter(string)` | `""` (overlayfs) | Containerd snapshotter |
| `WithBaseDir(string)` | system temp | Base for XDG temp dirs |
| `WithLogLevel(string)` | `"disabled"` | Daemon log level |
| `WithQuotaHelper(string)` | daemon default | Path to nexus-quota helper |
| `WithBtrfsHelper(string)` | daemon default | Path to nexus-btrfs helper |
| `WithNetNSHelper(string)` | daemon default | Path to nexus-netns helper |
| `WithCNIExecBin(string)` | daemon default | Path to nexus-cni-exec helper |
| `WithNodeExporterPath(string)` | daemon default | Path to node_exporter binary |

## Daemon Lifecycle Helpers

The harness provides three ways to stop a daemon, used for different test
scenarios:

| Method | Behavior | Use Case |
|--------|----------|----------|
| `StopFatal(t)` | SIGTERM + cleanup namespace + remove XDG dirs | Normal test teardown |
| `GracefulStop()` | SIGTERM only, no cleanup | Test restart across daemon restarts |
| `Kill()` | SIGKILL, no cleanup | Simulate daemon crash |

`GracefulStop` and `Kill` preserve the containerd namespace and XDG dirs so a
new daemon can be started with `StartDaemonWithNamespace` to resume from the
same state.

## Writing New Tests

1. **Start with `startDaemon(t)`** for basic tests. Add options only as needed.

2. **Use `nginx:alpine` if the test starts a VM and interacts with it** (exec,
   console, stream, metrics). Use the default image if the VM is never started
   or only needs to exist in created/stopped state.

3. **Use `startNetworkedDaemon`** only if the test needs VM IP addresses.

4. **Use `startBtrfsDaemon`** for snapshot/drive/backup tests that need btrfs.

5. **Add `requireBtrfs(t)` or `requireNetworking(t)`** at the top of tests
   that depend on infrastructure that may not be available, so they skip
   gracefully.

6. **Each test should start its own daemon.** Don't share daemons between
   tests — isolation prevents flaky failures from shared state.

## Troubleshooting

### "websocket: bad handshake" in console tests
The VM exited before the console could connect. The handler calls
`ExecConsoleVM` before upgrading to WebSocket — if the VM isn't running, it
returns an HTTP 400 error which the WebSocket client sees as "bad handshake".
**Fix: use `nginx:alpine`.**

### "invalid state transition" on exec/console
Same root cause as above. The VM used default alpine, which exited immediately.
By the time exec is attempted, the VM is in `stopped` state. **Fix: use
`nginx:alpine`.**

### Tests skip with "build/nexus-netns not found"
Run `mise run build` to compile helper binaries, then start dev-setcap-loop
to grant them capabilities.

### Leaked containerd namespaces
After crashes or interrupted test runs, namespaces like `nexus-e2e-a1b2c3d4`
may remain in containerd. Run `mise run e2e:clean` to remove them.

### Tests fail with "btrfs" errors
Ensure the working directory is on a btrfs filesystem. Snapshot and backup
tests will skip automatically if it isn't — they use `requireBtrfs(t)`.
