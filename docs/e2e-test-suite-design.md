# E2E Test Suite Design

Approved design for feature #3 from `docs/remaining-features.md`.

## Summary

Full-stack E2E test suite following Sharkfin's subprocess harness pattern. Tests
the compiled binary end-to-end against real containerd, Kata/runc, CNI, and btrfs.
Separate Go module in `tests/e2e/` with no internal imports.

## Structure

```
tests/e2e/
  go.mod          # github.com/Work-Fort/nexus-e2e
  go.sum
  harness/
    harness.go    # Daemon, Client, FreePort, RandomNamespace
  nexus_test.go   # TestMain + all tests
```

## TestMain

Builds all Nexus binaries to a temp dir with `-race`:
- `nexus` (daemon)
- `nexus-netns`, `nexus-cni-exec`, `nexus-quota`, `nexus-dns` (helpers)

Sets package-level `nexusBin` and `binDir` vars. Cleans up on exit.

```go
func TestMain(m *testing.M) {
    tmpDir := buildBinaries()
    defer os.RemoveAll(tmpDir)
    nexusBin = filepath.Join(tmpDir, "nexus")
    binDir = tmpDir
    os.Exit(m.Run())
}
```

Build target is `../..` (project root) and each `./cmd/nexus-*` helper.

## Harness: Daemon

`StartDaemon(binary, addr string, opts ...DaemonOption) (*Daemon, error)`

Per-test isolation:
- Temp XDG dirs (`XDG_CONFIG_HOME`, `XDG_STATE_HOME`)
- Random containerd namespace (`nexus-e2e-<8hex>`)
- Free TCP port
- Helper binaries on PATH via env

Default daemon flags:
```
nexus daemon \
  --listen <addr> \
  --namespace <random-ns> \
  --log-level disabled \
  --network-enabled=false \
  --dns-enabled=false
```

Options:
- `WithNetworkEnabled(bool)` — enable CNI networking
- `WithDNSEnabled(bool)` — enable CoreDNS
- `WithRuntime(string)` — override container runtime
- `WithDrivesDir(string)` — override drives directory

`StopFatal(t)`:
1. Sends SIGTERM, waits 5s for exit
2. Checks stderr for `DATA RACE`, fails test if found
3. Cleans up containerd namespace (kill tasks, delete containers)
4. Removes temp XDG dirs

## Harness: Client

Thin HTTP client wrapping the REST API. No internal imports.

**VM operations:**
- `CreateVM(name, role string, opts ...VMOption) (*VM, error)`
- `GetVM(id string) (*VM, error)`
- `ListVMs() ([]*VM, error)`
- `DeleteVM(id string) error`
- `StartVM(id string) error`
- `StopVM(id string) error`
- `ExecVM(id string, cmd []string) (*ExecResult, error)`

**Drive operations:**
- `CreateDrive(name, size string) (*Drive, error)`
- `ListDrives() ([]*Drive, error)`
- `DeleteDrive(id string) error`
- `AttachDrive(id, vmID, mountpoint string) error`
- `DetachDrive(id string) error`

**Device operations:**
- `CreateDevice(name, hostPath string) (*Device, error)`
- `ListDevices() ([]*Device, error)`
- `DeleteDevice(id string) error`
- `AttachDevice(id, vmID string) error`
- `DetachDevice(id string) error`

**Raw access:**
- `RawRequest(method, path string, body io.Reader) (*http.Response, error)`

## Test Matrix

Tests run sequentially (`-parallel 1`). Each test starts its own daemon.

### VM Lifecycle (6 tests)

| Test | Description |
|------|-------------|
| `TestCreateVM` | Create VM, verify ID returned, verify in list |
| `TestStartStopVM` | Create, start (status=running), stop (status=stopped) |
| `TestExecVM` | Create, start, exec `uname -r`, verify guest kernel output |
| `TestDeleteVM` | Create, delete, verify gone from list |
| `TestDeleteRunningVM` | Delete running VM should fail (must stop first) |
| `TestCreateDuplicateName` | Second VM with same name should fail |

### Drives (5 tests)

| Test | Description |
|------|-------------|
| `TestCreateDrive` | Create drive with size, verify in list |
| `TestAttachDetachDrive` | Attach to VM, verify, detach, verify |
| `TestDeleteAttachedDrive` | Delete while attached should fail |
| `TestDriveInVM` | Attach, start, exec `mount` to verify visible inside VM |
| `TestDeleteDrive` | Create, delete, verify gone |

### Devices (4 tests)

| Test | Description |
|------|-------------|
| `TestCreateDevice` | Create device, verify in list |
| `TestAttachDetachDevice` | Attach to VM, verify, detach |
| `TestDeleteAttachedDevice` | Delete while attached should fail |
| `TestDeleteDevice` | Create, delete, verify gone |

### Error Cases (4 tests)

| Test | Description |
|------|-------------|
| `TestGetNonexistentVM` | 404 response |
| `TestStartAlreadyRunningVM` | Idempotent or error (verify current behavior) |
| `TestStopAlreadyStopped` | Idempotent or error (verify current behavior) |
| `TestInvalidCreatePayload` | Missing fields, validation errors |

### Signal Handling (1 test)

| Test | Description |
|------|-------------|
| `TestGracefulShutdown` | Start daemon, create VM, send SIGTERM, verify clean exit |

## Mise Integration

```toml
[tasks.e2e]
description = "Run E2E tests (requires root, containerd, btrfs)"
depends = ["build"]
run = "cd tests/e2e && sudo go test -v -count=1 -parallel 1 -timeout 10m ."
```

`-count=1` disables test caching (external state). `-timeout 10m` for VM ops.

## Namespace Cleanup

`StopFatal` does best-effort cleanup of the per-test namespace. For manual
cleanup of leaked namespaces after crashes:

```bash
for ns in $(sudo ctr namespaces list -q | grep ^nexus-e2e-); do
  sudo ctr -n "$ns" tasks kill -a 2>/dev/null
  sudo ctr -n "$ns" containers delete $(sudo ctr -n "$ns" containers list -q) 2>/dev/null
  sudo ctr namespaces remove "$ns" 2>/dev/null
done
```

A `mise e2e:clean` task wraps this.

## Prerequisites

- Root access (containerd, CNI, btrfs operations)
- containerd running with Kata or runc runtime available
- btrfs filesystem for drives/snapshots
- OCI image pulled (agent image from Nexus config)
- CNI plugins installed (for network-enabled tests)
