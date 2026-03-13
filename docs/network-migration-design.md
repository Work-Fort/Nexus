# Network Migration on Restart

When Nexus restarts with CNI configuration changes (e.g. adding the loopback
plugin, changing the subnet), existing VMs retain their old network namespace
configuration. This design adds startup reconciliation that detects config
drift and rebuilds namespaces automatically.

## Config Fingerprint

The CNI conflist JSON (plugin list, subnet, bridge name, IPAM data dir) is
hashed with SHA-256 during `network.New()`. The hash is written to:

    $XDG_RUNTIME_DIR/nexus/netns/.cni-config-hash

On the next startup, the new config hash is compared against the stored one.
If they match, existing namespaces are reused as-is. If they differ (or the
file is missing, e.g. first run after upgrade), migration is triggered.

Since this directory is on tmpfs, a system reboot clears the hash file. This
is fine — a reboot also clears the namespace bind-mount files, so all VMs
need fresh namespaces regardless.

## Startup Reconciliation

Migration runs inside `RestoreVMs()`, before any VMs are started:

1. Call `network.ConfigChanged()` to compare hashes.
2. If unchanged, skip to normal RestoreVMs logic.
3. If changed, run a 3-phase migration (all teardowns before any setups,
   because the CNI bridge plugin retains the old gateway IP and rejects
   a new subnet's gateway if the bridge interface still exists):
   a. **Phase 1 — Teardown:** For each VM with a `NetNSPath`, record its
      previous IP and call `network.Teardown(ctx, vm.ID)`.
   b. **Phase 2 — Reset:** Call `network.ResetNetwork(ctx)` to delete the
      bridge interface and clear IPAM/cache state.
   c. **Phase 3 — Setup:** For each torn-down VM, call
      `network.Setup(ctx, vm.ID, WithPreferredIP(prevIP))` to create a
      fresh namespace with the current config. Update the VM record with
      new `NetNSPath`, `IP`, `Gateway` via `store.UpdateNetwork()`.
      Update DNS record if DNS is enabled.
   d. Write the new hash to the fingerprint file.
   e. Log summary: "network migration complete, migrated=N, failed=M".
4. Proceed with normal RestoreVMs logic (start VMs per restart policy).

Migration happens before any VMs are started, so there is no window where a
VM is running with a stale namespace.

## Best-Effort IP Reuse

The `host-local` IPAM plugin supports requesting a specific IP via the `ips`
capability. During migration:

- The VM's previous IP is read from the DB before teardown.
- The previous IP is passed via `RuntimeConf.CapabilityArgs["ips"]`.
- The conflist IPAM block must declare `"capabilities": {"ips": true}`.
- If IPAM cannot honor the request (subnet changed, IP conflict), it assigns
  a new one.
- The DB record and DNS are updated with whatever IP was assigned.

By convention, services should use DNS names rather than IPs for addressing.
DNS names remain stable regardless of IP changes.

## Interface Changes

### `domain.Network`

Add `ConfigChanged() bool` to the interface. `NoopNetwork` returns `false`.

### `domain.Network.Setup`

Add functional options to `Setup` to support preferred IP:

    Setup(ctx context.Context, id string, opts ...SetupOpt) (*NetworkInfo, error)

Where `SetupOpt` follows the existing pattern (see `CreateOpt` in ports.go):

    type SetupOpt func(*setupConfig)
    func WithPreferredIP(ip string) SetupOpt

Existing callers pass no options and behave unchanged.

### `domain.VMStore`

Add `UpdateNetwork(ctx context.Context, id, ip, gateway, netnsPath string) error`.
Requires a new SQL query in both SQLite and Postgres stores, and sqlc
regeneration.

## Configuration Toggle

A `network-auto-migrate` option controls whether migration runs automatically:

- **Viper key:** `network-auto-migrate`
- **CLI flag:** `--network-auto-migrate`
- **Env:** `NEXUS_NETWORK_AUTO_MIGRATE`
- **Default:** `true`

When `false`, config drift is detected and logged as a warning, but namespaces
are not rebuilt. Registered in `cmd/daemon.go` alongside existing flags, bound
via `viper.BindPFlag`, and passed to `RestoreVMs()`.

## Shutdown Behavior

No changes to the shutdown path. On graceful shutdown, `Shutdown()` stops
containerd tasks but leaves network namespaces intact. This is correct:

- If config hasn't changed, namespaces are reused on restart (fast recovery).
- If config has changed, `RestoreVMs()` tears down and rebuilds before starting.

The fingerprint file is written during `network.New()`, not during shutdown.

## Error Handling

- **Per-VM errors are non-fatal.** Log the error, continue with remaining VMs.
- **Teardown failure:** Log warning, attempt setup anyway (setup creates a
  fresh namespace at the same path).
- **Setup failure:** Log error, clear the VM's `NetNSPath`/`IP`/`Gateway` in
  the DB. The VM won't have networking but can still be deleted and recreated.
- **Missing fingerprint file:** Treated as "changed" — rebuild all namespaces.
  Safe default for upgrades from versions without this feature.
- **Networking disabled** (`NoopNetwork`): Skip migration entirely.
- **Stale IPAM state:** If teardown's CNI Del fails due to inconsistent IPAM
  data, the IP deallocation may not happen. In this case, best-effort IP reuse
  is unlikely to work and a new IP will be assigned. This is acceptable.

## Files Changed

| Change | Files |
|--------|-------|
| `ConfigChanged() bool` on `Network` interface | `internal/domain/ports.go` |
| `ConfigChanged` stub on `NoopNetwork` | `internal/infra/cni/noop.go` |
| Hash computation and file I/O | `internal/infra/cni/network.go` |
| `SetupOpt` / `WithPreferredIP` | `internal/domain/ports.go`, `internal/infra/cni/network.go`, `noop.go` |
| `ips` capability in conflist JSON | `internal/infra/cni/network.go` |
| `CapabilityArgs` in `Setup` | `internal/infra/cni/network.go` |
| `UpdateNetwork` on `VMStore` | `internal/domain/ports.go` |
| `UpdateVMNetwork` SQL query | `internal/infra/sqlite/queries.sql`, `queries.sql.go` |
| Postgres `UpdateNetwork` | `internal/infra/postgres/store.go` |
| `--network-auto-migrate` flag | `cmd/daemon.go` |
| Migration logic in `RestoreVMs` | `internal/app/restart.go` |

## Testing

### Unit Tests

In `internal/infra/cni/`:

- `TestConfigFingerprint` — hash is deterministic, changes when config changes.
- `TestConfigFingerprintUnchanged` — same config produces same hash,
  `ConfigChanged()` returns false.
- `TestConfigFingerprintMissing` — missing hash file returns "changed".

In `internal/app/`:

- `TestRestoreVMsWithNetworkMigration` — mock network/runtime/store, verify
  teardown + setup called for each VM when config changed.
- `TestRestoreVMsNoMigration` — no teardown when config unchanged.
- `TestRestoreVMsMigrationDisabled` — skip when `network-auto-migrate=false`.

### E2E Tests

In `tests/e2e/`:

- `TestNetworkMigrationOnRestart` — create a VM, stop daemon, change subnet
  config, restart daemon, verify VM gets a new IP in the new subnet and has
  loopback.
- `TestNetworkNoMigrationSameConfig` — create VM, note IP, restart daemon with
  same config, verify same IP is preserved.
