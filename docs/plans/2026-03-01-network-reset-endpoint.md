# Network Reset Endpoint

## Context

When the CNI subnet config changes (e.g., 10.88.0.0/16 → 172.16.0.0/12), the
existing `nexus0` bridge retains its old IP. The bridge plugin refuses to
reconfigure it, requiring manual `sudo ip link delete nexus0`. The daemon needs
an endpoint to handle this cleanup itself.

## Design Decisions

- **Refuse if VMs exist** (409 Conflict) — deleting the bridge while VMs have
  active veth pairs silently breaks their networking. Operator should delete VMs
  first, then reset. Simple and safe.
- **Dedicated `delete-bridge` subcommand** on nexus-cni-exec, not generic
  exec-with-caps. Keeps the attack surface minimal — can only delete a named
  interface, not run arbitrary commands with elevated caps.
- **Idempotent** — if bridge doesn't exist, treat as success.
- **Track bridge name and paths in Network struct** — avoids re-parsing config.

## Implementation

### 1. `cmd/nexus-cni-exec/main.go` — Add `delete-bridge` subcommand

When invoked as `nexus-cni-exec` (not via symlink), dispatch subcommands:

```
nexus-cni-exec delete-bridge nexus0
```

- Validate interface name (alphanumeric + hyphen/underscore, max 15 chars)
- Raise only CAP_NET_ADMIN (not SYS_ADMIN — not needed for link delete)
- `exec.LookPath("ip")` then `unix.Exec` to `ip link delete <name>`
- Existing symlink-based CNI plugin behavior is unchanged

### 2. `internal/domain/ports.go` — Extend Network interface

```go
type Network interface {
    Setup(ctx context.Context, id string) (*NetworkInfo, error)
    Teardown(ctx context.Context, id string) error
    ResetNetwork(ctx context.Context) error
}

var ErrNetworkInUse = errors.New("network in use")
```

### 3. `internal/infra/cni/noop.go` — Satisfy interface

Add no-op `ResetNetwork` method.

### 4. `internal/infra/cni/network.go` — Implement ResetNetwork

Add fields to Network struct: `bridgeName`, `cniExecBin`, `ipamDataDir`, `cacheDir`.
Populate in `New()`.

`ResetNetwork` does:
1. `exec.CommandContext(ctx, n.cniExecBin, "delete-bridge", n.bridgeName)`
2. If exit code != 0 but output contains "Cannot find device" → success (idempotent)
3. Clear `.ipam` dir contents
4. Clear `.cache` dir contents

### 5. `internal/app/vm_service.go` — Orchestration

```go
func (s *VMService) ResetNetwork(ctx context.Context) error {
    vms, _ := s.store.List(ctx, domain.VMFilter{})
    if len(vms) > 0 {
        return fmt.Errorf("%d VM(s) exist, delete them first: %w", len(vms), domain.ErrNetworkInUse)
    }
    return s.network.ResetNetwork(ctx)
}
```

### 6. `internal/infra/httpapi/handler.go` — HTTP endpoint

- Route: `POST /v1/network/reset`
- Success: 200 `{"status": "ok"}`
- VMs exist: 409 with error message including VM count
- Add `ErrNetworkInUse` case to `mapError`

## Files Modified

- `cmd/nexus-cni-exec/main.go` — `delete-bridge` subcommand + interface name validation
- `internal/domain/ports.go` — `ResetNetwork` on interface, `ErrNetworkInUse`
- `internal/infra/cni/noop.go` — no-op `ResetNetwork`
- `internal/infra/cni/network.go` — new struct fields, `ResetNetwork` impl, `clearDir` helper
- `internal/app/vm_service.go` — `ResetNetwork` with VM check
- `internal/infra/httpapi/handler.go` — route + handler + error mapping

## Verification

1. `go build ./...` and `go test ./...`
2. Build, setcap, start daemon
3. `POST /v1/network/reset` — should succeed (no VMs, deletes stale bridge)
4. Create a VM — should get 172.16.x.x IP on fresh bridge
5. `POST /v1/network/reset` while VM exists — should get 409
6. Delete VM, then reset again — should succeed
7. Reset when bridge already gone — should succeed (idempotent)
