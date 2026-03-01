# Networking Implementation Plan

## Context

Nexus currently creates containers/VMs via containerd but has no networking.
VMs can't talk to each other, to the host, or to the internet. This blocks the
entire WorkFort topology: Portal ↔ Sharkfin ↔ Agent VMs ↔ Nexus ↔ Internet.

**Why manual CNI?** The containerd Go client (which Nexus uses) does NOT handle
CNI automatically — that's only done by the CRI plugin (Kubernetes path). Since
we use the client directly, we must manage network namespaces and CNI ourselves
using the `github.com/containerd/go-cni` library.

## Architecture

New `Network` port in domain layer, CNI adapter in infra, orchestrated by VMService.

```
domain/ports.go        + Network interface (Setup/Teardown)
domain/vm.go           + NetworkInfo field on VM
infra/cni/network.go   CNI adapter (go-cni library)
infra/sqlite/          Migration 002 for network columns
app/vm_service.go      Orchestrate: netns → CNI setup → container create → store
cmd/daemon.go          Wire CNI adapter, add config flags
```

## Step 1: Domain Layer

**`internal/domain/ports.go`** — Add Network port:

```go
type NetworkInfo struct {
    IP        string
    Gateway   string
    NetNSPath string
}

type Network interface {
    Setup(ctx context.Context, id string) (*NetworkInfo, error)
    Teardown(ctx context.Context, id string) error
}
```

**`internal/domain/vm.go`** — Add optional NetworkInfo to VM struct and CreateVMParams:

```go
// In VM struct:
IP        string
Gateway   string
NetNSPath string
```

## Step 2: Runtime.Create — Accept Network Namespace

**`internal/domain/ports.go`** — Add functional option to Runtime.Create:

```go
type CreateOpt func(*CreateConfig)
type CreateConfig struct{ NetNSPath string }

// Runtime.Create signature becomes:
Create(ctx context.Context, id, image, runtimeHandler string, opts ...CreateOpt) error
```

**`internal/infra/containerd/runtime.go`** — Apply netns via `oci.WithLinuxNamespace`:

```go
if cfg.NetNSPath != "" {
    specOpts = append(specOpts, oci.WithLinuxNamespace(specs.LinuxNamespace{
        Type: specs.NetworkNamespace,
        Path: cfg.NetNSPath,
    }))
}
```

## Step 3: CNI Adapter

**`internal/infra/cni/network.go`** — Implements domain.Network:

1. Create network namespace: `unix.Unshare(CLONE_NEWNET)` + bind mount to `/var/run/netns/<id>`
2. Call `cniNetwork.Setup(ctx, id, netnsPath)` — go-cni invokes the bridge plugin
3. Extract IP/gateway from the CNI result
4. Teardown: `cniNetwork.Remove(ctx, id, netnsPath)` then unmount + delete netns file

**CNI config** (bridge plugin, written by Nexus at startup):

```json
{
  "cniVersion": "1.0.0",
  "name": "nexus",
  "type": "bridge",
  "bridge": "nexus0",
  "isGateway": true,
  "ipMasq": true,
  "ipam": { "type": "host-local", "subnet": "10.88.0.0/16" }
}
```

**NoopNetwork** for testing (returns zero-value NetworkInfo, does nothing on teardown).

## Step 4: Database Migration

**`internal/infra/sqlite/migrations/002_add_networking.sql`**:

```sql
-- +goose Up
ALTER TABLE vms ADD COLUMN ip TEXT NOT NULL DEFAULT '';
ALTER TABLE vms ADD COLUMN gateway TEXT NOT NULL DEFAULT '';
ALTER TABLE vms ADD COLUMN netns_path TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE vms DROP COLUMN netns_path;
ALTER TABLE vms DROP COLUMN gateway;
ALTER TABLE vms DROP COLUMN ip;
```

Update sqlc queries to read/write the new columns.

## Step 5: App Service Orchestration

**`internal/app/vm_service.go`** — Update CreateVM flow:

```
1. Validate params
2. network.Setup(id)          → get NetworkInfo (IP, gateway, netns)
3. runtime.Create(id, ..., WithNetNS(netns))
4. store.Create(vm)           → includes IP, gateway, netns_path
   On failure: rollback runtime.Delete, network.Teardown
```

Update DeleteVM to call `network.Teardown(id)` after runtime deletion.

Add Network field to VMService struct, injected via constructor.

## Step 6: Configuration & Wiring

**`internal/config/config.go`** — Add defaults:

```go
viper.SetDefault("cni-bin-dir", "/opt/cni/bin")
viper.SetDefault("cni-conf-dir", "")  // empty = Nexus writes config to temp dir
viper.SetDefault("network-subnet", "10.88.0.0/16")
```

**`cmd/daemon.go`** — Wire CNI adapter:

```go
network, err := cni.New(cni.Config{
    BinDir: viper.GetString("cni-bin-dir"),
    Subnet: viper.GetString("network-subnet"),
})
defer network.Close()

svc := app.NewVMService(store, runtime, network, ...)
```

## Step 7: HTTP API

Update VM response JSON to include `ip` and `gateway` fields (already populated
from the store — no handler changes needed beyond the response struct).

## Prerequisites

Before implementation, CNI plugins must be installed:

```bash
# Install CNI plugins to /opt/cni/bin
sudo mkdir -p /opt/cni/bin
curl -L https://github.com/containernetworking/plugins/releases/download/v1.6.2/cni-plugins-linux-amd64-v1.6.2.tgz | sudo tar -xz -C /opt/cni/bin
```

Also requires `CAP_NET_ADMIN` for network namespace creation. The daemon will
need `AmbientCapabilities=CAP_NET_ADMIN` in its systemd unit, or the cni/network
adapter can be skipped (NoopNetwork) when running without networking.

## Implementation Order

1. Domain types (NetworkInfo, Network port, CreateOpt)
2. Runtime.Create functional options
3. NoopNetwork adapter (enables testing without CNI)
4. Database migration + sqlc regeneration
5. App service orchestration (with NoopNetwork wired in)
6. CNI adapter (real networking)
7. Config + daemon wiring
8. HTTP response updates
9. Smoke test with real CNI

## Verification

1. `go build ./...` — compiles
2. `go test ./...` — unit tests pass (with NoopNetwork)
3. Smoke test: create VM, verify IP assigned, exec `ping` between two VMs
4. Verify teardown: delete VM, confirm netns cleaned up
5. Test with Kata runtime: same flow with `io.containerd.kata.v2`

## Files Modified

- `internal/domain/ports.go` — Network interface, CreateOpt
- `internal/domain/vm.go` — NetworkInfo fields on VM
- `internal/infra/containerd/runtime.go` — CreateOpt support, netns spec
- `internal/infra/cni/network.go` — NEW: CNI adapter
- `internal/infra/cni/noop.go` — NEW: NoopNetwork for testing
- `internal/infra/sqlite/migrations/002_add_networking.sql` — NEW
- `internal/infra/sqlite/queries.sql` — Update for new columns
- `internal/infra/sqlite/store.go` — Updated queries
- `internal/app/vm_service.go` — Network orchestration
- `internal/config/config.go` — CNI config defaults
- `cmd/daemon.go` — Wire CNI adapter
- `internal/infra/httpapi/handler.go` — VM response with IP/gateway
