# VM Image Update

Update a VM's image without losing attached drives, network identity,
env vars, or other configuration. The rootfs is replaced with a fresh
snapshot from the new image.

## How It Works

The VM must be stopped. The operation:

1. Stop the VM if running (or require stopped state).
2. Delete the containerd container and its rootfs snapshot.
3. Pull the new image.
4. Create a new containerd container from the new image, reusing the
   existing network namespace, resolv.conf, env vars, drives, devices,
   init config, and root size.
5. Update the `image` field in the database.

Everything except the rootfs is preserved:

| Preserved | How |
|-----------|-----|
| Network (IP, gateway, namespace) | Reused from DB — not recreated |
| DNS record | Unchanged (same name, same IP) |
| Drives | Attached via bind mounts — independent of rootfs |
| Devices | Attached via OCI spec — rebuilt from DB |
| Env vars | Stored in DB, applied to new container |
| Tags, restart policy, shell | DB fields — untouched |
| Init config + template | Reused from DB |
| Root size quota | Reapplied to new snapshot |

What is **lost**: any modifications to the rootfs (installed packages,
config file edits, files written outside of mounted drives). This is
by design — persistent data belongs on drives.

## API

### REST

```
PUT /v1/vms/{id}/image
{"image": "ghcr.io/work-fort/passport:v0.3.1"}
```

Returns the updated VM. Requires the VM to be stopped.

### MCP

```
vm_patch(id: "passport", image: "ghcr.io/work-fort/passport:v0.3.1")
```

Extend the existing `vm_patch` tool (currently handles `root_size`)
to also accept an `image` parameter.

### CLI

```
nexusctl vm update-image <id> <image>
```

## Implementation

### VMService.UpdateImage

```go
func (s *VMService) UpdateImage(ctx context.Context, ref, newImage string) (*domain.VM, error) {
    vm, err := s.store.Resolve(ctx, ref)
    // Require stopped state.
    // Delete old container + snapshot via runtime.Delete.
    // Pull new image + create new container with same opts
    //   (netns, resolv.conf, env, drives, devices, init, root size).
    // Update image in DB.
    // Return updated VM.
}
```

The key insight: `runtime.Start` already recreates the container on
every start (added for env var support). So `UpdateImage` just needs
to update the image field in the DB, delete the old container, and
let the next `StartVM` handle the recreation with the new image.

Simplified flow:
1. Require stopped.
2. `runtime.Delete(ctx, vm.ID)` — removes container + snapshot.
3. Pull new image: `runtime.Create(ctx, vm.ID, newImage, vm.Runtime, opts...)`.
4. `store.UpdateImage(ctx, vm.ID, newImage)`.
5. Return updated VM.

### VMStore

Add `UpdateImage(ctx context.Context, id, image string) error` to the
VMStore interface. Simple column update — no migration needed since the
`image` column already exists.

### Database

No migration required. Just a new query:

```sql
-- name: UpdateVMImage :exec
UPDATE vms SET image = ? WHERE id = ?;
```

## What Changes

- `internal/domain/ports.go` — add `UpdateImage` to VMStore
- `internal/infra/sqlite/queries.sql` + regenerate — new query
- `internal/infra/sqlite/store.go` — implement UpdateImage
- `internal/infra/postgres/store.go` — implement UpdateImage
- `internal/app/vm_service.go` — add UpdateImage method
- `internal/infra/httpapi/handler.go` — add PUT endpoint or extend vm_patch
- `internal/infra/mcp/handler.go` — extend vm_patch tool
- `cmd/nexusctl/vm.go` — add update-image subcommand
- `tests/e2e/nexus_test.go` — TestVMImageUpdate
- Mock stores — add UpdateImage stub
