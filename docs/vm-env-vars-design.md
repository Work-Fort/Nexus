# VM Environment Variables

Environment variables for VMs, settable at creation time and updateable
afterward. Changes take effect on next VM restart.

## Storage

Add `Env map[string]string` to the `VM` struct and `CreateVMParams` in
`internal/domain/vm.go`. Stored as a JSON column in SQLite and Postgres.
Null/empty map means no user-supplied env vars.

## Create

`POST /v1/vms` accepts an optional `env` field:

```json
{
  "name": "passport",
  "image": "ghcr.io/work-fort/passport:v0.0.8",
  "env": {
    "DATABASE_URL": "postgres://...",
    "LOG_LEVEL": "info"
  }
}
```

## Update

`PUT /v1/vms/{id}/env` replaces the full env var map. Changes are stored
in the DB and take effect on next VM restart.

```json
{
  "env": {
    "DATABASE_URL": "postgres://new-host/...",
    "LOG_LEVEL": "debug",
    "NEW_VAR": "value"
  }
}
```

To clear all env vars, send an empty map: `{"env": {}}`.

## Runtime Behavior

### Env var merging

When `runtime.Create` builds the OCI spec, user-supplied env vars are
merged on top of image-defined env vars. User vars override image
defaults on conflict. Image env vars that are not overridden are
preserved.

### Container recreation on start

Env vars are baked into the OCI spec at container creation time. To
apply changes, the container must be recreated. `runtime.Start` will
always recreate the container:

1. Load existing container from containerd.
2. Delete the container metadata (preserve the rootfs snapshot).
3. Recreate the container with the current env vars, reusing the
   existing `<id>-snap` snapshot.
4. Create a new task and start it.

Data safety:
- **Rootfs snapshot** (`<id>-snap`) is preserved across recreation.
- **Drives** are btrfs subvolumes mounted via bind mounts, independent
  of the container. Unaffected by recreation.

## API

### REST

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /v1/vms` | POST | Create VM with optional `env` field |
| `GET /v1/vms/{id}` | GET | Returns VM including `env` |
| `PUT /v1/vms/{id}/env` | PUT | Replace env var map (takes effect on restart) |

### MCP

| Tool | Description |
|------|-------------|
| `vm_create` | Add `env` parameter (JSON object string) |
| `vm_get` | Response includes `env` field |
| `vm_env` | Get/set env vars. Usage: `vm_env(id: "myvm", env: {"KEY": "value"})` |

### CLI (nexusctl)

```
nexusctl vm create --name myvm --env KEY=value --env DB_URL=postgres://...
nexusctl vm env <id>                    # show current env vars
nexusctl vm env <id> KEY=value ...      # set env vars
nexusctl vm env <id> --clear            # remove all env vars
```

## Database

### SQLite

Add column to `vms` table:

```sql
ALTER TABLE vms ADD COLUMN env TEXT NOT NULL DEFAULT '{}';
```

New queries:
- `UpdateVMEnv`: `UPDATE vms SET env = ? WHERE id = ?`

### Postgres

Same column addition and query.

## What Changes

- `internal/domain/vm.go` — add `Env` field to `VM` and `CreateVMParams`
- `internal/domain/ports.go` — add `UpdateEnv` to `VMStore`
- `internal/infra/sqlite/` — migration, query, store method
- `internal/infra/postgres/` — same
- `internal/infra/containerd/runtime.go` — accept env vars in `CreateConfig`,
  change `Start` to always recreate the container
- `internal/app/vm_service.go` — pass env to runtime, add `UpdateEnv` method
- `internal/infra/httpapi/` — new handler, update create handler
- `internal/infra/mcp/` — new tool, update vm_create
- `cmd/nexusctl/` — new subcommand
