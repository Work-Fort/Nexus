# Webhook Cleanup Design

## Problem

The current webhook system is tightly coupled to Sharkfin:

- `SharkfinWebhook` struct lives in the app layer (leaks infra concern)
- `POST /webhooks/sharkfin` is a hardcoded single-purpose route
- `HandleWebhook()` bundles Sharkfin-specific payload parsing with generic
  "ensure VM is running" logic
- No OpenAPI spec — external callers have no contract to code against
- Unused `webhook-url` config key

Nexus is about to be called by multiple services (Sharkfin, Combine, cloud
provisioner). Each is a regular API client — Nexus doesn't need to know or care
who's calling. The existing CRUD + start/stop API is already sufficient for all
callers. Sharkfin checks agent presence and calls `POST /v1/vms/{id}/start`
when an agent is offline — no special endpoint needed.

## Design

### 1. Delete Sharkfin-specific code

Remove entirely:

- `SharkfinWebhook` struct from `internal/app/vm_service.go`
- `HandleWebhook()` method from `internal/app/vm_service.go`
- `internal/infra/httpapi/webhook.go`
- `internal/infra/httpapi/webhook_test.go`
- `POST /webhooks/sharkfin` route from handler.go
- `webhook-url` viper default from `internal/config/config.go`

### 2. Migrate handlers to huma v2

Replace all `func(w, r)` handlers with huma's typed handler signature:

```go
func(ctx context.Context, input *T) (*U, error)
```

Using the `humago` adapter for stdlib `net/http` compatibility. This gives us:

- OpenAPI 3.1 spec generated at runtime (served at `/openapi.yaml`)
- Type-safe request/response handling
- No build step for spec generation
- Interactive docs at `/docs`

All existing endpoints migrate: VMs, drives, devices, exec, network reset.
No new endpoints.

### 3. Scope

- **Domain layer**: no changes
- **App layer**: delete `SharkfinWebhook` + `HandleWebhook`
- **HTTP layer**: rewrite all handlers to huma, delete `webhook.go`
- **Config**: remove `webhook-url` default

## Implementation Plan

### Task 1: Add huma dependency

Add `github.com/danielgtaylor/huma/v2` to `go.mod`. Verify `humago` adapter
works with our mux.

Files: `go.mod`, `go.sum`

### Task 2: Delete Sharkfin webhook code

- Delete `SharkfinWebhook` struct and `HandleWebhook()` from `vm_service.go`
- Delete `webhook.go` and `webhook_test.go`
- Remove `webhook-url` default from `config.go`

Files:
- `internal/app/vm_service.go`
- `internal/infra/httpapi/webhook.go` (delete)
- `internal/infra/httpapi/webhook_test.go` (delete)
- `internal/config/config.go`

### Task 3: Migrate handler to huma — VM endpoints

Rewrite all VM handlers to huma's typed signature using `humago` adapter.
Define input/output structs with struct tags for OpenAPI metadata. Register
routes via `huma.Register()`.

Endpoints:
- `POST /v1/vms` (create)
- `GET /v1/vms` (list)
- `GET /v1/vms/{id}` (get)
- `DELETE /v1/vms/{id}` (delete)
- `POST /v1/vms/{id}/start`
- `POST /v1/vms/{id}/stop`
- `POST /v1/vms/{id}/exec`

Files: `internal/infra/httpapi/handler.go`

### Task 4: Migrate handler to huma — drive endpoints

Rewrite all drive handlers to huma.

Endpoints:
- `POST /v1/drives` (create)
- `GET /v1/drives` (list)
- `GET /v1/drives/{id}` (get)
- `DELETE /v1/drives/{id}` (delete)
- `POST /v1/drives/{id}/attach`
- `POST /v1/drives/{id}/detach`

Files: `internal/infra/httpapi/handler.go`

### Task 5: Migrate handler to huma — device endpoints

Rewrite all device handlers to huma.

Endpoints:
- `POST /v1/devices` (create)
- `GET /v1/devices` (list)
- `GET /v1/devices/{id}` (get)
- `DELETE /v1/devices/{id}` (delete)
- `POST /v1/devices/{id}/attach`
- `POST /v1/devices/{id}/detach`

Files: `internal/infra/httpapi/handler.go`

### Task 6: Migrate handler to huma — network + utility

Rewrite network reset handler and shared helpers (error mapping, response
conversion).

Endpoints:
- `POST /v1/network/reset`

Files: `internal/infra/httpapi/handler.go`

### Task 7: Update tests

Rewrite HTTP handler tests for the new huma-based handlers. Delete webhook
tests. Existing CRUD tests updated to work with huma's response format.

Files:
- `internal/infra/httpapi/handler_test.go`

### Task 8: Add mise task for OpenAPI spec export

Add a `mise.toml` task that starts the daemon briefly to dump the generated
OpenAPI spec to `docs/openapi.yaml`. Or write a small Go program that
instantiates the huma API and writes the spec without starting a server.

Files: `mise.toml`, possibly `cmd/openapi/main.go`

### Task 9: Verify and build

Run `mise run build`, run all tests, verify the generated OpenAPI spec is
complete and valid.
