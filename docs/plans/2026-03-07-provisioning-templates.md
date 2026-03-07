# Provisioning Templates Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add provisioning templates as a first-class CRUD resource that bootstraps init systems into container images, making them usable as long-running VMs.

**Architecture:** Templates are stored in SQLite via goose migration + sqlc queries. The domain layer defines `Template`, `TemplateStore`, and `CreateTemplateParams`. VMService gains template resolution logic (distro auto-detection + store lookup). The containerd runtime gains `DetectDistro` which reads `/etc/os-release` from image snapshots. Templates are exposed via REST (huma) and MCP endpoints, plus the client library and nexusctl CLI.

**Tech Stack:** Go, SQLite (goose migrations, sqlc), huma REST framework, mcp-go, cobra/viper CLI

---

### Task 1: Domain Types and Store Interface

**Files:**
- Create: `internal/domain/template.go`
- Modify: `internal/domain/ports.go`
- Modify: `internal/domain/vm.go`

**Step 1: Create template domain type**

Create `internal/domain/template.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import "time"

// Template is a reusable provisioning script for bootstrapping VMs.
type Template struct {
	ID        string
	Name      string
	Distro    string // matches /etc/os-release ID field
	Script    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateTemplateParams holds parameters for creating a template.
type CreateTemplateParams struct {
	Name   string
	Distro string
	Script string
}
```

**Step 2: Add TemplateStore interface to ports.go**

Add to `internal/domain/ports.go` after the DeviceStore interface:

```go
// TemplateStore persists provisioning template metadata.
type TemplateStore interface {
	CreateTemplate(ctx context.Context, t *Template) error
	GetTemplate(ctx context.Context, id string) (*Template, error)
	GetTemplateByName(ctx context.Context, name string) (*Template, error)
	GetTemplateByDistro(ctx context.Context, distro string) (*Template, error)
	ResolveTemplate(ctx context.Context, ref string) (*Template, error)
	ListTemplates(ctx context.Context) ([]*Template, error)
	UpdateTemplate(ctx context.Context, id string, name, distro, script string) error
	DeleteTemplate(ctx context.Context, id string) error
	CountTemplateRefs(ctx context.Context, templateID string) (int, error)
}
```

Also add sentinel error:

```go
var ErrTemplateInUse = errors.New("template is referenced by VMs")
```

**Step 3: Add init fields to VM and CreateVMParams in vm.go**

Add to `VM` struct:

```go
Init           bool   // whether init injection is enabled
TemplateID     string // reference to provisioning template
ScriptOverride string // per-VM script override, empty = use template
```

Add to `CreateVMParams` struct:

```go
Init         bool   // opt-in init injection
TemplateName string // optional explicit template, empty = auto-detect
```

**Step 4: Add WithInitScript CreateOpt to ports.go**

```go
// WithInitScript bind-mounts an init bootstrap script into the container
// and overrides the entrypoint to run it.
func WithInitScript(path string) CreateOpt {
	return func(c *CreateConfig) {
		c.InitScriptPath = path
	}
}
```

Add `InitScriptPath string` to CreateConfig struct.

**Step 5: Commit**

```bash
git add internal/domain/template.go internal/domain/ports.go internal/domain/vm.go
git commit -m "feat(domain): add Template type, TemplateStore interface, VM init fields"
```

---

### Task 2: SQLite Migration and Queries

**Files:**
- Create: `internal/infra/sqlite/migrations/010_add_templates.sql`
- Create: `internal/infra/sqlite/migrations/011_add_vm_init.sql`
- Modify: `internal/infra/sqlite/queries.sql`
- Run: `mise run sqlc` to regenerate

**Step 1: Create templates table migration**

Create `internal/infra/sqlite/migrations/010_add_templates.sql`:

```sql
-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
CREATE TABLE templates (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    distro     TEXT NOT NULL,
    script     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX idx_templates_distro ON templates(distro);

-- +goose Down
DROP INDEX IF EXISTS idx_templates_distro;
DROP TABLE IF EXISTS templates;
```

**Step 2: Add VM init fields migration**

Create `internal/infra/sqlite/migrations/011_add_vm_init.sql`:

```sql
-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
ALTER TABLE vms ADD COLUMN init INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vms ADD COLUMN template_id TEXT REFERENCES templates(id);
ALTER TABLE vms ADD COLUMN script_override TEXT;

-- +goose Down
ALTER TABLE vms DROP COLUMN script_override;
ALTER TABLE vms DROP COLUMN template_id;
ALTER TABLE vms DROP COLUMN init;
```

**Step 3: Add sqlc queries for templates**

Append to `internal/infra/sqlite/queries.sql`:

```sql
-- name: InsertTemplate :exec
INSERT INTO templates (id, name, distro, script, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetTemplate :one
SELECT id, name, distro, script, created_at, updated_at
FROM templates WHERE id = ?;

-- name: GetTemplateByName :one
SELECT id, name, distro, script, created_at, updated_at
FROM templates WHERE name = ?;

-- name: GetTemplateByDistro :one
SELECT id, name, distro, script, created_at, updated_at
FROM templates WHERE distro = ?;

-- name: ResolveTemplate :one
SELECT id, name, distro, script, created_at, updated_at
FROM templates WHERE id = ? OR name = ?;

-- name: ListTemplates :many
SELECT id, name, distro, script, created_at, updated_at
FROM templates ORDER BY name;

-- name: UpdateTemplate :exec
UPDATE templates SET name = ?, distro = ?, script = ?, updated_at = ? WHERE id = ?;

-- name: DeleteTemplate :exec
DELETE FROM templates WHERE id = ?;

-- name: CountTemplateRefs :one
SELECT COUNT(*) FROM vms WHERE template_id = ? AND init = 1;
```

**Step 4: Add VM init field queries**

Append to queries.sql:

```sql
-- name: UpdateVMInit :exec
UPDATE vms SET init = ?, template_id = ?, script_override = ? WHERE id = ?;
```

Also modify the InsertVM query to include the new columns:
- Add `init`, `template_id`, `script_override` to the INSERT.
- Add them to the SELECT in GetVM, GetVMByName, ListVMs, ListVMsByRole, ResolveVM.

**Step 5: Regenerate sqlc**

Run: `mise run sqlc`

**Step 6: Commit**

```bash
git add internal/infra/sqlite/migrations/ internal/infra/sqlite/queries.sql internal/infra/sqlite/*.go
git commit -m "feat(sqlite): add templates table and VM init columns"
```

---

### Task 3: SQLite Store Implementation

**Files:**
- Modify: `internal/infra/sqlite/store.go` — add TemplateStore methods
- Test: `internal/infra/sqlite/store_test.go` or create `internal/infra/sqlite/template_test.go`

**Step 1: Write failing tests for template CRUD**

Test: create template → get by ID → get by name → get by distro → list → update → delete.
Test: CountTemplateRefs returns correct count.
Test: resolve by ID and by name.

**Step 2: Implement TemplateStore methods on Store**

Follow the same pattern as existing Drive/Device store methods. Key methods:

- `CreateTemplate` — insert with nxid, validate name uniqueness
- `GetTemplate`, `GetTemplateByName`, `GetTemplateByDistro` — simple selects
- `ResolveTemplate` — by ID or name (same pattern as ResolveDrive)
- `ListTemplates` — return all
- `UpdateTemplate` — update name, distro, script, set updated_at
- `DeleteTemplate` — check CountTemplateRefs first, fail with ErrTemplateInUse
- `CountTemplateRefs` — count VMs referencing this template

Also update VM serialization to include init, template_id, script_override fields in scanVM/insertVM helpers.

**Step 3: Run tests**

Run: `go test ./internal/infra/sqlite/ -v`

**Step 4: Commit**

```bash
git add internal/infra/sqlite/
git commit -m "feat(sqlite): implement TemplateStore methods"
```

---

### Task 4: Built-in Template Seeding

**Files:**
- Create: `internal/infra/sqlite/seeds.go`
- Modify: `internal/infra/sqlite/store.go` — call seeding from Open

**Step 1: Create seeds.go with default templates**

```go
package sqlite

// defaultTemplates are seeded on first run if the templates table is empty.
var defaultTemplates = []struct {
	Name   string
	Distro string
	Script string
}{
	{
		Name:   "alpine-openrc",
		Distro: "alpine",
		Script: `#!/bin/sh
if ! command -v openrc >/dev/null 2>&1; then
    apk add --no-cache openrc
    sed -i 's/^#rc_sys=""/rc_sys="lxc"/' /etc/rc.conf
    mkdir -p /run/openrc
    touch /run/openrc/softlevel
fi
exec /sbin/init`,
	},
	{
		Name:   "ubuntu-systemd",
		Distro: "ubuntu",
		Script: `#!/bin/sh
if [ ! -d /run/systemd/system ]; then
    apt-get update -qq && apt-get install -y -qq systemd-sysv dbus >/dev/null 2>&1
fi
exec /lib/systemd/systemd`,
	},
	{
		Name:   "arch-systemd",
		Distro: "arch",
		Script: `#!/bin/sh
if [ ! -d /run/systemd/system ]; then
    pacman -Sy --noconfirm systemd >/dev/null 2>&1
fi
exec /lib/systemd/systemd`,
	},
}
```

**Step 2: Add SeedTemplates method and call from Open**

`SeedTemplates` checks if the templates table is empty. If so, inserts the defaults. Called from `Open` after migrations complete.

**Step 3: Write test verifying seeds**

Open a fresh `:memory:` store, verify 3 templates exist with correct names/distros.

**Step 4: Commit**

```bash
git add internal/infra/sqlite/seeds.go internal/infra/sqlite/store.go
git commit -m "feat(sqlite): seed built-in provisioning templates on first run"
```

---

### Task 5: Distro Detection in Containerd Runtime

**Files:**
- Modify: `internal/infra/containerd/runtime.go` — add DetectDistro method
- Modify: `internal/domain/ports.go` — add DetectDistro to Runtime interface

**Step 1: Add DetectDistro to Runtime interface**

In `internal/domain/ports.go`, add to the Runtime interface:

```go
DetectDistro(ctx context.Context, image string) (string, error)
```

**Step 2: Implement DetectDistro in containerd runtime**

After pulling/loading the image, mount the snapshot read-only and read `/etc/os-release`. Parse `ID=<distro>`. Return the distro string.

Implementation approach: use containerd's image mount + content reading APIs to read the file from the image's top layer without starting a container.

Fallback: if `/etc/os-release` doesn't exist, check for `/sbin/apk` (alpine), `/usr/bin/apt` (ubuntu/debian), `/usr/bin/pacman` (arch).

**Step 3: Update mock runtime in tests**

Add `DetectDistro` stub to `mockRuntime` in `internal/app/vm_service_test.go` and `internal/infra/httpapi/handler_test.go`.

**Step 4: Commit**

```bash
git add internal/domain/ports.go internal/infra/containerd/runtime.go internal/app/vm_service_test.go internal/infra/httpapi/handler_test.go
git commit -m "feat(containerd): add DetectDistro for image distro identification"
```

---

### Task 6: App Layer — Template CRUD and Init Injection

**Files:**
- Modify: `internal/app/vm_service.go` — add template methods + init injection in CreateVM
- Modify: `internal/app/vm_service_test.go` — tests for template CRUD and init flow

**Step 1: Add WithTemplateStore option**

```go
func WithTemplateStore(ts domain.TemplateStore) func(*VMService) {
	return func(s *VMService) { s.templateStore = ts }
}
```

Add `templateStore domain.TemplateStore` field to VMService struct.

**Step 2: Implement template CRUD methods**

- `CreateTemplate(ctx, params)` — validate, generate NXID, store
- `GetTemplate(ctx, ref)` — resolve by ID or name
- `ListTemplates(ctx)` — list all
- `UpdateTemplate(ctx, ref, params)` — resolve, update
- `DeleteTemplate(ctx, ref)` — check refs, delete

**Step 3: Add init injection to CreateVM**

When `params.Init` is true:

1. Call `runtime.DetectDistro(ctx, image)` to get distro
2. If `params.TemplateName` is set, resolve that template; otherwise look up by distro
3. Store `template_id` on the VM
4. Write template script to temp file at `$XDG_RUNTIME_DIR/nexus/init/<vm-id>.sh`
5. Add `WithInitScript(path)` to createOpts
6. The runtime layer handles bind-mounting and entrypoint override

**Step 4: Handle per-VM script override**

Add `UpdateScriptOverride(ctx, ref, script)` method. On StartVM, resolve the effective script (override > template) and write to temp file.

**Step 5: Write unit tests**

- Test template CRUD lifecycle
- Test CreateVM with init=true auto-detects distro and assigns template
- Test CreateVM with init=true and explicit template name
- Test CreateVM with init=true fails when no matching template
- Test script override takes precedence

**Step 6: Commit**

```bash
git add internal/app/
git commit -m "feat(app): add template CRUD and init injection in CreateVM"
```

---

### Task 7: Containerd Runtime — Init Script Bind-Mount

**Files:**
- Modify: `internal/infra/containerd/runtime.go` — handle InitScriptPath in Create

**Step 1: Handle InitScriptPath in Create**

In the `Create` method, after processing existing CreateConfig fields, add:

```go
if createCfg.InitScriptPath != "" {
	specOpts = append(specOpts, oci.WithMounts([]specs.Mount{{
		Destination: "/nexus-init.sh",
		Type:        "bind",
		Source:      createCfg.InitScriptPath,
		Options:     []string{"rbind", "ro"},
	}}))
	specOpts = append(specOpts, oci.WithProcessArgs("/bin/sh", "/nexus-init.sh"))
}
```

**Step 2: Commit**

```bash
git add internal/infra/containerd/runtime.go
git commit -m "feat(containerd): bind-mount init script and override entrypoint"
```

---

### Task 8: REST API — Template Endpoints

**Files:**
- Modify: `internal/infra/httpapi/handler.go` — add template routes

**Step 1: Add registerTemplateRoutes function**

Follow the exact same pattern as `registerDeviceRoutes`. Five operations:

- `POST /v1/templates` — create
- `GET /v1/templates` — list
- `GET /v1/templates/{ref}` — get by ID or name
- `PUT /v1/templates/{ref}` — update
- `DELETE /v1/templates/{ref}` — delete

**Step 2: Update VM create/get responses to include init fields**

Add `init`, `template_id`, `script_override` to the VM response struct.
Add `init` and `template` to the VM create request struct.

**Step 3: Add script_override to VM PATCH**

**Step 4: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat(httpapi): add template CRUD endpoints and VM init fields"
```

---

### Task 9: MCP Tools — Template Operations

**Files:**
- Modify: `internal/infra/mcp/handler.go` — add 5 template tools + update vm_create

**Step 1: Add registerTemplateTools function**

5 tools: `template_create`, `template_list`, `template_get`, `template_update`, `template_delete`. Follow the exact pattern of `registerDriveTools`.

**Step 2: Update vm_create tool**

Add `init` (boolean) and `template` (string, optional) parameters.

**Step 3: Commit**

```bash
git add internal/infra/mcp/handler.go
git commit -m "feat(mcp): add template tools and vm_create init parameter"
```

---

### Task 10: Client Library — Template Methods

**Files:**
- Create: `client/template.go`
- Modify: `client/vm.go` — add init fields to VM and CreateVMParams

**Step 1: Create client/template.go**

Follow the same pattern as `client/device.go`. Types: `Template`, `CreateTemplateParams`, `UpdateTemplateParams`. Methods: `CreateTemplate`, `ListTemplates`, `GetTemplate`, `UpdateTemplate`, `DeleteTemplate`.

**Step 2: Update client VM types**

Add to `VM` struct: `Init bool`, `TemplateID string`, `ScriptOverride string`.
Add to `CreateVMParams`: `Init bool`, `Template string`.
Add `UpdateScriptOverride(ctx, ref, script)` method.

**Step 3: Add client unit tests**

Add template CRUD tests to `client/client_test.go` following the existing httptest mock pattern.

**Step 4: Commit**

```bash
git add client/template.go client/vm.go client/client_test.go
git commit -m "feat(client): add template methods and VM init fields"
```

---

### Task 11: nexusctl CLI — Template Commands

**Files:**
- Create: `cmd/nexusctl/template.go`
- Modify: `cmd/nexusctl/root.go` — register template command
- Modify: `cmd/nexusctl/vm.go` — add --init and --template flags to vm create

**Step 1: Create template.go**

Follow the pattern of `cmd/nexusctl/device.go`. Subcommands: `template list`, `template get`, `template create`, `template update`, `template delete`.

**Step 2: Register in root.go**

Add `rootCmd.AddCommand(newTemplateCmd())`.

**Step 3: Add --init and --template flags to vm create**

**Step 4: Commit**

```bash
git add cmd/nexusctl/template.go cmd/nexusctl/root.go cmd/nexusctl/vm.go
git commit -m "feat(nexusctl): add template commands and vm create --init flag"
```

---

### Task 12: Wiring — Daemon Startup

**Files:**
- Modify: `cmd/daemon.go` — wire TemplateStore into VMService

**Step 1: Add WithTemplateStore to VMService construction**

After the existing `WithDeviceStore(store)` line, add `app.WithTemplateStore(store)`.

**Step 2: Commit**

```bash
git add cmd/daemon.go
git commit -m "feat(daemon): wire TemplateStore into VMService"
```

---

### Task 13: E2E Tests — Template CRUD

**Files:**
- Modify: `tests/e2e/nexus_test.go` — add template CRUD E2E test

**Step 1: Add TestTemplateLifecycle**

Create a template via REST, list, get, update, delete. Verify each operation.

**Step 2: Run E2E tests**

Run: `mise run e2e`

**Step 3: Commit**

```bash
git add tests/e2e/
git commit -m "test(e2e): add template CRUD lifecycle test"
```

---

### Task 14: E2E Tests — Real Init System Bootstrap

**Files:**
- Create: `tests/e2e/init_test.go`
- Modify: `mise.toml` — add `e2e:init` task

**Step 1: Add mise task**

```toml
[tasks."e2e:init"]
description = "Run init system E2E tests (slow, pulls real images)"
depends = ["build"]
run = "cd tests/e2e && go test -v -count=1 -parallel 1 -timeout 20m -run TestInit ."
```

**Step 2: Write TestInitAlpineOpenRC**

Create VM from `alpine:latest` with init=true → start → wait up to 30s for init → exec `rc-status` → verify output contains service info → stop → restart → verify init comes back.

**Step 3: Write TestInitUbuntuSystemd**

Create VM from `ubuntu:latest` with init=true → start → wait → exec `systemctl is-system-running` → verify `running` or `degraded` → stop → restart → verify.

**Step 4: Write TestInitArchSystemd**

Same pattern with `archlinux:latest`.

**Step 5: Write TestInitPerVMOverride**

Create VM with init=true → patch with script_override → restart → verify override script ran (check for marker file).

**Step 6: Run init E2E tests**

Run: `mise run e2e:init`

**Step 7: Commit**

```bash
git add tests/e2e/init_test.go mise.toml
git commit -m "test(e2e): add real-image init system bootstrap tests"
```

---

### Task 15: Verification and Cleanup

**Step 1: Run full build and tests**

```bash
go build ./...
go vet ./...
go test -short ./...
```

**Step 2: Verify MCP tools show up**

Test with mcp-bridge:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize",...}\n...\n{"jsonrpc":"2.0","id":2,"method":"tools/list",...}\n' | nexusctl mcp-bridge
```

Verify template_create, template_list, template_get, template_update, template_delete appear in the tool list.

**Step 3: Clean up test VM**

```bash
nexusctl vm delete test-vm
```

**Step 4: Commit any remaining changes**

```bash
git add -A && git commit -m "chore: verification cleanup"
```
