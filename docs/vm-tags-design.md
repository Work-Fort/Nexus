# VM Tags Design

Approved design for feature #10 from `docs/remaining-features.md`.

## Summary

Replace the hardcoded `role` enum (`agent`/`service`) with free-form string
tags. Tags are simple lowercase strings stored in a dedicated join table.
The `role` field is removed entirely — existing role values are migrated to
tags.

## Storage

New `vm_tags` join table (migration 009):

```sql
CREATE TABLE vm_tags (
    vm_id TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    tag   TEXT NOT NULL,
    PRIMARY KEY (vm_id, tag)
);
CREATE INDEX idx_vm_tags_tag ON vm_tags(tag);
```

Migration migrates existing `role` values into `vm_tags`, then drops the
`role` column and its index from `vms`.

## Domain Model

```go
type VM struct {
    // ... existing fields ...
    Tags []string  // replaces Role
}

type CreateVMParams struct {
    // ... existing fields ...
    Tags []string  // replaces Role
}

type VMFilter struct {
    Tags     []string // filter by tags
    TagMatch string   // "all" (default, AND) or "any" (OR)
}
```

`VMRole`, `ValidRole()`, and the role constants are deleted.

## Store Interface

`VMStore` gains one method:

```go
SetTags(ctx context.Context, vmID string, tags []string) error
```

`SetTags` is replace-all: delete existing tags, insert new set. `Create`
handles initial tags as part of VM insertion. VM reads (`Get`, `Resolve`,
`List`) load tags with a second query and stitch them onto the VM struct.

List filtering:

- **AND**: `SELECT DISTINCT vm_id FROM vm_tags WHERE tag IN (?) GROUP BY vm_id HAVING COUNT(DISTINCT tag) = ?`
- **OR**: `SELECT DISTINCT vm_id FROM vm_tags WHERE tag IN (?)`

## API

**Create VM** — `POST /v1/vms`:
```json
{"name": "my-vm", "tags": ["agent", "dev"]}
```

**List VMs** — `GET /v1/vms?tag=agent&tag=dev` (AND by default),
`?tag_match=any` for OR.

**Update Tags** — `PUT /v1/vms/{id}/tags`:
```json
{"tags": ["agent", "ci-runner"]}
```
Replaces all tags. Returns updated VM. Works in any VM state.

**Responses**: All VM responses return `"tags": [...]` instead of `"role"`.

**Validation**: Tags must be non-empty, lowercase alphanumeric + hyphens,
max 64 chars each, max 20 tags per VM. Uses existing `nxid.ValidateName`.

## Cascading Changes

- `client/` package: `VM.Tags`, `CreateVMParams.Tags`, `ListVMsFilter.Tags`
  replace role fields
- `cmd/nexusctl/`: `--tag` flags replace `--role`
- MCP endpoint: `tags` parameter replaces `role` on all tools
- E2E harness: types and helpers updated
- Backup export/import: manifest uses `tags` instead of `role`

## Testing

- **Store unit tests**: `SetTags`, AND/OR filtering, empty tags, migration
- **Service unit tests**: `CreateVM` with tags, `SetTags`, filtered listing
- **E2E tests**: Create with tags, list filtering, update tags, export/import
  preserves tags
- **Client tests**: Updated mock tests for tags
- **Bulk update**: Existing tests replace `Role: "agent"` with
  `Tags: []string{"agent"}`
