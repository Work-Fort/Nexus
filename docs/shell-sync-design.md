# Shell Sync Design

Approved design for feature #11 from `docs/remaining-features.md`.

## Summary

Detect the root user's default login shell from inside a running VM and
persist it to the VM's `shell` field. Uses the existing `ExecVM` path to
run `getent passwd root` and parse field 7. Runs automatically on first
start (when `shell` is empty) and on-demand via an explicit API endpoint.

**Dependency:** Feature #7 (Terminal Access) must be implemented first —
it adds the `Shell` field to the VM struct, the `shell` column in SQLite,
and the `UpdateShell` store method.

## Detection Logic

Exec `getent passwd root` inside the running VM. Parse the first line of
stdout as colon-delimited passwd format and extract field 7 (the shell):

```
root:x:0:0:root:/root:/bin/bash
                          ^^^^^^^ field 7
```

Validation: the detected shell must be a non-empty absolute path (starts
with `/`). If `getent` fails, the output is unparseable, or the shell
isn't an absolute path, `SyncShell` returns an error.

If the detected shell equals the current `vm.Shell`, skip the store
update (no-op).

## Service Method

```go
func (s *VMService) SyncShell(ctx context.Context, ref string) (*domain.VM, error)
```

1. Resolve VM by ref
2. Validate state is `running`
3. Exec `getent passwd root` via `s.runtime.Exec`
4. Parse field 7 from first line of stdout
5. Validate it's an absolute path
6. If different from current `vm.Shell`, call `s.store.UpdateShell`
7. Return updated VM

## Auto-Sync

In `StartVM`, after the state transitions to running, if `vm.Shell == ""`:

```go
go func() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if _, err := s.SyncShell(ctx, vm.ID); err != nil {
        log.Warn("auto shell sync failed", "vm", vm.ID, "err", err)
    }
}()
```

Fire-and-forget goroutine with a 10-second timeout. Uses a fresh context
(not the request context) since the HTTP response has already been sent.
If it fails, the explicit endpoint is always available as a fallback.

## API

**Explicit endpoint** — `POST /v1/vms/{id}/sync-shell`:
- No request body
- Returns updated VM (same shape as `GET /v1/vms/{id}`)
- Errors: 404 (not found), 409 (not running), 422 (detection failed)

**MCP tool** — `vm_sync_shell` with one parameter `vm` (string, required).
Returns the updated VM. Same error semantics.

**nexusctl** — `nexusctl vm sync-shell <vm>`. Prints the detected shell.

## Testing

**Service unit tests:**
- Happy path: mock exec returns valid passwd line, verify `UpdateShell`
  called with correct shell
- No-op: detected shell matches current `vm.Shell`, verify `UpdateShell`
  not called
- Non-running VM: returns error
- Exec failure: returns error
- Bad output: malformed passwd line (too few fields, empty shell, relative
  path) — returns error
- Auto-sync in `StartVM`: verify exec happens when `vm.Shell == ""`
- Auto-sync skipped: verify no exec when `vm.Shell` already set

**E2E tests:**
- Create VM, start, call sync-shell, verify non-empty `shell` in response
- Call sync-shell on stopped VM, verify 409
