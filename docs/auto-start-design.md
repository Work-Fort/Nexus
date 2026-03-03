# Auto-Start on Boot Design

Approved design for feature #5 from `docs/remaining-features.md`.

## Summary

Restore previously-running VMs on daemon startup and optionally monitor for
crashes with automatic restart. Per-VM `restart_policy` controls behavior;
per-VM `restart_strategy` controls timing.

## Data Model

Two new fields on the VM:

| Field | Type | Default | Values |
|-------|------|---------|--------|
| `restart_policy` | enum | `none` | `none`, `on-boot`, `always` |
| `restart_strategy` | enum | `backoff` | `immediate`, `backoff`, `fixed` |

**Behavior matrix:**

| Policy | Daemon boot (was running) | Daemon boot (was stopped) | Task crash |
|--------|--------------------------|--------------------------|------------|
| `none` | Mark as stopped | No action | Mark as stopped |
| `on-boot` | Restart | Restart | Mark as stopped |
| `always` | Restart | Restart | Restart |

**Strategy details:**

- `immediate` — restart with no delay.
- `backoff` — exponential (1s, 2s, 4s... capped at 60s), reset after 30s of
  stability.
- `fixed` — 5s delay before each restart.

## Boot Recovery

Runs on daemon startup, after `SyncDNS()` and before `http.Serve()`:

1. Query all VMs from the store.
2. For each VM:
   - **`policy=none` + `state=running`** — Mark as `stopped`. The daemon
     crashed; we can't guarantee the containerd task survived. User restarts
     manually.
   - **`policy=on-boot` or `always`** — Best-effort `runtime.Stop()` (clears
     stale task if alive), then `runtime.Start()`. Update state to `running`.
3. Log each action. Errors on individual VMs don't block other VMs or daemon
   startup.

Runs sequentially per VM during startup.

## Crash Monitor

Background goroutine subscribing to containerd task exit events.

**Lifecycle:**

- Started after boot recovery, before HTTP server.
- Context-based cancellation on daemon shutdown (SIGTERM/SIGINT).

**Event loop:**

1. Subscribe: `namespace==<ns>,topic=="/tasks/exit"`
2. On `TaskExit`:
   - Skip exec process exits (`e.ID != e.ContainerID`).
   - Look up VM by container ID (container ID = VM ID).
   - Skip if `restart_policy != always`.
   - Apply restart strategy.
   - On success: update state to `running`, log.
   - On failure: log error. Will retry on next exit event if the task starts
     briefly.

**Backoff state:** In-memory `map[string]backoffState` keyed by VM ID (last
failure time + current delay). Not persisted — resets on daemon restart.

**Task lifecycle:** After a task exits, containerd auto-deletes it.
`runtime.Start()` calls `container.NewTask()` which creates a fresh task from
the existing container — no container recreation needed.

## API

### Create VM — `POST /v1/vms`

Optional new fields:

```json
{
  "name": "worker",
  "role": "agent",
  "restart_policy": "always",
  "restart_strategy": "backoff"
}
```

Both default to `none` / `backoff` if omitted.

### Update Restart Policy — `PUT /v1/vms/{id}/restart-policy`

```json
{
  "restart_policy": "always",
  "restart_strategy": "immediate"
}
```

Returns 200 with updated VM. Follows the existing action-endpoint pattern
(`start`, `stop`, `exec`).

### VM Response

New fields in all VM responses:

```json
{
  "restart_policy": "none",
  "restart_strategy": "backoff"
}
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Boot recovery: runtime.Start fails | Log error, skip VM, continue to next |
| Crash monitor: runtime.Start fails | Log error, backoff applies on next exit |
| Crash loop (always + immediate) | Tight loop — user should use `backoff` |
| Task still alive at boot | `runtime.Stop()` clears it before restart |
| Invalid restart_policy value | 422 validation error on create/update |

## Testing

### Unit Tests

- Restart policy/strategy enum validation.
- Boot recovery logic with mock store + runtime: correct VMs restarted vs
  marked stopped based on policy.
- Backoff calculation: delays double, cap at 60s, reset after 30s stability.

### Integration Test (mock-based)

- VM with `policy=always`: simulate task exit event → `runtime.Start()` called.
- VM with `policy=none`: simulate task exit → no restart.
- Update restart policy via API → verify stored correctly.

### E2E Tests

- **Crash restart** — VM with `always` policy, kill the containerd task via
  `ctr tasks kill`, verify VM comes back to running within a few seconds.
- **Boot recovery (kill -9)** — VM with `always` policy running, `kill -9` the
  daemon process, start a new daemon on the same state dir and namespace,
  verify VM comes back to running.
- **No-policy cleanup (kill -9)** — VM with `none` policy running, `kill -9`
  the daemon, restart daemon, verify VM state is `stopped`.
