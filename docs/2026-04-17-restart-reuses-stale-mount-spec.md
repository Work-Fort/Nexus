# Bug: VM restart reuses stale mount spec after config change

## Symptom

After upgrading `node-exporter-path` resolution (or any other
`MetricsConfig`-sourced mount), previously-created VMs fail to start on
daemon boot:

```
runtime create: failed to fulfil mount request:
  open /usr/bin/node_exporter: no such file or directory
```

The mount HostPath was resolved correctly in the new daemon's config, but
existing VMs still reference the old value.

## Root cause

`internal/app/restart.go:56` calls `s.runtime.Start(ctx, vm.ID, ...)` on
each VM with `restart_policy != none`. In
`internal/infra/containerd/runtime.go:559`, `Start`:

1. Loads the existing container (`client.LoadContainer`)
2. Reads its persisted OCI spec (`container.Spec(ctx)`)
3. Deletes the container (`container.Delete`)
4. Recreates it re-using that **same spec** (line ~590) with only `Env`
   replaced from the new `CreateOpts`

Daemon-config-sourced mounts (metrics/node_exporter,
`ResolvConfPath`, etc.) are established at create time and persist in the
spec. `Start` never re-derives them from the current daemon config, so a
daemon upgrade that changes the resolved path produces a mismatch between
the daemon's view and the container's persisted spec.

## Impact

Any config change that alters a daemon-computed mount path breaks VMs with
`restart_policy=always|on-boot` across a daemon upgrade. Fresh VMs
(created after the upgrade) are unaffected.

Observed today: `node_exporter` path resolved via `exec.LookPath`. Old
daemon resolved against a different PATH and stored `/usr/bin/node_exporter`
in the container spec. New daemon resolves to `~/.local/bin/node_exporter`
in config but Start reuses the stored `/usr/bin/node_exporter`.

## Suggested fix

In `restart.go`, when re-starting a VM, pass fresh mounts/config via
`CreateOpts` the same way the VMService's `StartVM` path does. Or in
`runtime.Start`, drop daemon-managed mounts (node_exporter, resolv.conf,
init script) from the reused spec and re-apply them from `CreateOpts`.

User-defined mounts (drives, devices) must still be preserved.

A marker on mounts to distinguish "daemon-managed" from "user-defined"
would make this unambiguous.

## Workaround

Delete and recreate affected VMs:

```
nexusctl vm delete <name>
nexusctl vm create <name> ...
nexusctl drive attach <data-drive> <name>
nexusctl vm start <name>
```

Persistent drives survive the delete/recreate cycle, so stateful services
(e.g. Passport's DB on `passport-data`) don't lose state.
