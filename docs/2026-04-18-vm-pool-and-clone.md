# VM Pool and Drive Clone for Agent Orchestration

Nexus's component-level work for the agent pool design. The
cross-cutting design lives in
`flow/lead/docs/2026-04-18-agent-pool.md`.

Nexus already has the primitives. This doc documents what Flow
expects from Nexus and what (if anything) needs to be added.

## What Nexus already provides

Confirmed in source as of `dev-daf7199`:

- VM lifecycle: `vm_create`, `vm_start`, `vm_stop`, `vm_delete`,
  `vm_get`, `vm_list`. REST + MCP.
- Drive lifecycle: `drive_create`, `drive_attach`, `drive_detach`,
  `drive_delete`, `drive_get`, `drive_list`. REST + MCP.
- Snapshot operations on VMs: `CreateSnapshot`, `ListSnapshots`,
  `DeleteSnapshot`, `RestoreSnapshot`, `CloneSnapshot` in
  `internal/app/snapshot.go`. REST + MCP.
- btrfs subvolume support: `nexus-quota` and `nexus-btrfs` helpers
  exist; subvolumes are the underlying storage for drives.
- The btrfs `SnapshotVolume` primitive is available internally on
  the storage abstraction — `CloneSnapshot` already uses it to
  clone drives as part of cloning a VM.

## What Flow needs

### A pool of fungible claude-cli VMs

Flow's claude-cli runtime adapter expects to be able to pick a
free VM from a pool of identical VMs. Each pool VM:

- Runs the same `adjutant-claude-cli:local` image.
- Has no per-agent state baked in (no credentials drive attached
  by default; Flow attaches the per-agent credentials drive on
  claim).
- Is named operationally (e.g. `pool-vm-01`) — not tied to an
  agent identity.

This is **operational provisioning**, not a Nexus code change.
Flow needs to know which VMs are pool VMs (configured in Flow,
or tagged in Nexus). Nexus tag support already exists on the VM
record.

Suggested convention: pool VMs are tagged `pool=claude-cli`. Flow
queries `vm_list` and filters by tag.

### Drive clone from a long-lived master — IMPLEMENTED

`CloneDrive` ships as `app.VMService.CloneDrive` and is exposed on
both REST and MCP using a CSI-shaped wire surface that maps 1:1 to
k8s `VolumeSnapshot` + `PersistentVolumeClaim` clone-from-snapshot
semantics:

- REST: `POST /v1/drives/clone` with body
  `{source_volume_ref, name, mount_path?, snapshot_name?}`
- MCP: tool `drive_clone` with the same four arguments

`mount_path` is optional — when omitted the clone inherits the
source drive's `mount_path`, matching CSI's separation of volume
creation from mount-target declaration. The intermediate btrfs
snapshot is ephemeral when `snapshot_name` is omitted (CSI no-
snapshot path) and retained when set (CSI named-snapshot path).

Implementation reuses `s.storage.SnapshotVolume` and a new
`s.storage.CloneVolume` primitive; the underlying btrfs operation
is `btrfs.CreateSnapshot(snap, dst, readOnly=false)`. Provenance
(source_volume_ref / snapshot_name) is echoed in the response for
the immediate caller's bookkeeping but is not persisted on
`domain.Drive`.

### No hot-attach required

Flow's design accepts that drive attach/detach requires VM stop/
start. Each work item gets its own VM lifecycle, so this isn't
on the hot path.

## Operational setup

When the agent pool design is deployed:

1. Decide pool size (initial estimate: enough VMs for peak
   concurrent work — start with 5–10).
2. Provision pool VMs via `nexusctl vm create`, tagged
   `pool=claude-cli`, with the `adjutant-claude-cli:local` image.
3. Confirm Flow can see them via `vm_list` filtered by tag.

## Out of scope

- Nexus does not know about agents. It hosts VMs and manages
  drives. Flow tells it what to do.
- Nexus does not know about work items. Flow keys drive names by
  work item ID; Nexus stores them as opaque named drives.
- Nexus does not need to know about the project source masters
  versus per-work-item drives. From Nexus's perspective they're
  all drives; Flow handles the semantic distinction.
