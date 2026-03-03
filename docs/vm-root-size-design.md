# VM Root Size Design

Approved design for feature #2 from `docs/remaining-features.md`.

## Summary

Add a `root_size` field to VMs that limits the writable layer size of the
container snapshot. Uses btrfs simple quotas (squotas) on the snapshot's
subvolume. Expand only (no shrink).

## Mechanism

Each container snapshot under the btrfs snapshotter is a btrfs subvolume.
btrfs simple quotas (kernel 6.7+, near-zero overhead) enforce per-subvolume
size limits via qgroup. The host sets the limit at container creation time.

For Kata VMs: the btrfs snapshotter returns a block device, Kata hotplugs it
into the guest via virtio-mmio (Firecracker) or virtio-scsi (QEMU), and the
guest kernel (with `CONFIG_BTRFS_FS=y`) mounts it. The quota is enforced on
the host side — the guest sees `ENOSPC` when the limit is hit.

Expand is immediate: `btrfs qgroup limit <new_size> <subvolume>` takes effect
without restart.

## Containerd Configuration

- Switch default snapshotter to btrfs in containerd config.
- Nexus Go client adds `client.WithSnapshotter("btrfs")` and
  `client.WithPullSnapshotter("btrfs")`.
- One-time host setup: `btrfs quota enable --simple /` (or the btrfs mount
  point containing containerd's state).
- Guest kernel: Anvil 6.19.5 with `CONFIG_BTRFS_FS=y` (verified working with
  Kata + QEMU, full NVDIMM/DAX path).

## API & Domain Model

### API

`POST /v1/vms` accepts an optional `root_size` string using k8s-style size
notation:

```json
{"name": "worker", "role": "agent", "root_size": "10G"}
```

Supported suffixes: `M` (mebibytes), `G` (gibibytes), `T` (tebibytes).
If omitted, no quota is set (unlimited).

`PATCH /v1/vms/:id` with `{"root_size": "20G"}` expands the quota. New size
must be larger than current (expand only).

### Domain

- `CreateVMParams` and `VM` struct gain a `RootSize int64` field (bytes).
- Zero means no limit.
- Validation: must be positive if set, minimum `64M`.
- `ParseSize(s string) (int64, error)` — converts k8s strings to bytes.
- `FormatSize(n int64) string` — converts bytes to k8s strings for responses.

### Containerd Runtime Adapter

When `RootSize > 0`, after creating the snapshot in `runtime.go`, call
`btrfs qgroup limit <size> <subvolume>` on the snapshot's subvolume. This
happens at container creation time, before `NewTask`.

For expand: call `btrfs qgroup limit` with the new value. Immediate, no
restart needed.

## Error Handling

- **Quota set fails** (e.g. squotas not enabled): VM creation fails with a
  clear error. Snapshot and container are cleaned up. No partial state.
- **Disk full** (VM hits quota): Writes inside the container get `ENOSPC`.
  The VM keeps running. Caller can expand via `PATCH` or the VM can free
  space internally.
- **Expand fails** (e.g. subvolume gone): Returns error, current quota
  unchanged.

Observability of quota events (outbound webhooks, Prometheus) is out of scope
for this feature — tracked in `docs/remaining-features.md` under Investigate.

## Testing

- **Unit tests**: `ParseSize`/`FormatSize` helper (k8s strings to/from bytes),
  validation (minimum 64M, expand-only, positive values).
- **Integration test**: Create VM with `root_size:"1G"`, verify qgroup limit
  is set on the btrfs subvolume via `btrfs qgroup show`. Expand to `2G`,
  verify limit updated.
- **E2E test** (future, feature #3): Create VM with small root size, fill it
  up, confirm `ENOSPC`, expand, confirm writes succeed again.

## Prerequisites

- btrfs simple quotas enabled on the host filesystem
- Anvil 6.19.5+ kernel with `CONFIG_BTRFS_FS=y` (verified)
- containerd configured with btrfs snapshotter
