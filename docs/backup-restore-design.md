# Backup/Restore Design

Approved design for feature #4 from `docs/remaining-features.md`.

## Summary

Self-contained portable export of a VM and its drives as a `.tar.zst` archive.
Uses btrfs send/receive for drive data and containerd image export for the OCI
image. Import recreates everything to a startable state on any Nexus instance
with a btrfs filesystem.

## Archive Format

```
manifest.json               # VM config + drive/device metadata
image.tar                   # OCI image (containerd export)
drives/
  <drive-name>.btrfs        # btrfs send stream per drive
```

### manifest.json

```json
{
  "version": 1,
  "vm": {
    "name": "worker",
    "role": "agent",
    "image": "docker.io/library/alpine:latest",
    "runtime": "io.containerd.kata.v2",
    "root_size": "10G",
    "dns": {
      "servers": ["172.16.0.1"],
      "search": ["nexus.local"]
    }
  },
  "drives": [
    {"name": "data", "size": "5G", "mount_path": "/data"}
  ],
  "devices": [
    {
      "name": "gpu",
      "host_path": "/dev/vfio/42",
      "container_path": "/dev/vfio/42",
      "permissions": "rwm",
      "gid": 109
    }
  ]
}
```

- `version` field for future compatibility.
- VM fields use user-facing values (k8s size strings, not raw bytes).
- IDs, IPs, timestamps, and netns paths are NOT exported — regenerated on import.
- Devices included only if caller opts in (`include_devices=true`).

## Export Flow

1. Validate VM exists and is **stopped** (reject running VMs with 409).
2. Build `manifest.json` from VM record + attached drives + optionally devices.
3. Create a read-only btrfs snapshot of each drive subvolume (consistent
   point-in-time).
4. Open a tar.zst writer streaming to the response body (HTTP) or file (CLI).
5. Write `manifest.json` to the archive.
6. Export OCI image via containerd `client.Export` → write as `image.tar` entry.
7. For each drive: run `btrfs send <snapshot>` → pipe into tar as
   `drives/<name>.btrfs`.
8. Clean up read-only snapshots.

The archive is never fully buffered in memory. The tar writer receives data as
btrfs send produces it.

## Import Flow

1. Decompress and open tar reader.
2. Read `manifest.json` — validate version and required fields.
3. Check for name conflicts (VM name, drive names). Error if conflicts exist.
4. Import OCI image via containerd `client.Import` from `image.tar` entry.
5. For each drive in `drives/`:
   - Create a new btrfs subvolume.
   - Run `btrfs receive` piping the `.btrfs` stream into it.
   - Set quota if `size` specified.
6. Create VM record in store (state=created, new ID, no IP).
7. Create drive records attached to the new VM.
8. If devices included:
   - Check if each `host_path` exists on this host.
   - Missing: warn by default, error only if `strict_devices=true`.
   - Create device records for valid devices, attached to the new VM.
9. Create containerd container (wire up drives, devices).
10. Return the new VM object — ready to start.

On failure at any step, clean up all partially created resources (subvolumes,
store records, containerd state). No partial state.

## API

```
POST /v1/vms/:id/export?include_devices=false
  → 200 OK, Content-Type: application/zstd
  Body: streaming tar.zst archive

POST /v1/vms/import?strict_devices=false
  Content-Type: application/zstd
  Body: tar.zst archive
  → 201 Created
  Body: { vm: vmResponse, warnings: string[] }
```

## CLI

```
nexus export <vm-id-or-name> -o backup.tar.zst [--include-devices]
nexus import backup.tar.zst [--strict-devices]
```

CLI calls the same `VMService.ExportVM` / `VMService.ImportVM` methods, writing
to/reading from files instead of HTTP streams.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Export running VM | 409 Conflict. Must stop first. |
| Name conflict on import | 409 Conflict. Caller deletes/renames first. |
| Corrupt archive | Error during tar read or btrfs receive. Clean up partial resources. |
| Missing OCI image in archive | Error. Archive is malformed. |
| btrfs receive fails | Clean up created subvolumes, return error. |
| Device host_path missing | Warn unless `strict_devices=true`, then error. |
| Disk full (ENOSPC) | btrfs receive fails. Clean up partial subvolume. |

## Prerequisites

- btrfs filesystem on both source and target hosts
- `btrfs send` and `btrfs receive` available (btrfs-progs)
- containerd running with the target OCI image accessible
- VM must be stopped before export

## Testing

- **Unit tests**: manifest serialization/deserialization, version validation,
  name conflict detection.
- **Integration tests**: export VM with drives, import on same host with
  different name, verify drives restored, verify VM startable.
- **E2E test**: create VM + drive, write data, export, delete original, import,
  start, verify data intact.
