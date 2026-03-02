# Device Passthrough Design

**Date:** 2026-03-01
**Status:** Approved

## Goal

Add generic device passthrough to nexus so that host devices (GPUs via VFIO, render nodes, FPGAs, etc.) can be attached to VMs. Devices are independent resources with attach/detach lifecycle, matching the drives pattern.

## Architecture

Devices follow the same pattern as drives: independent resources stored in a `devices` table, attached/detached from stopped VMs. When a VM's container is created (or recreated), all attached devices are included in the OCI spec as `linux.devices` entries with corresponding cgroup allow rules.

nexus does NOT manage IOMMU setup, VFIO binding, or capability grants. Those are host-level prerequisites done before registering a device in the API.

## Domain Model

```go
type Device struct {
    ID            string
    HostPath      string    // "/dev/vfio/42", "/dev/dri/renderD128"
    ContainerPath string    // path inside the container
    Permissions   string    // "rwm", "rw", "r" (cgroup device access)
    GID           uint32    // GID for the device node inside the container
    VMID          string    // attached VM ID (empty = unattached)
    CreatedAt     time.Time
}

type CreateDeviceParams struct {
    HostPath      string
    ContainerPath string
    Permissions   string
    GID           uint32
}
```

The `GID` field sets group ownership on the device node inside the container/VM, enabling non-root processes in that group to access the device (e.g., GID 44 for `video` group).

## Database

Migration `004_add_devices.sql`:

```sql
CREATE TABLE devices (
    id              TEXT PRIMARY KEY,
    host_path       TEXT NOT NULL,
    container_path  TEXT NOT NULL,
    permissions     TEXT NOT NULL DEFAULT 'rwm',
    gid             INTEGER NOT NULL DEFAULT 0,
    vm_id           TEXT REFERENCES vms(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_devices_vm_id ON devices(vm_id);
```

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/devices` | Register a device mapping |
| GET | `/v1/devices` | List all devices |
| GET | `/v1/devices/{id}` | Get a device |
| DELETE | `/v1/devices/{id}` | Delete (must be detached) |
| POST | `/v1/devices/{id}/attach` | Attach to a stopped VM |
| POST | `/v1/devices/{id}/detach` | Detach from a stopped VM |

Request (POST /v1/devices):
```json
{
  "host_path": "/dev/vfio/42",
  "container_path": "/dev/vfio/42",
  "permissions": "rwm",
  "gid": 44
}
```

Response:
```json
{
  "id": "uuid",
  "host_path": "/dev/vfio/42",
  "container_path": "/dev/vfio/42",
  "permissions": "rwm",
  "gid": 44,
  "vm_id": null,
  "created_at": "2026-03-01T12:00:00.000Z"
}
```

## OCI Integration

In `Runtime.Create`, attached devices produce two OCI spec entries:

1. **`specs.LinuxDevice`** — declares the device node:
   - `Path`: container_path
   - `Type`: "c" (char) or "b" (block), derived from `stat(host_path)`
   - `Major`/`Minor`: derived from `stat(host_path).Rdev`
   - `GID`: from the device record

2. **`specs.LinuxDeviceCgroup`** — allows access:
   - `Allow`: true
   - `Type`: same as above
   - `Major`/`Minor`: same as above
   - `Access`: permissions string ("rwm")

For Kata+QEMU: the shim translates `linux.devices` with VFIO paths into QEMU `-device vfio-pci` arguments. For runc: the device node is created directly in the container's rootfs.

## Validation

On `POST /v1/devices`:
- `host_path` must exist and be a device file (char or block)
- `container_path` must be an absolute path
- `permissions` must be 1-3 chars, only containing 'r', 'w', 'm', no duplicates

On attach/detach:
- VM must exist and be stopped (same constraint as drives)
- Device must not already be attached (for attach)

## Interaction with recreateContainer

The existing `recreateContainer` helper rebuilds the OCI spec with current drives. It will also query attached devices and include them. Both drives and devices are applied in a single container recreation.

## Layers Modified

| Layer | Files | Changes |
|-------|-------|---------|
| Domain | `domain/device.go`, `domain/ports.go` | Device type, DeviceStore interface, WithDevices CreateOpt |
| Infra/SQLite | `migrations/004_add_devices.sql`, `queries.sql`, `store.go` | Table, queries, DeviceStore impl |
| Infra/containerd | `runtime.go` | Device → OCI spec translation |
| App | `vm_service.go` | 6 device methods, recreateContainer update |
| Infra/HTTP | `handler.go` | 6 routes, request/response types |
| sqlc | `sqlc.yaml` | Rename fix if needed |
