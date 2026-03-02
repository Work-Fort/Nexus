-- SPDX-License-Identifier: Apache-2.0

-- name: InsertVM :exec
INSERT INTO vms (id, name, role, image, runtime, state, created_at, ip, gateway, netns_path)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path
FROM vms WHERE id = ?;

-- name: GetVMByName :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path
FROM vms WHERE name = ?;

-- name: ListVMs :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path
FROM vms ORDER BY created_at DESC;

-- name: ListVMsByRole :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path
FROM vms WHERE role = ? ORDER BY created_at DESC;

-- name: UpdateVMStateCreated :exec
UPDATE vms SET state = 'created', started_at = NULL, stopped_at = NULL WHERE id = ?;

-- name: UpdateVMStarted :exec
UPDATE vms SET state = 'running', started_at = ? WHERE id = ?;

-- name: UpdateVMStopped :exec
UPDATE vms SET state = 'stopped', stopped_at = ? WHERE id = ?;

-- name: DeleteVM :exec
DELETE FROM vms WHERE id = ?;

-- name: CountVMs :one
SELECT COUNT(*) FROM vms;

-- name: InsertDrive :exec
INSERT INTO drives (id, name, size_bytes, mount_path, vm_id, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetDrive :one
SELECT id, name, size_bytes, mount_path, vm_id, created_at
FROM drives WHERE id = ?;

-- name: GetDriveByName :one
SELECT id, name, size_bytes, mount_path, vm_id, created_at
FROM drives WHERE name = ?;

-- name: ListDrives :many
SELECT id, name, size_bytes, mount_path, vm_id, created_at
FROM drives ORDER BY created_at DESC;

-- name: AttachDrive :exec
UPDATE drives SET vm_id = ? WHERE id = ?;

-- name: DetachDrive :exec
UPDATE drives SET vm_id = NULL WHERE id = ?;

-- name: DetachAllDrives :exec
UPDATE drives SET vm_id = NULL WHERE vm_id = ?;

-- name: GetDrivesByVM :many
SELECT id, name, size_bytes, mount_path, vm_id, created_at
FROM drives WHERE vm_id = ? ORDER BY name;

-- name: DeleteDrive :exec
DELETE FROM drives WHERE id = ?;

-- name: InsertDevice :exec
INSERT INTO devices (id, name, host_path, container_path, permissions, gid, vm_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetDevice :one
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE id = ?;

-- name: GetDeviceByName :one
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE name = ?;

-- name: ListDevices :many
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices ORDER BY created_at DESC;

-- name: AttachDevice :exec
UPDATE devices SET vm_id = ? WHERE id = ?;

-- name: DetachDevice :exec
UPDATE devices SET vm_id = NULL WHERE id = ?;

-- name: DetachAllDevices :exec
UPDATE devices SET vm_id = NULL WHERE vm_id = ?;

-- name: GetDevicesByVM :many
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE vm_id = ? ORDER BY host_path;

-- name: DeleteDevice :exec
DELETE FROM devices WHERE id = ?;

-- name: ResolveVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path
FROM vms WHERE id = ? OR name = ?;

-- name: ResolveDrive :one
SELECT id, name, size_bytes, mount_path, vm_id, created_at
FROM drives WHERE id = ? OR name = ?;

-- name: ResolveDevice :one
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE id = ? OR name = ?;
