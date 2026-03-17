-- SPDX-License-Identifier: GPL-3.0-or-later

-- name: InsertVM :exec
INSERT INTO vms (id, name, image, runtime, state, created_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy, shell, init, template_id, script_override, env)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetVM :one
SELECT id, name, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy, shell, init, template_id, script_override, env
FROM vms WHERE id = ?;

-- name: GetVMByName :one
SELECT id, name, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy, shell, init, template_id, script_override, env
FROM vms WHERE name = ?;

-- name: ListVMs :many
SELECT id, name, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy, shell, init, template_id, script_override, env
FROM vms ORDER BY created_at DESC;

-- name: UpdateVMStateCreated :exec
UPDATE vms SET state = 'created', started_at = NULL, stopped_at = NULL WHERE id = ?;

-- name: UpdateVMStarted :exec
UPDATE vms SET state = 'running', started_at = ? WHERE id = ?;

-- name: UpdateVMStopped :exec
UPDATE vms SET state = 'stopped', stopped_at = ? WHERE id = ?;

-- name: UpdateVMRootSize :exec
UPDATE vms SET root_size = ? WHERE id = ?;

-- name: UpdateVMShell :exec
UPDATE vms SET shell = ? WHERE id = ?;

-- name: DeleteVM :exec
DELETE FROM vms WHERE id = ?;

-- name: CountVMs :one
SELECT COUNT(*) FROM vms;

-- name: InsertTag :exec
INSERT OR IGNORE INTO vm_tags (vm_id, tag) VALUES (?, ?);

-- name: DeleteTagsByVM :exec
DELETE FROM vm_tags WHERE vm_id = ?;

-- name: GetTagsByVM :many
SELECT tag FROM vm_tags WHERE vm_id = ? ORDER BY tag;

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
SELECT id, name, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search, root_size, restart_policy, restart_strategy, shell, init, template_id, script_override, env
FROM vms WHERE id = ? OR name = ?;

-- name: UpdateVMRestartPolicy :exec
UPDATE vms SET restart_policy = ?, restart_strategy = ? WHERE id = ?;

-- name: ResolveDrive :one
SELECT id, name, size_bytes, mount_path, vm_id, created_at
FROM drives WHERE id = ? OR name = ?;

-- name: ResolveDevice :one
SELECT id, name, host_path, container_path, permissions, gid, vm_id, created_at
FROM devices WHERE id = ? OR name = ?;

-- name: UpdateVMInit :exec
UPDATE vms SET init = ?, template_id = ?, script_override = ? WHERE id = ?;

-- Template queries

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

-- name: CountTemplates :one
SELECT COUNT(*) FROM templates;

-- name: InsertSnapshot :exec
INSERT INTO snapshots (id, vm_id, name, created_at) VALUES (?, ?, ?, ?);

-- name: GetSnapshot :one
SELECT id, vm_id, name, created_at FROM snapshots WHERE id = ?;

-- name: GetSnapshotByName :one
SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = ? AND name = ?;

-- name: ListSnapshotsByVM :many
SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = ? ORDER BY created_at;

-- name: DeleteSnapshotByID :exec
DELETE FROM snapshots WHERE id = ?;

-- name: UpdateVMEnv :exec
UPDATE vms SET env = ? WHERE id = ?;

-- name: UpdateVMNetwork :exec
UPDATE vms SET ip = ?, gateway = ?, netns_path = ? WHERE id = ?;
