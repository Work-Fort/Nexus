-- SPDX-License-Identifier: Apache-2.0

-- name: InsertVM :exec
INSERT INTO vms (id, name, role, image, runtime, state, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
FROM vms WHERE id = ?;

-- name: GetVMByName :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
FROM vms WHERE name = ?;

-- name: ListVMs :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
FROM vms ORDER BY created_at DESC;

-- name: ListVMsByRole :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
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
