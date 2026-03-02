-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
CREATE TABLE devices_new (
    id              TEXT PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    host_path       TEXT NOT NULL,
    container_path  TEXT NOT NULL,
    permissions     TEXT NOT NULL DEFAULT 'rwm',
    gid             INTEGER NOT NULL DEFAULT 0,
    vm_id           TEXT REFERENCES vms(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO devices_new (id, name, host_path, container_path, permissions, gid, vm_id, created_at)
    SELECT id, id, host_path, container_path, permissions, gid, vm_id, created_at FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
CREATE INDEX idx_devices_vm_id ON devices(vm_id);

-- +goose Down
CREATE TABLE devices_old (
    id              TEXT PRIMARY KEY,
    host_path       TEXT NOT NULL,
    container_path  TEXT NOT NULL,
    permissions     TEXT NOT NULL DEFAULT 'rwm',
    gid             INTEGER NOT NULL DEFAULT 0,
    vm_id           TEXT REFERENCES vms(id),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
INSERT INTO devices_old (id, host_path, container_path, permissions, gid, vm_id, created_at)
    SELECT id, host_path, container_path, permissions, gid, vm_id, created_at FROM devices;
DROP TABLE devices;
ALTER TABLE devices_old RENAME TO devices;
CREATE INDEX idx_devices_vm_id ON devices(vm_id);
