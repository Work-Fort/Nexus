-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
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

-- +goose Down
DROP INDEX IF EXISTS idx_devices_vm_id;
DROP TABLE IF EXISTS devices;
