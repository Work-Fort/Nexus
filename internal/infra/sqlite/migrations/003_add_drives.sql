-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
CREATE TABLE drives (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    size_bytes INTEGER NOT NULL,
    mount_path TEXT NOT NULL,
    vm_id      TEXT REFERENCES vms(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_drives_vm_id ON drives(vm_id);

-- +goose Down
DROP INDEX IF EXISTS idx_drives_vm_id;
DROP TABLE IF EXISTS drives;
