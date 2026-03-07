-- +goose Up
CREATE TABLE snapshots (
    id         TEXT PRIMARY KEY,
    vm_id      TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(vm_id, name)
);

-- +goose Down
DROP TABLE IF EXISTS snapshots;
