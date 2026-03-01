-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
CREATE TABLE vms (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('agent', 'service')),
    image      TEXT NOT NULL,
    runtime    TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'created' CHECK (state IN ('created', 'running', 'stopped')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    started_at TEXT,
    stopped_at TEXT
);

CREATE INDEX idx_vms_role ON vms(role);
CREATE INDEX idx_vms_state ON vms(state);

-- +goose Down
DROP INDEX IF EXISTS idx_vms_state;
DROP INDEX IF EXISTS idx_vms_role;
DROP TABLE IF EXISTS vms;
