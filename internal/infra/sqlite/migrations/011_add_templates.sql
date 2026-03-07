-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
CREATE TABLE templates (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    distro     TEXT NOT NULL,
    script     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE UNIQUE INDEX idx_templates_distro ON templates(distro);

-- +goose Down
DROP INDEX IF EXISTS idx_templates_distro;
DROP TABLE IF EXISTS templates;
