-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
CREATE TABLE IF NOT EXISTS templates (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    distro     TEXT NOT NULL,
    script     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_templates_distro ON templates(distro);

CREATE TABLE IF NOT EXISTS vms (
    id               TEXT PRIMARY KEY,
    name             TEXT UNIQUE NOT NULL,
    image            TEXT NOT NULL,
    runtime          TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'created' CHECK (state IN ('created', 'running', 'stopped')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at       TIMESTAMPTZ,
    stopped_at       TIMESTAMPTZ,
    ip               TEXT NOT NULL DEFAULT '',
    gateway          TEXT NOT NULL DEFAULT '',
    netns_path       TEXT NOT NULL DEFAULT '',
    dns_servers      TEXT,
    dns_search       TEXT,
    root_size        BIGINT NOT NULL DEFAULT 0,
    restart_policy   TEXT NOT NULL DEFAULT 'none' CHECK (restart_policy IN ('none', 'on-boot', 'always')),
    restart_strategy TEXT NOT NULL DEFAULT 'backoff' CHECK (restart_strategy IN ('immediate', 'backoff', 'fixed')),
    shell            TEXT NOT NULL DEFAULT '',
    init             BOOLEAN NOT NULL DEFAULT FALSE,
    template_id      TEXT REFERENCES templates(id),
    script_override  TEXT
);

CREATE INDEX IF NOT EXISTS idx_vms_state ON vms(state);

CREATE TABLE IF NOT EXISTS vm_tags (
    vm_id TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    tag   TEXT NOT NULL,
    PRIMARY KEY (vm_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_vm_tags_tag ON vm_tags(tag);

CREATE TABLE IF NOT EXISTS drives (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    size_bytes BIGINT NOT NULL,
    mount_path TEXT NOT NULL,
    vm_id      TEXT REFERENCES vms(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_drives_vm_id ON drives(vm_id);

CREATE TABLE IF NOT EXISTS devices (
    id             TEXT PRIMARY KEY,
    name           TEXT UNIQUE NOT NULL,
    host_path      TEXT NOT NULL,
    container_path TEXT NOT NULL,
    permissions    TEXT NOT NULL DEFAULT 'rwm',
    gid            INTEGER NOT NULL DEFAULT 0,
    vm_id          TEXT REFERENCES vms(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_vm_id ON devices(vm_id);

-- +goose Down
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS drives;
DROP TABLE IF EXISTS vm_tags;
DROP TABLE IF EXISTS vms;
DROP TABLE IF EXISTS templates;
