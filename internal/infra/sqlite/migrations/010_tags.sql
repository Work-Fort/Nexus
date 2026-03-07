-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
CREATE TABLE vm_tags (
    vm_id TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    tag   TEXT NOT NULL,
    PRIMARY KEY (vm_id, tag)
);

CREATE INDEX idx_vm_tags_tag ON vm_tags(tag);

-- Migrate existing role values into vm_tags.
INSERT INTO vm_tags (vm_id, tag) SELECT id, role FROM vms;

-- Drop role column and its index.
DROP INDEX IF EXISTS idx_vms_role;
ALTER TABLE vms DROP COLUMN role;

-- +goose Down
ALTER TABLE vms ADD COLUMN role TEXT NOT NULL DEFAULT 'agent' CHECK (role IN ('agent', 'service'));
UPDATE vms SET role = (SELECT tag FROM vm_tags WHERE vm_tags.vm_id = vms.id LIMIT 1);
CREATE INDEX idx_vms_role ON vms(role);
DROP INDEX IF EXISTS idx_vm_tags_tag;
DROP TABLE IF EXISTS vm_tags;
