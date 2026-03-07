-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
ALTER TABLE vms ADD COLUMN init INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vms ADD COLUMN template_id TEXT REFERENCES templates(id);
ALTER TABLE vms ADD COLUMN script_override TEXT;

-- +goose Down
ALTER TABLE vms DROP COLUMN script_override;
ALTER TABLE vms DROP COLUMN template_id;
ALTER TABLE vms DROP COLUMN init;
