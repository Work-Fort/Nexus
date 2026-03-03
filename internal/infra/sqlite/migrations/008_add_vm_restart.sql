-- +goose Up
ALTER TABLE vms ADD COLUMN restart_policy TEXT NOT NULL DEFAULT 'none' CHECK (restart_policy IN ('none', 'on-boot', 'always'));
ALTER TABLE vms ADD COLUMN restart_strategy TEXT NOT NULL DEFAULT 'backoff' CHECK (restart_strategy IN ('immediate', 'backoff', 'fixed'));

-- +goose Down
-- SQLite doesn't support DROP COLUMN before 3.35.0; recreate if needed.
