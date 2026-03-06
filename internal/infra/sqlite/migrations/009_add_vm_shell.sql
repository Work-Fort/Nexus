-- +goose Up
ALTER TABLE vms ADD COLUMN shell TEXT NOT NULL DEFAULT '';

-- +goose Down
-- SQLite doesn't support DROP COLUMN before 3.35.0; recreate if needed.
