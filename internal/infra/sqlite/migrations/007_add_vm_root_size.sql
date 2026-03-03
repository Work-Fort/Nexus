-- +goose Up
ALTER TABLE vms ADD COLUMN root_size INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE vms DROP COLUMN root_size;
