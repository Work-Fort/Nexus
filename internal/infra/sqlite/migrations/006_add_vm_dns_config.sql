-- +goose Up
ALTER TABLE vms ADD COLUMN dns_servers TEXT;
ALTER TABLE vms ADD COLUMN dns_search TEXT;

-- +goose Down
ALTER TABLE vms DROP COLUMN dns_servers;
ALTER TABLE vms DROP COLUMN dns_search;
