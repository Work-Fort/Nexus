-- SPDX-License-Identifier: GPL-3.0-or-later

-- +goose Up
ALTER TABLE vms ADD COLUMN env TEXT NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE vms DROP COLUMN env;
