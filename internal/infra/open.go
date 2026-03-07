// SPDX-License-Identifier: GPL-3.0-or-later
package infra

import (
	"io"
	"strings"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/postgres"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
)

// Store combines all storage interfaces and io.Closer.
type Store interface {
	domain.VMStore
	domain.DriveStore
	domain.DeviceStore
	domain.TemplateStore
	domain.SnapshotStore
	io.Closer
}

// Open auto-detects the database backend from the DSN and returns a Store.
//
// DSN formats:
//   - postgres://... or postgresql://... → PostgreSQL
//   - Any file path or :memory:         → SQLite
func Open(dsn string) (Store, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return postgres.Open(dsn)
	}
	return sqlite.Open(dsn)
}
