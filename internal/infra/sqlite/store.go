// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/Work-Fort/Nexus/internal/domain"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

const timeFormat = "2006-01-02T15:04:05.000Z"

// Store implements domain.VMStore backed by SQLite.
type Store struct {
	db *sql.DB
	q  *Queries
}

// Open creates a new SQLite-backed store at the given path.
// Use ":memory:" for an in-memory database (tests).
func Open(path string) (*Store, error) {
	sqldb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := sqldb.Exec("PRAGMA foreign_keys = ON"); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	if _, err := sqldb.Exec("PRAGMA journal_mode = WAL"); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("set journal mode: %w", err)
	}
	if _, err := sqldb.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	if _, err := sqldb.Exec("PRAGMA synchronous = NORMAL"); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("set synchronous: %w", err)
	}
	if _, err := sqldb.Exec("PRAGMA wal_autocheckpoint = 1000"); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("set wal_autocheckpoint: %w", err)
	}
	sqldb.SetMaxOpenConns(1)

	if err := runMigrations(sqldb); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Store{db: sqldb, q: New(sqldb)}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func runMigrations(db *sql.DB) error {
	fsys, err := fs.Sub(embedMigrations, "migrations")
	if err != nil {
		return fmt.Errorf("migrations fs: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, fsys)
	if err != nil {
		return fmt.Errorf("goose provider: %w", err)
	}
	if _, err := provider.Up(context.Background()); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// --- domain.VMStore implementation ---

func (s *Store) Create(ctx context.Context, vm *domain.VM) error {
	return s.q.InsertVM(ctx, InsertVMParams{
		ID:        vm.ID,
		Name:      vm.Name,
		Role:      string(vm.Role),
		Image:     vm.Image,
		Runtime:   vm.Runtime,
		State:     string(vm.State),
		CreatedAt: vm.CreatedAt.UTC().Format(timeFormat),
	})
}

func (s *Store) Get(ctx context.Context, id string) (*domain.VM, error) {
	row, err := s.q.GetVM(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get vm: %w", err)
	}
	return vmFromRow(row), nil
}

func (s *Store) GetByName(ctx context.Context, name string) (*domain.VM, error) {
	row, err := s.q.GetVMByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get vm by name: %w", err)
	}
	return vmFromRow(row), nil
}

func (s *Store) List(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	if filter.Role != nil {
		rows, err := s.q.ListVMsByRole(ctx, string(*filter.Role))
		if err != nil {
			return nil, fmt.Errorf("list vms by role: %w", err)
		}
		vms := make([]*domain.VM, len(rows))
		for i, r := range rows {
			vms[i] = vmFromRow(r)
		}
		return vms, nil
	}
	rows, err := s.q.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vms: %w", err)
	}
	vms := make([]*domain.VM, len(rows))
	for i, r := range rows {
		vms[i] = vmFromRow(r)
	}
	return vms, nil
}

func (s *Store) UpdateState(ctx context.Context, id string, state domain.VMState, now time.Time) error {
	ts := now.UTC().Format(timeFormat)
	switch state {
	case domain.VMStateRunning:
		return s.q.UpdateVMStarted(ctx, UpdateVMStartedParams{
			StartedAt: sql.NullString{String: ts, Valid: true},
			ID:        id,
		})
	case domain.VMStateStopped:
		return s.q.UpdateVMStopped(ctx, UpdateVMStoppedParams{
			StoppedAt: sql.NullString{String: ts, Valid: true},
			ID:        id,
		})
	case domain.VMStateCreated:
		return s.q.UpdateVMStateCreated(ctx, id)
	default:
		return fmt.Errorf("unknown state: %s", state)
	}
}

func (s *Store) Delete(ctx context.Context, id string) error {
	return s.q.DeleteVM(ctx, id)
}

// --- type conversion helper ---

// vmFromRow converts a sqlc-generated Vm row into a domain.VM.
func vmFromRow(row Vm) *domain.VM {
	vm := &domain.VM{
		ID:      row.ID,
		Name:    row.Name,
		Role:    domain.VMRole(row.Role),
		State:   domain.VMState(row.State),
		Image:   row.Image,
		Runtime: row.Runtime,
	}
	vm.CreatedAt, _ = time.Parse(timeFormat, row.CreatedAt)
	if row.StartedAt.Valid {
		t, _ := time.Parse(timeFormat, row.StartedAt.String)
		vm.StartedAt = &t
	}
	if row.StoppedAt.Valid {
		t, _ := time.Parse(timeFormat, row.StoppedAt.String)
		vm.StoppedAt = &t
	}
	return vm
}
