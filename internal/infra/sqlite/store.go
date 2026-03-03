// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
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
	var dnsServers, dnsSearch sql.NullString
	if vm.DNSConfig != nil {
		if len(vm.DNSConfig.Servers) > 0 {
			b, _ := json.Marshal(vm.DNSConfig.Servers)
			dnsServers = sql.NullString{String: string(b), Valid: true}
		}
		if len(vm.DNSConfig.Search) > 0 {
			b, _ := json.Marshal(vm.DNSConfig.Search)
			dnsSearch = sql.NullString{String: string(b), Valid: true}
		}
	}
	return s.q.InsertVM(ctx, InsertVMParams{
		ID:         vm.ID,
		Name:       vm.Name,
		Role:       string(vm.Role),
		Image:      vm.Image,
		Runtime:    vm.Runtime,
		State:      string(vm.State),
		CreatedAt:  vm.CreatedAt.UTC().Format(timeFormat),
		Ip:         vm.IP,
		Gateway:    vm.Gateway,
		NetnsPath:  vm.NetNSPath,
		DnsServers: dnsServers,
		DnsSearch:  dnsSearch,
		RootSize:   vm.RootSize,
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
	return vmFromRow(row)
}

func (s *Store) GetByName(ctx context.Context, name string) (*domain.VM, error) {
	row, err := s.q.GetVMByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get vm by name: %w", err)
	}
	return vmFromRow(row)
}

func (s *Store) List(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	if filter.Role != nil {
		rows, err := s.q.ListVMsByRole(ctx, string(*filter.Role))
		if err != nil {
			return nil, fmt.Errorf("list vms by role: %w", err)
		}
		vms := make([]*domain.VM, len(rows))
		for i, r := range rows {
			vm, err := vmFromRow(r)
			if err != nil {
				return nil, err
			}
			vms[i] = vm
		}
		return vms, nil
	}
	rows, err := s.q.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vms: %w", err)
	}
	vms := make([]*domain.VM, len(rows))
	for i, r := range rows {
		vm, err := vmFromRow(r)
		if err != nil {
			return nil, err
		}
		vms[i] = vm
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

func (s *Store) UpdateRootSize(ctx context.Context, id string, rootSize int64) error {
	return s.q.UpdateVMRootSize(ctx, UpdateVMRootSizeParams{RootSize: rootSize, ID: id})
}

func (s *Store) Delete(ctx context.Context, id string) error {
	return s.q.DeleteVM(ctx, id)
}

// --- domain.DriveStore implementation ---

func (s *Store) CreateDrive(ctx context.Context, d *domain.Drive) error {
	var vmID sql.NullString
	if d.VMID != "" {
		vmID = sql.NullString{String: d.VMID, Valid: true}
	}
	return s.q.InsertDrive(ctx, InsertDriveParams{
		ID:        d.ID,
		Name:      d.Name,
		SizeBytes: int64(d.SizeBytes),
		MountPath: d.MountPath,
		VmID:      vmID,
		CreatedAt: d.CreatedAt.UTC().Format(timeFormat),
	})
}

func (s *Store) GetDrive(ctx context.Context, id string) (*domain.Drive, error) {
	row, err := s.q.GetDrive(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get drive: %w", err)
	}
	return driveFromRow(row)
}

func (s *Store) GetDriveByName(ctx context.Context, name string) (*domain.Drive, error) {
	row, err := s.q.GetDriveByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get drive by name: %w", err)
	}
	return driveFromRow(row)
}

func (s *Store) ListDrives(ctx context.Context) ([]*domain.Drive, error) {
	rows, err := s.q.ListDrives(ctx)
	if err != nil {
		return nil, fmt.Errorf("list drives: %w", err)
	}
	drives := make([]*domain.Drive, len(rows))
	for i, r := range rows {
		d, err := driveFromRow(r)
		if err != nil {
			return nil, err
		}
		drives[i] = d
	}
	return drives, nil
}

func (s *Store) AttachDrive(ctx context.Context, driveID, vmID string) error {
	return s.q.AttachDrive(ctx, AttachDriveParams{
		VmID: sql.NullString{String: vmID, Valid: true},
		ID:   driveID,
	})
}

func (s *Store) DetachDrive(ctx context.Context, driveID string) error {
	return s.q.DetachDrive(ctx, driveID)
}

func (s *Store) DetachAllDrives(ctx context.Context, vmID string) error {
	return s.q.DetachAllDrives(ctx, sql.NullString{String: vmID, Valid: true})
}

func (s *Store) GetDrivesByVM(ctx context.Context, vmID string) ([]*domain.Drive, error) {
	rows, err := s.q.GetDrivesByVM(ctx, sql.NullString{String: vmID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("get drives by vm: %w", err)
	}
	drives := make([]*domain.Drive, len(rows))
	for i, r := range rows {
		d, err := driveFromRow(r)
		if err != nil {
			return nil, err
		}
		drives[i] = d
	}
	return drives, nil
}

func (s *Store) DeleteDrive(ctx context.Context, id string) error {
	return s.q.DeleteDrive(ctx, id)
}

// --- domain.DeviceStore implementation ---

func (s *Store) CreateDevice(ctx context.Context, d *domain.Device) error {
	var vmID sql.NullString
	if d.VMID != "" {
		vmID = sql.NullString{String: d.VMID, Valid: true}
	}
	return s.q.InsertDevice(ctx, InsertDeviceParams{
		ID:            d.ID,
		Name:          d.Name,
		HostPath:      d.HostPath,
		ContainerPath: d.ContainerPath,
		Permissions:   d.Permissions,
		Gid:           int64(d.GID),
		VmID:          vmID,
		CreatedAt:     d.CreatedAt.UTC().Format(timeFormat),
	})
}

func (s *Store) GetDevice(ctx context.Context, id string) (*domain.Device, error) {
	row, err := s.q.GetDevice(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get device: %w", err)
	}
	return deviceFromRow(row)
}

func (s *Store) ListDevices(ctx context.Context) ([]*domain.Device, error) {
	rows, err := s.q.ListDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	devices := make([]*domain.Device, len(rows))
	for i, r := range rows {
		d, err := deviceFromRow(r)
		if err != nil {
			return nil, err
		}
		devices[i] = d
	}
	return devices, nil
}

func (s *Store) AttachDevice(ctx context.Context, deviceID, vmID string) error {
	return s.q.AttachDevice(ctx, AttachDeviceParams{
		VmID: sql.NullString{String: vmID, Valid: true},
		ID:   deviceID,
	})
}

func (s *Store) DetachDevice(ctx context.Context, deviceID string) error {
	return s.q.DetachDevice(ctx, deviceID)
}

func (s *Store) DetachAllDevices(ctx context.Context, vmID string) error {
	return s.q.DetachAllDevices(ctx, sql.NullString{String: vmID, Valid: true})
}

func (s *Store) GetDevicesByVM(ctx context.Context, vmID string) ([]*domain.Device, error) {
	rows, err := s.q.GetDevicesByVM(ctx, sql.NullString{String: vmID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("get devices by vm: %w", err)
	}
	devices := make([]*domain.Device, len(rows))
	for i, r := range rows {
		d, err := deviceFromRow(r)
		if err != nil {
			return nil, err
		}
		devices[i] = d
	}
	return devices, nil
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	return s.q.DeleteDevice(ctx, id)
}

func (s *Store) GetDeviceByName(ctx context.Context, name string) (*domain.Device, error) {
	row, err := s.q.GetDeviceByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get device by name: %w", err)
	}
	return deviceFromRow(row)
}

// --- Resolve methods (lookup by ID or name) ---

func (s *Store) Resolve(ctx context.Context, ref string) (*domain.VM, error) {
	row, err := s.q.ResolveVM(ctx, ResolveVMParams{ID: ref, Name: ref})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("resolve vm: %w", err)
	}
	return vmFromRow(row)
}

func (s *Store) ResolveDrive(ctx context.Context, ref string) (*domain.Drive, error) {
	row, err := s.q.ResolveDrive(ctx, ResolveDriveParams{ID: ref, Name: ref})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("resolve drive: %w", err)
	}
	return driveFromRow(row)
}

func (s *Store) ResolveDevice(ctx context.Context, ref string) (*domain.Device, error) {
	row, err := s.q.ResolveDevice(ctx, ResolveDeviceParams{ID: ref, Name: ref})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("resolve device: %w", err)
	}
	return deviceFromRow(row)
}

// --- type conversion helpers ---

// deviceFromRow converts a sqlc-generated Device row into a domain.Device.
func deviceFromRow(row Device) (*domain.Device, error) {
	d := &domain.Device{
		ID:            row.ID,
		Name:          row.Name,
		HostPath:      row.HostPath,
		ContainerPath: row.ContainerPath,
		Permissions:   row.Permissions,
		GID:           uint32(row.Gid),
	}
	if row.VmID.Valid {
		d.VMID = row.VmID.String
	}
	var err error
	d.CreatedAt, err = time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at for device %s: %w", row.ID, err)
	}
	return d, nil
}

// driveFromRow converts a sqlc-generated Drive row into a domain.Drive.
func driveFromRow(row Drive) (*domain.Drive, error) {
	d := &domain.Drive{
		ID:        row.ID,
		Name:      row.Name,
		SizeBytes: uint64(row.SizeBytes),
		MountPath: row.MountPath,
	}
	if row.VmID.Valid {
		d.VMID = row.VmID.String
	}
	var err error
	d.CreatedAt, err = time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at for drive %s: %w", row.ID, err)
	}
	return d, nil
}

// vmFromRow converts a sqlc-generated Vm row into a domain.VM.
func vmFromRow(row Vm) (*domain.VM, error) {
	vm := &domain.VM{
		ID:        row.ID,
		Name:      row.Name,
		Role:      domain.VMRole(row.Role),
		State:     domain.VMState(row.State),
		Image:     row.Image,
		Runtime:   row.Runtime,
		IP:        row.Ip,
		Gateway:   row.Gateway,
		NetNSPath: row.NetnsPath,
		RootSize:  row.RootSize,
	}
	var err error
	vm.CreatedAt, err = time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at for %s: %w", row.ID, err)
	}
	if row.StartedAt.Valid {
		t, err := time.Parse(timeFormat, row.StartedAt.String)
		if err != nil {
			return nil, fmt.Errorf("parse started_at for %s: %w", row.ID, err)
		}
		vm.StartedAt = &t
	}
	if row.StoppedAt.Valid {
		t, err := time.Parse(timeFormat, row.StoppedAt.String)
		if err != nil {
			return nil, fmt.Errorf("parse stopped_at for %s: %w", row.ID, err)
		}
		vm.StoppedAt = &t
	}
	if row.DnsServers.Valid || row.DnsSearch.Valid {
		vm.DNSConfig = &domain.DNSConfig{}
		if row.DnsServers.Valid {
			json.Unmarshal([]byte(row.DnsServers.String), &vm.DNSConfig.Servers)
		}
		if row.DnsSearch.Valid {
			json.Unmarshal([]byte(row.DnsSearch.String), &vm.DNSConfig.Search)
		}
	}
	return vm, nil
}
