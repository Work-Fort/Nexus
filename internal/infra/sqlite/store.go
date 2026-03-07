// SPDX-License-Identifier: GPL-3.0-or-later
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
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

	s := &Store{db: sqldb, q: New(sqldb)}
	if err := s.seedTemplates(context.Background()); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("seed templates: %w", err)
	}
	return s, nil
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
	var initVal int64
	if vm.Init {
		initVal = 1
	}
	var templateID sql.NullString
	if vm.TemplateID != "" {
		templateID = sql.NullString{String: vm.TemplateID, Valid: true}
	}
	var scriptOverride sql.NullString
	if vm.ScriptOverride != "" {
		scriptOverride = sql.NullString{String: vm.ScriptOverride, Valid: true}
	}
	if err := s.q.InsertVM(ctx, InsertVMParams{
		ID:              vm.ID,
		Name:            vm.Name,
		Image:           vm.Image,
		Runtime:         vm.Runtime,
		State:           string(vm.State),
		CreatedAt:       vm.CreatedAt.UTC().Format(timeFormat),
		Ip:              vm.IP,
		Gateway:         vm.Gateway,
		NetnsPath:       vm.NetNSPath,
		DnsServers:      dnsServers,
		DnsSearch:       dnsSearch,
		RootSize:        vm.RootSize,
		RestartPolicy:   string(vm.RestartPolicy),
		RestartStrategy: string(vm.RestartStrategy),
		Shell:           vm.Shell,
		Init:            initVal,
		TemplateID:      templateID,
		ScriptOverride:  scriptOverride,
	}); err != nil {
		return err
	}
	for _, tag := range vm.Tags {
		if err := s.q.InsertTag(ctx, InsertTagParams{VmID: vm.ID, Tag: tag}); err != nil {
			return fmt.Errorf("insert tag %q: %w", tag, err)
		}
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (*domain.VM, error) {
	row, err := s.q.GetVM(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get vm: %w", err)
	}
	vm, err := vmFromRow(row)
	if err != nil {
		return nil, err
	}
	vm.Tags, err = s.loadTags(ctx, vm.ID)
	if err != nil {
		return nil, fmt.Errorf("load tags: %w", err)
	}
	return vm, nil
}

func (s *Store) GetByName(ctx context.Context, name string) (*domain.VM, error) {
	row, err := s.q.GetVMByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get vm by name: %w", err)
	}
	vm, err := vmFromRow(row)
	if err != nil {
		return nil, err
	}
	vm.Tags, err = s.loadTags(ctx, vm.ID)
	if err != nil {
		return nil, fmt.Errorf("load tags: %w", err)
	}
	return vm, nil
}

func (s *Store) List(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	if len(filter.Tags) > 0 {
		return s.listByTags(ctx, filter.Tags, filter.TagMatch)
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
		vm.Tags, err = s.loadTags(ctx, vm.ID)
		if err != nil {
			return nil, fmt.Errorf("load tags: %w", err)
		}
		vms[i] = vm
	}
	return vms, nil
}

func (s *Store) listByTags(ctx context.Context, tags []string, matchMode string) ([]*domain.VM, error) {
	placeholders := make([]string, len(tags))
	args := make([]any, len(tags))
	for i, t := range tags {
		placeholders[i] = "?"
		args[i] = t
	}
	inClause := strings.Join(placeholders, ",")

	var query string
	if matchMode == "any" {
		query = `SELECT DISTINCT v.id, v.name, v.image, v.runtime, v.state,
			v.created_at, v.started_at, v.stopped_at, v.ip, v.gateway, v.netns_path,
			v.dns_servers, v.dns_search, v.root_size, v.restart_policy, v.restart_strategy, v.shell
			FROM vms v JOIN vm_tags t ON v.id = t.vm_id
			WHERE t.tag IN (` + inClause + `) ORDER BY v.created_at DESC`
	} else {
		query = `SELECT v.id, v.name, v.image, v.runtime, v.state,
			v.created_at, v.started_at, v.stopped_at, v.ip, v.gateway, v.netns_path,
			v.dns_servers, v.dns_search, v.root_size, v.restart_policy, v.restart_strategy, v.shell
			FROM vms v JOIN vm_tags t ON v.id = t.vm_id
			WHERE t.tag IN (` + inClause + `)
			GROUP BY v.id HAVING COUNT(DISTINCT t.tag) = ?
			ORDER BY v.created_at DESC`
		args = append(args, len(tags))
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vms by tags: %w", err)
	}
	defer rows.Close()

	// Collect all rows first so we close the cursor before calling loadTags
	// (SQLite allows only one active statement per connection).
	var scanned []Vm
	for rows.Next() {
		var row Vm
		if err := rows.Scan(&row.ID, &row.Name, &row.Image, &row.Runtime,
			&row.State, &row.CreatedAt, &row.StartedAt, &row.StoppedAt,
			&row.Ip, &row.Gateway, &row.NetnsPath, &row.DnsServers,
			&row.DnsSearch, &row.RootSize, &row.RestartPolicy, &row.RestartStrategy, &row.Shell); err != nil {
			return nil, fmt.Errorf("scan vm: %w", err)
		}
		scanned = append(scanned, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	vms := make([]*domain.VM, 0, len(scanned))
	for _, row := range scanned {
		vm, err := vmFromRow(row)
		if err != nil {
			return nil, err
		}
		vm.Tags, err = s.loadTags(ctx, vm.ID)
		if err != nil {
			return nil, fmt.Errorf("load tags: %w", err)
		}
		vms = append(vms, vm)
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

func (s *Store) UpdateRestartPolicy(ctx context.Context, id string, policy domain.RestartPolicy, strategy domain.RestartStrategy) error {
	return s.q.UpdateVMRestartPolicy(ctx, UpdateVMRestartPolicyParams{
		RestartPolicy:   string(policy),
		RestartStrategy: string(strategy),
		ID:              id,
	})
}

func (s *Store) UpdateShell(ctx context.Context, id, shell string) error {
	return s.q.UpdateVMShell(ctx, UpdateVMShellParams{
		Shell: shell,
		ID:    id,
	})
}

func (s *Store) SetTags(ctx context.Context, vmID string, tags []string) error {
	if err := s.q.DeleteTagsByVM(ctx, vmID); err != nil {
		return fmt.Errorf("delete tags: %w", err)
	}
	for _, tag := range tags {
		if err := s.q.InsertTag(ctx, InsertTagParams{VmID: vmID, Tag: tag}); err != nil {
			return fmt.Errorf("insert tag %q: %w", tag, err)
		}
	}
	return nil
}

func (s *Store) loadTags(ctx context.Context, vmID string) ([]string, error) {
	return s.q.GetTagsByVM(ctx, vmID)
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
	vm, err := vmFromRow(row)
	if err != nil {
		return nil, err
	}
	vm.Tags, err = s.loadTags(ctx, vm.ID)
	if err != nil {
		return nil, fmt.Errorf("load tags: %w", err)
	}
	return vm, nil
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
		State:     domain.VMState(row.State),
		Image:     row.Image,
		Runtime:   row.Runtime,
		IP:        row.Ip,
		Gateway:   row.Gateway,
		NetNSPath: row.NetnsPath,
		RootSize:        row.RootSize,
		RestartPolicy:   domain.RestartPolicy(row.RestartPolicy),
		RestartStrategy: domain.RestartStrategy(row.RestartStrategy),
		Shell:           row.Shell,
		Init:            row.Init != 0,
		TemplateID:      row.TemplateID.String,
		ScriptOverride:  row.ScriptOverride.String,
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

// --- domain.TemplateStore implementation ---

func (s *Store) CreateTemplate(ctx context.Context, t *domain.Template) error {
	return s.q.InsertTemplate(ctx, InsertTemplateParams{
		ID:        t.ID,
		Name:      t.Name,
		Distro:    t.Distro,
		Script:    t.Script,
		CreatedAt: t.CreatedAt.UTC().Format(timeFormat),
		UpdatedAt: t.UpdatedAt.UTC().Format(timeFormat),
	})
}

func (s *Store) GetTemplate(ctx context.Context, id string) (*domain.Template, error) {
	row, err := s.q.GetTemplate(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get template: %w", err)
	}
	return templateFromRow(row)
}

func (s *Store) GetTemplateByName(ctx context.Context, name string) (*domain.Template, error) {
	row, err := s.q.GetTemplateByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get template by name: %w", err)
	}
	return templateFromRow(row)
}

func (s *Store) GetTemplateByDistro(ctx context.Context, distro string) (*domain.Template, error) {
	row, err := s.q.GetTemplateByDistro(ctx, distro)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get template by distro: %w", err)
	}
	return templateFromRow(row)
}

func (s *Store) ResolveTemplate(ctx context.Context, ref string) (*domain.Template, error) {
	row, err := s.q.ResolveTemplate(ctx, ResolveTemplateParams{ID: ref, Name: ref})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("resolve template: %w", err)
	}
	return templateFromRow(row)
}

func (s *Store) ListTemplates(ctx context.Context) ([]*domain.Template, error) {
	rows, err := s.q.ListTemplates(ctx)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	templates := make([]*domain.Template, len(rows))
	for i, r := range rows {
		t, err := templateFromRow(r)
		if err != nil {
			return nil, err
		}
		templates[i] = t
	}
	return templates, nil
}

func (s *Store) UpdateTemplate(ctx context.Context, id string, name, distro, script string) error {
	return s.q.UpdateTemplate(ctx, UpdateTemplateParams{
		ID:        id,
		Name:      name,
		Distro:    distro,
		Script:    script,
		UpdatedAt: time.Now().UTC().Format(timeFormat),
	})
}

func (s *Store) DeleteTemplate(ctx context.Context, id string) error {
	return s.q.DeleteTemplate(ctx, id)
}

func (s *Store) CountTemplateRefs(ctx context.Context, templateID string) (int, error) {
	n, err := s.q.CountTemplateRefs(ctx, sql.NullString{String: templateID, Valid: true})
	if err != nil {
		return 0, fmt.Errorf("count template refs: %w", err)
	}
	return int(n), nil
}

func templateFromRow(row Template) (*domain.Template, error) {
	t := &domain.Template{
		ID:     row.ID,
		Name:   row.Name,
		Distro: row.Distro,
		Script: row.Script,
	}
	var err error
	t.CreatedAt, err = time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at for template %s: %w", row.ID, err)
	}
	t.UpdatedAt, err = time.Parse(timeFormat, row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at for template %s: %w", row.ID, err)
	}
	return t, nil
}

// --- SnapshotStore ---

func (s *Store) CreateSnapshot(ctx context.Context, snap *domain.Snapshot) error {
	return s.q.InsertSnapshot(ctx, InsertSnapshotParams{
		ID:        snap.ID,
		VmID:      snap.VMID,
		Name:      snap.Name,
		CreatedAt: snap.CreatedAt.UTC().Format(timeFormat),
	})
}

func (s *Store) GetSnapshot(ctx context.Context, id string) (*domain.Snapshot, error) {
	row, err := s.q.GetSnapshot(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return snapshotFromRow(row), nil
}

func (s *Store) GetSnapshotByName(ctx context.Context, vmID, name string) (*domain.Snapshot, error) {
	row, err := s.q.GetSnapshotByName(ctx, GetSnapshotByNameParams{VmID: vmID, Name: name})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return snapshotFromRow(row), nil
}

func (s *Store) ListSnapshots(ctx context.Context, vmID string) ([]*domain.Snapshot, error) {
	rows, err := s.q.ListSnapshotsByVM(ctx, vmID)
	if err != nil {
		return nil, err
	}
	result := make([]*domain.Snapshot, len(rows))
	for i, r := range rows {
		result[i] = snapshotFromRow(r)
	}
	return result, nil
}

func (s *Store) DeleteSnapshot(ctx context.Context, id string) error {
	return s.q.DeleteSnapshotByID(ctx, id)
}

func snapshotFromRow(row Snapshot) *domain.Snapshot {
	t, _ := time.Parse(timeFormat, row.CreatedAt)
	return &domain.Snapshot{
		ID:        row.ID,
		VMID:      row.VmID,
		Name:      row.Name,
		CreatedAt: t,
	}
}
