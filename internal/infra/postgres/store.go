// SPDX-License-Identifier: GPL-3.0-or-later
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// Compile-time interface checks.
var (
	_ domain.VMStore       = (*Store)(nil)
	_ domain.DriveStore    = (*Store)(nil)
	_ domain.DeviceStore   = (*Store)(nil)
	_ domain.TemplateStore  = (*Store)(nil)
	_ domain.SnapshotStore  = (*Store)(nil)
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// Store implements domain.VMStore, DriveStore, DeviceStore, and TemplateStore
// backed by PostgreSQL.
type Store struct {
	db *sql.DB
}

// Open opens a PostgreSQL database and runs migrations.
func Open(dsn string) (*Store, error) {
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	sqldb.SetMaxOpenConns(25)
	sqldb.SetMaxIdleConns(5)
	sqldb.SetConnMaxLifetime(5 * time.Minute)

	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	if err := runMigrations(sqldb); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	s := &Store{db: sqldb}
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
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		return fmt.Errorf("goose provider: %w", err)
	}
	if _, err := provider.Up(context.Background()); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// --- domain.VMStore ---

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
	var templateID, scriptOverride sql.NullString
	if vm.TemplateID != "" {
		templateID = sql.NullString{String: vm.TemplateID, Valid: true}
	}
	if vm.ScriptOverride != "" {
		scriptOverride = sql.NullString{String: vm.ScriptOverride, Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vms (id, name, image, runtime, state, created_at, ip, gateway, netns_path,
			dns_servers, dns_search, root_size, restart_policy, restart_strategy, shell,
			init, template_id, script_override)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		vm.ID, vm.Name, vm.Image, vm.Runtime, string(vm.State), vm.CreatedAt.UTC(),
		vm.IP, vm.Gateway, vm.NetNSPath, dnsServers, dnsSearch, vm.RootSize,
		string(vm.RestartPolicy), string(vm.RestartStrategy), vm.Shell,
		vm.Init, templateID, scriptOverride,
	)
	if err != nil {
		return err
	}
	for _, tag := range vm.Tags {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO vm_tags (vm_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			vm.ID, tag); err != nil {
			return fmt.Errorf("insert tag %q: %w", tag, err)
		}
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (*domain.VM, error) {
	return s.scanVM(ctx, `SELECT `+vmCols+` FROM vms WHERE id = $1`, id)
}

func (s *Store) GetByName(ctx context.Context, name string) (*domain.VM, error) {
	return s.scanVM(ctx, `SELECT `+vmCols+` FROM vms WHERE name = $1`, name)
}

func (s *Store) Resolve(ctx context.Context, ref string) (*domain.VM, error) {
	return s.scanVM(ctx, `SELECT `+vmCols+` FROM vms WHERE id = $1 OR name = $2`, ref, ref)
}

func (s *Store) List(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	if len(filter.Tags) > 0 {
		return s.listByTags(ctx, filter.Tags, filter.TagMatch)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+vmCols+` FROM vms ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list vms: %w", err)
	}
	defer rows.Close()
	return s.collectVMs(ctx, rows)
}

func (s *Store) listByTags(ctx context.Context, tags []string, matchMode string) ([]*domain.VM, error) {
	placeholders := make([]string, len(tags))
	args := make([]any, len(tags))
	for i, t := range tags {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = t
	}
	inClause := strings.Join(placeholders, ",")

	var query string
	if matchMode == "any" {
		query = `SELECT DISTINCT ` + vmCols + ` FROM vms v JOIN vm_tags t ON v.id = t.vm_id
			WHERE t.tag IN (` + inClause + `) ORDER BY v.created_at DESC`
	} else {
		query = `SELECT ` + vmCols + ` FROM vms v JOIN vm_tags t ON v.id = t.vm_id
			WHERE t.tag IN (` + inClause + `)
			GROUP BY ` + vmColsPrefixed + ` HAVING COUNT(DISTINCT t.tag) = $` + fmt.Sprintf("%d", len(tags)+1) + `
			ORDER BY v.created_at DESC`
		args = append(args, len(tags))
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vms by tags: %w", err)
	}
	defer rows.Close()
	return s.collectVMs(ctx, rows)
}

func (s *Store) UpdateState(ctx context.Context, id string, state domain.VMState, now time.Time) error {
	ts := now.UTC()
	var err error
	switch state {
	case domain.VMStateRunning:
		_, err = s.db.ExecContext(ctx,
			`UPDATE vms SET state = 'running', started_at = $1 WHERE id = $2`, ts, id)
	case domain.VMStateStopped:
		_, err = s.db.ExecContext(ctx,
			`UPDATE vms SET state = 'stopped', stopped_at = $1 WHERE id = $2`, ts, id)
	case domain.VMStateCreated:
		_, err = s.db.ExecContext(ctx,
			`UPDATE vms SET state = 'created', started_at = NULL, stopped_at = NULL WHERE id = $1`, id)
	default:
		return fmt.Errorf("unknown state: %s", state)
	}
	return err
}

func (s *Store) UpdateRootSize(ctx context.Context, id string, rootSize int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vms SET root_size = $1 WHERE id = $2`, rootSize, id)
	return err
}

func (s *Store) UpdateRestartPolicy(ctx context.Context, id string, policy domain.RestartPolicy, strategy domain.RestartStrategy) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE vms SET restart_policy = $1, restart_strategy = $2 WHERE id = $3`,
		string(policy), string(strategy), id)
	return err
}

func (s *Store) UpdateShell(ctx context.Context, id, shell string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vms SET shell = $1 WHERE id = $2`, shell, id)
	return err
}

func (s *Store) SetTags(ctx context.Context, vmID string, tags []string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM vm_tags WHERE vm_id = $1`, vmID); err != nil {
		return fmt.Errorf("delete tags: %w", err)
	}
	for _, tag := range tags {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO vm_tags (vm_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			vmID, tag); err != nil {
			return fmt.Errorf("insert tag %q: %w", tag, err)
		}
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vms WHERE id = $1`, id)
	return err
}

// --- domain.DriveStore ---

func (s *Store) CreateDrive(ctx context.Context, d *domain.Drive) error {
	var vmID sql.NullString
	if d.VMID != "" {
		vmID = sql.NullString{String: d.VMID, Valid: true}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO drives (id, name, size_bytes, mount_path, vm_id, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		d.ID, d.Name, int64(d.SizeBytes), d.MountPath, vmID, d.CreatedAt.UTC())
	return err
}

func (s *Store) GetDrive(ctx context.Context, id string) (*domain.Drive, error) {
	return s.scanDrive(ctx, `SELECT `+driveCols+` FROM drives WHERE id = $1`, id)
}

func (s *Store) GetDriveByName(ctx context.Context, name string) (*domain.Drive, error) {
	return s.scanDrive(ctx, `SELECT `+driveCols+` FROM drives WHERE name = $1`, name)
}

func (s *Store) ResolveDrive(ctx context.Context, ref string) (*domain.Drive, error) {
	return s.scanDrive(ctx, `SELECT `+driveCols+` FROM drives WHERE id = $1 OR name = $2`, ref, ref)
}

func (s *Store) ListDrives(ctx context.Context) ([]*domain.Drive, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+driveCols+` FROM drives ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var drives []*domain.Drive
	for rows.Next() {
		d, err := scanDriveRow(rows)
		if err != nil {
			return nil, err
		}
		drives = append(drives, d)
	}
	return drives, rows.Err()
}

func (s *Store) AttachDrive(ctx context.Context, driveID, vmID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE drives SET vm_id = $1 WHERE id = $2`, vmID, driveID)
	return err
}

func (s *Store) DetachDrive(ctx context.Context, driveID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE drives SET vm_id = NULL WHERE id = $1`, driveID)
	return err
}

func (s *Store) DetachAllDrives(ctx context.Context, vmID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE drives SET vm_id = NULL WHERE vm_id = $1`, vmID)
	return err
}

func (s *Store) GetDrivesByVM(ctx context.Context, vmID string) ([]*domain.Drive, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+driveCols+` FROM drives WHERE vm_id = $1 ORDER BY name`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var drives []*domain.Drive
	for rows.Next() {
		d, err := scanDriveRow(rows)
		if err != nil {
			return nil, err
		}
		drives = append(drives, d)
	}
	return drives, rows.Err()
}

func (s *Store) DeleteDrive(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM drives WHERE id = $1`, id)
	return err
}

// --- domain.DeviceStore ---

func (s *Store) CreateDevice(ctx context.Context, d *domain.Device) error {
	var vmID sql.NullString
	if d.VMID != "" {
		vmID = sql.NullString{String: d.VMID, Valid: true}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO devices (id, name, host_path, container_path, permissions, gid, vm_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		d.ID, d.Name, d.HostPath, d.ContainerPath, d.Permissions, int64(d.GID), vmID, d.CreatedAt.UTC())
	return err
}

func (s *Store) GetDevice(ctx context.Context, id string) (*domain.Device, error) {
	return s.scanDevice(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = $1`, id)
}

func (s *Store) GetDeviceByName(ctx context.Context, name string) (*domain.Device, error) {
	return s.scanDevice(ctx, `SELECT `+deviceCols+` FROM devices WHERE name = $1`, name)
}

func (s *Store) ResolveDevice(ctx context.Context, ref string) (*domain.Device, error) {
	return s.scanDevice(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = $1 OR name = $2`, ref, ref)
}

func (s *Store) ListDevices(ctx context.Context) ([]*domain.Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []*domain.Device
	for rows.Next() {
		d, err := scanDeviceRow(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *Store) AttachDevice(ctx context.Context, deviceID, vmID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET vm_id = $1 WHERE id = $2`, vmID, deviceID)
	return err
}

func (s *Store) DetachDevice(ctx context.Context, deviceID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET vm_id = NULL WHERE id = $1`, deviceID)
	return err
}

func (s *Store) DetachAllDevices(ctx context.Context, vmID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET vm_id = NULL WHERE vm_id = $1`, vmID)
	return err
}

func (s *Store) GetDevicesByVM(ctx context.Context, vmID string) ([]*domain.Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE vm_id = $1 ORDER BY host_path`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []*domain.Device
	for rows.Next() {
		d, err := scanDeviceRow(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = $1`, id)
	return err
}

// --- domain.TemplateStore ---

func (s *Store) CreateTemplate(ctx context.Context, t *domain.Template) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO templates (id, name, distro, script, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		t.ID, t.Name, t.Distro, t.Script, t.CreatedAt.UTC(), t.UpdatedAt.UTC())
	return err
}

func (s *Store) GetTemplate(ctx context.Context, id string) (*domain.Template, error) {
	return s.scanTemplate(ctx, `SELECT `+templateCols+` FROM templates WHERE id = $1`, id)
}

func (s *Store) GetTemplateByName(ctx context.Context, name string) (*domain.Template, error) {
	return s.scanTemplate(ctx, `SELECT `+templateCols+` FROM templates WHERE name = $1`, name)
}

func (s *Store) GetTemplateByDistro(ctx context.Context, distro string) (*domain.Template, error) {
	return s.scanTemplate(ctx, `SELECT `+templateCols+` FROM templates WHERE distro = $1`, distro)
}

func (s *Store) ResolveTemplate(ctx context.Context, ref string) (*domain.Template, error) {
	return s.scanTemplate(ctx, `SELECT `+templateCols+` FROM templates WHERE id = $1 OR name = $2`, ref, ref)
}

func (s *Store) ListTemplates(ctx context.Context) ([]*domain.Template, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+templateCols+` FROM templates ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var templates []*domain.Template
	for rows.Next() {
		t, err := scanTemplateRow(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

func (s *Store) UpdateTemplate(ctx context.Context, id string, name, distro, script string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE templates SET name = $1, distro = $2, script = $3, updated_at = $4 WHERE id = $5`,
		name, distro, script, time.Now().UTC(), id)
	return err
}

func (s *Store) DeleteTemplate(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM templates WHERE id = $1`, id)
	return err
}

func (s *Store) CountTemplateRefs(ctx context.Context, templateID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vms WHERE template_id = $1 AND init = TRUE`, templateID).Scan(&n)
	return n, err
}

// --- Column lists ---

const vmCols = `id, name, image, runtime, state, created_at, started_at, stopped_at,
	ip, gateway, netns_path, dns_servers, dns_search, root_size,
	restart_policy, restart_strategy, shell, init, template_id, script_override`

const vmColsPrefixed = `v.id, v.name, v.image, v.runtime, v.state, v.created_at, v.started_at, v.stopped_at,
	v.ip, v.gateway, v.netns_path, v.dns_servers, v.dns_search, v.root_size,
	v.restart_policy, v.restart_strategy, v.shell, v.init, v.template_id, v.script_override`

const driveCols = `id, name, size_bytes, mount_path, vm_id, created_at`
const deviceCols = `id, name, host_path, container_path, permissions, gid, vm_id, created_at`
const templateCols = `id, name, distro, script, created_at, updated_at`

// --- Scan helpers ---

type scanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanVM(ctx context.Context, query string, args ...any) (*domain.VM, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	vm, err := scanVMRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	vm.Tags, err = s.loadTags(ctx, vm.ID)
	if err != nil {
		return nil, fmt.Errorf("load tags: %w", err)
	}
	return vm, nil
}

func scanVMRow(s scanner) (*domain.VM, error) {
	var vm domain.VM
	var state, restartPolicy, restartStrategy string
	var createdAt time.Time
	var startedAt, stoppedAt sql.NullTime
	var dnsServers, dnsSearch, templateID, scriptOverride sql.NullString

	err := s.Scan(
		&vm.ID, &vm.Name, &vm.Image, &vm.Runtime, &state, &createdAt,
		&startedAt, &stoppedAt, &vm.IP, &vm.Gateway, &vm.NetNSPath,
		&dnsServers, &dnsSearch, &vm.RootSize,
		&restartPolicy, &restartStrategy, &vm.Shell, &vm.Init,
		&templateID, &scriptOverride,
	)
	if err != nil {
		return nil, err
	}

	vm.State = domain.VMState(state)
	vm.CreatedAt = createdAt
	vm.RestartPolicy = domain.RestartPolicy(restartPolicy)
	vm.RestartStrategy = domain.RestartStrategy(restartStrategy)
	vm.TemplateID = templateID.String
	vm.ScriptOverride = scriptOverride.String

	if startedAt.Valid {
		t := startedAt.Time
		vm.StartedAt = &t
	}
	if stoppedAt.Valid {
		t := stoppedAt.Time
		vm.StoppedAt = &t
	}
	if dnsServers.Valid || dnsSearch.Valid {
		vm.DNSConfig = &domain.DNSConfig{}
		if dnsServers.Valid {
			json.Unmarshal([]byte(dnsServers.String), &vm.DNSConfig.Servers)
		}
		if dnsSearch.Valid {
			json.Unmarshal([]byte(dnsSearch.String), &vm.DNSConfig.Search)
		}
	}
	return &vm, nil
}

func (s *Store) collectVMs(ctx context.Context, rows *sql.Rows) ([]*domain.VM, error) {
	var vms []*domain.VM
	for rows.Next() {
		vm, err := scanVMRow(rows)
		if err != nil {
			return nil, err
		}
		vm.Tags, err = s.loadTags(ctx, vm.ID)
		if err != nil {
			return nil, fmt.Errorf("load tags: %w", err)
		}
		vms = append(vms, vm)
	}
	return vms, rows.Err()
}

func (s *Store) loadTags(ctx context.Context, vmID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tag FROM vm_tags WHERE vm_id = $1 ORDER BY tag`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, rows.Err()
}

func (s *Store) scanDrive(ctx context.Context, query string, args ...any) (*domain.Drive, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	d, err := scanDriveRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return d, nil
}

func scanDriveRow(s scanner) (*domain.Drive, error) {
	var d domain.Drive
	var sizeBytes int64
	var vmID sql.NullString
	var createdAt time.Time

	if err := s.Scan(&d.ID, &d.Name, &sizeBytes, &d.MountPath, &vmID, &createdAt); err != nil {
		return nil, err
	}
	d.SizeBytes = uint64(sizeBytes)
	d.VMID = vmID.String
	d.CreatedAt = createdAt
	return &d, nil
}

func (s *Store) scanDevice(ctx context.Context, query string, args ...any) (*domain.Device, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	d, err := scanDeviceRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return d, nil
}

func scanDeviceRow(s scanner) (*domain.Device, error) {
	var d domain.Device
	var gid int64
	var vmID sql.NullString
	var createdAt time.Time

	if err := s.Scan(&d.ID, &d.Name, &d.HostPath, &d.ContainerPath, &d.Permissions, &gid, &vmID, &createdAt); err != nil {
		return nil, err
	}
	d.GID = uint32(gid)
	d.VMID = vmID.String
	d.CreatedAt = createdAt
	return &d, nil
}

func (s *Store) scanTemplate(ctx context.Context, query string, args ...any) (*domain.Template, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	t, err := scanTemplateRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

func scanTemplateRow(s scanner) (*domain.Template, error) {
	var t domain.Template
	var createdAt, updatedAt time.Time

	if err := s.Scan(&t.ID, &t.Name, &t.Distro, &t.Script, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	t.CreatedAt = createdAt
	t.UpdatedAt = updatedAt
	return &t, nil
}

// --- SnapshotStore ---

func (s *Store) CreateSnapshot(ctx context.Context, snap *domain.Snapshot) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO snapshots (id, vm_id, name, created_at) VALUES ($1, $2, $3, $4)`,
		snap.ID, snap.VMID, snap.Name, snap.CreatedAt)
	return err
}

func (s *Store) GetSnapshot(ctx context.Context, id string) (*domain.Snapshot, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, vm_id, name, created_at FROM snapshots WHERE id = $1`, id)
	return scanSnapshotRow(row)
}

func (s *Store) GetSnapshotByName(ctx context.Context, vmID, name string) (*domain.Snapshot, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = $1 AND name = $2`,
		vmID, name)
	return scanSnapshotRow(row)
}

func (s *Store) ListSnapshots(ctx context.Context, vmID string) ([]*domain.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, vm_id, name, created_at FROM snapshots WHERE vm_id = $1 ORDER BY created_at`,
		vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.Snapshot
	for rows.Next() {
		snap, err := scanSnapshotRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, snap)
	}
	return result, rows.Err()
}

func (s *Store) DeleteSnapshot(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM snapshots WHERE id = $1`, id)
	return err
}

func scanSnapshotRow(s scanner) (*domain.Snapshot, error) {
	var snap domain.Snapshot
	var createdAt time.Time
	if err := s.Scan(&snap.ID, &snap.VMID, &snap.Name, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	snap.CreatedAt = createdAt
	return &snap, nil
}
