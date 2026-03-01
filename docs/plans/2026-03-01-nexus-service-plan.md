# Nexus Service Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Go HTTP service that wraps containerd for agent/service VM lifecycle management, with a Sharkfin webhook receiver for agent spawning.

**Architecture:** Hexagonal (Ports & Adapters). Domain types and port interfaces in `internal/domain/`, application use-cases in `internal/app/`, infrastructure adapters in `internal/infra/` (containerd, SQLite, HTTP). Dependencies always point inward — domain imports nothing from infra.

**Tech Stack:** Go 1.26, containerd v2.2.1 client, sqlc, goose v3, modernc.org/sqlite, Cobra/Viper, charmbracelet/log, stdlib net/http. Static binary (CGO_ENABLED=0).

**Directory Layout:**
```
cmd/nexusd/
  main.go               — entry point
  root.go               — Cobra root command, Viper config, logging
  daemon.go             — daemon subcommand, wiring
internal/
  config/config.go      — XDG paths, Viper defaults, env vars
  domain/
    vm.go               — VM, VMRole, VMState, CreateVMParams, ExecResult
    ports.go            — VMStore, Runtime interfaces
  app/
    vm_service.go       — use cases: CreateVM, StartVM, StopVM, DeleteVM, ListVMs, GetVM, ExecVM, HandleWebhook
    vm_service_test.go  — tests with mock ports
  infra/
    containerd/
      runtime.go        — domain.Runtime adapter wrapping containerd Go client
    sqlite/
      migrations/
        001_init.sql    — goose migration: vms table
      queries.sql       — sqlc query annotations
      db.go             — sqlc-generated (DBTX, New, Queries)
      models.go         — sqlc-generated (row types)
      queries.sql.go    — sqlc-generated (query methods)
      store.go          — domain.VMStore adapter wrapping sqlc Queries
      store_test.go     — tests with in-memory SQLite
    httpapi/
      handler.go        — HTTP routes, JSON request/response, mux setup
      handler_test.go   — tests with httptest
      webhook.go        — Sharkfin webhook receiver
      webhook_test.go   — webhook tests
sqlc.yaml               — sqlc configuration
```

**PostgreSQL:** Not in this plan. The hexagonal architecture makes it trivial to add later — implement a second `domain.VMStore` adapter in `internal/infra/postgres/` with its own migrations, queries, and sqlc target.

**Kata Runtime:** Not in this plan. The runtime handler is a config string, defaulting to `io.containerd.runc.v2`. Swap to Kata by changing config — zero code changes.

---

## Task 1: Project Scaffold

**Files:**
- Modify: `go.mod`
- Create: `cmd/nexusd/main.go`
- Create: `cmd/nexusd/root.go`
- Create: `internal/config/config.go`

### Step 1: Add dependencies to go.mod

Run:
```bash
cd /home/kazw/Work/WorkFort/nexus-go
go get github.com/spf13/cobra@latest \
       github.com/spf13/viper@latest \
       github.com/spf13/pflag@latest \
       github.com/charmbracelet/log@latest \
       modernc.org/sqlite@latest \
       github.com/pressly/goose/v3@latest \
       github.com/google/uuid@latest \
       github.com/containerd/containerd/v2@v2.2.1
```

Note: The containerd dependency pulls in gRPC, protobuf, OCI specs. This is expected.

### Step 2: Create main.go

```go
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"github.com/Work-Fort/Nexus/cmd/nexusd"
)

func main() {
	nexusd.Execute()
}
```

File: `cmd/nexusd/main.go`

### Step 3: Create root.go

```go
// SPDX-License-Identifier: Apache-2.0
package nexusd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Work-Fort/Nexus/internal/config"
)

// Version is set at build time via ldflags.
var Version string

var rootCmd = &cobra.Command{
	Use:   "nexusd",
	Short: "Nexus VM lifecycle daemon",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := config.InitDirs(); err != nil {
			return err
		}
		if err := config.LoadConfig(); err != nil {
			return err
		}

		ll := viper.GetString("log-level")
		if ll == "disabled" {
			log.SetOutput(io.Discard)
			return nil
		}

		var level log.Level
		switch ll {
		case "debug":
			level = log.DebugLevel
		case "info":
			level = log.InfoLevel
		case "warn":
			level = log.WarnLevel
		case "error":
			level = log.ErrorLevel
		default:
			level = log.DebugLevel
		}

		logFile := filepath.Join(config.GlobalPaths.StateDir, "debug.log")
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}

		logger := log.NewWithOptions(f, log.Options{
			ReportTimestamp: true,
			TimeFormat:      "2006-01-02T15:04:05.000Z07:00",
			Level:           level,
			ReportCaller:    true,
			Formatter:       log.JSONFormatter,
		})
		log.SetDefault(logger)

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func init() {
	config.InitViper()

	rootCmd.PersistentFlags().StringP("log-level", "l", "debug", "Log level: disabled, debug, info, warn, error")

	if err := config.BindFlags(rootCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	rootCmd.Version = Version
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
}
```

File: `cmd/nexusd/root.go`

### Step 4: Create config.go

```go
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	EnvPrefix          = "NEXUS"
	ConfigFileName     = "config"
	ConfigType         = "yaml"
	DefaultListenAddr  = "127.0.0.1:9600"
	DefaultSocketPath  = "/run/containerd/containerd.sock"
	DefaultRuntime     = "io.containerd.runc.v2"
	DefaultNamespace   = "nexus"
	DefaultAgentImage  = "docker.io/library/alpine:latest"
)

// Paths holds XDG-compliant directory paths.
type Paths struct {
	ConfigDir string
	StateDir  string
}

var GlobalPaths *Paths

func init() {
	GlobalPaths = GetPaths()
}

// GetPaths returns XDG-compliant directory paths.
func GetPaths() *Paths {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get home directory: %v\n", err)
			os.Exit(1)
		}
		configHome = filepath.Join(home, ".config")
	}

	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get home directory: %v\n", err)
			os.Exit(1)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}

	return &Paths{
		ConfigDir: filepath.Join(configHome, "nexus"),
		StateDir:  filepath.Join(stateHome, "nexus"),
	}
}

// InitDirs creates all necessary directories.
func InitDirs() error {
	dirs := []string{
		GlobalPaths.ConfigDir,
		GlobalPaths.StateDir,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}

// InitViper sets up viper defaults and config file search paths.
func InitViper() {
	viper.SetDefault("listen", DefaultListenAddr)
	viper.SetDefault("log-level", "debug")
	viper.SetDefault("containerd-socket", DefaultSocketPath)
	viper.SetDefault("runtime", DefaultRuntime)
	viper.SetDefault("namespace", DefaultNamespace)
	viper.SetDefault("agent-image", DefaultAgentImage)
	viper.SetDefault("webhook-url", "")

	viper.SetConfigName(ConfigFileName)
	viper.SetConfigType(ConfigType)
	viper.AddConfigPath(GlobalPaths.ConfigDir)

	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

// LoadConfig reads the config file if present.
func LoadConfig() error {
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("read config: %w", err)
	}
	return nil
}

// BindFlags binds cobra flags to viper.
func BindFlags(flags *pflag.FlagSet) error {
	flagsToBind := []string{"log-level"}
	for _, name := range flagsToBind {
		if err := viper.BindPFlag(name, flags.Lookup(name)); err != nil {
			return fmt.Errorf("bind flag %s: %w", name, err)
		}
	}
	return nil
}
```

File: `internal/config/config.go`

### Step 5: Verify compilation

Run: `go build ./cmd/nexusd`
Expected: Builds successfully, produces `nexusd` binary.

### Step 6: Commit

```bash
git add cmd/nexusd/ internal/config/ go.mod go.sum
git commit -m "feat(nexusd): scaffold project with Cobra/Viper and XDG config"
```

---

## Task 2: Domain Types and Port Interfaces

**Files:**
- Create: `internal/domain/vm.go`
- Create: `internal/domain/ports.go`

### Step 1: Write vm.go

```go
// SPDX-License-Identifier: Apache-2.0

// Package domain defines the core types and port interfaces for Nexus.
// This package has zero dependencies on infrastructure — it defines
// what the system does, not how.
package domain

import (
	"errors"
	"time"
)

// VMRole identifies what kind of workload runs in the VM.
type VMRole string

const (
	VMRoleAgent   VMRole = "agent"
	VMRoleService VMRole = "service"
)

// ValidRole returns true if r is a recognized VM role.
func ValidRole(r VMRole) bool {
	return r == VMRoleAgent || r == VMRoleService
}

// VMState represents the lifecycle state of a VM.
type VMState string

const (
	VMStateCreated VMState = "created"
	VMStateRunning VMState = "running"
	VMStateStopped VMState = "stopped"
)

// VM represents a managed virtual machine / container.
type VM struct {
	ID        string
	Name      string
	Role      VMRole
	State     VMState
	Image     string
	Runtime   string
	CreatedAt time.Time
	StartedAt *time.Time
	StoppedAt *time.Time
}

// CreateVMParams holds parameters for creating a new VM.
type CreateVMParams struct {
	Name    string
	Role    VMRole
	Image   string
	Runtime string
}

// ExecResult holds the output of a command executed inside a VM.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// VMFilter constrains VM list queries.
type VMFilter struct {
	Role *VMRole
}

// Sentinel errors.
var (
	ErrNotFound     = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidState = errors.New("invalid state transition")
)
```

File: `internal/domain/vm.go`

### Step 2: Write ports.go

```go
// SPDX-License-Identifier: Apache-2.0
package domain

import "context"

// VMStore persists VM metadata. Implementations live in internal/infra/.
type VMStore interface {
	Create(ctx context.Context, vm *VM) error
	Get(ctx context.Context, id string) (*VM, error)
	List(ctx context.Context, filter VMFilter) ([]*VM, error)
	GetByName(ctx context.Context, name string) (*VM, error)
	UpdateState(ctx context.Context, id string, state VMState, now time.Time) error
	Delete(ctx context.Context, id string) error
}

// Runtime manages the container/VM lifecycle. Implementations live in
// internal/infra/.
type Runtime interface {
	Create(ctx context.Context, id, image, runtimeHandler string) error
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	Exec(ctx context.Context, id string, cmd []string) (*ExecResult, error)
}
```

File: `internal/domain/ports.go`

### Step 3: Verify compilation

Run: `go build ./internal/domain/`
Expected: Compiles cleanly.

### Step 4: Commit

```bash
git add internal/domain/
git commit -m "feat(domain): add VM types and port interfaces"
```

---

## Task 3: SQLite Schema and sqlc Code Generation

**Files:**
- Create: `internal/infra/sqlite/migrations/001_init.sql`
- Create: `sqlc.yaml`
- Create: `internal/infra/sqlite/queries.sql`
- Generated: `internal/infra/sqlite/db.go`, `models.go`, `queries.sql.go`

### Step 1: Write the migration

```sql
-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
CREATE TABLE vms (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('agent', 'service')),
    image      TEXT NOT NULL,
    runtime    TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'created' CHECK (state IN ('created', 'running', 'stopped')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    started_at TEXT,
    stopped_at TEXT
);

CREATE INDEX idx_vms_role ON vms(role);
CREATE INDEX idx_vms_state ON vms(state);
CREATE UNIQUE INDEX idx_vms_name ON vms(name);

-- +goose Down
DROP INDEX IF EXISTS idx_vms_name;
DROP INDEX IF EXISTS idx_vms_state;
DROP INDEX IF EXISTS idx_vms_role;
DROP TABLE IF EXISTS vms;
```

File: `internal/infra/sqlite/migrations/001_init.sql`

Note: Timestamps stored as ISO 8601 TEXT (`strftime` default). SQLite has no native datetime type.

### Step 2: Create sqlc.yaml

```yaml
version: "2"
sql:
  - engine: "sqlite"
    queries: "internal/infra/sqlite/queries.sql"
    schema: "internal/infra/sqlite/migrations"
    gen:
      go:
        package: "sqlite"
        out: "internal/infra/sqlite"
        emit_json_tags: true
        emit_empty_slices: true
```

File: `sqlc.yaml` (project root)

### Step 3: Write queries.sql

```sql
-- SPDX-License-Identifier: Apache-2.0

-- name: InsertVM :exec
INSERT INTO vms (id, name, role, image, runtime, state, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetVM :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
FROM vms WHERE id = ?;

-- name: GetVMByName :one
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
FROM vms WHERE name = ?;

-- name: ListVMs :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
FROM vms ORDER BY created_at DESC;

-- name: ListVMsByRole :many
SELECT id, name, role, image, runtime, state, created_at, started_at, stopped_at
FROM vms WHERE role = ? ORDER BY created_at DESC;

-- name: UpdateVMStateCreated :exec
UPDATE vms SET state = 'created', started_at = NULL, stopped_at = NULL WHERE id = ?;

-- name: UpdateVMStarted :exec
UPDATE vms SET state = 'running', started_at = ? WHERE id = ?;

-- name: UpdateVMStopped :exec
UPDATE vms SET state = 'stopped', stopped_at = ? WHERE id = ?;

-- name: DeleteVM :exec
DELETE FROM vms WHERE id = ?;

-- name: CountVMs :one
SELECT COUNT(*) FROM vms;
```

File: `internal/infra/sqlite/queries.sql`

### Step 4: Install sqlc and generate code

Run:
```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
sqlc generate
```
Expected: Creates `internal/infra/sqlite/db.go`, `models.go`, `queries.sql.go`.

### Step 5: Verify generated code compiles

Run: `go build ./internal/infra/sqlite/`
Expected: Compiles cleanly.

### Step 6: Commit

```bash
git add sqlc.yaml internal/infra/sqlite/
git commit -m "feat(sqlite): add schema migration and sqlc queries"
```

---

## Task 4: SQLite VMStore Adapter

**Files:**
- Create: `internal/infra/sqlite/store.go`
- Create: `internal/infra/sqlite/store_test.go`

### Step 1: Write failing tests

```go
// SPDX-License-Identifier: Apache-2.0
package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
)

func openTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestStoreCreateAndGet(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	vm := &domain.VM{
		ID:        "vm-001",
		Name:      "test-agent",
		Role:      domain.VMRoleAgent,
		State:     domain.VMStateCreated,
		Image:     "alpine:latest",
		Runtime:   "io.containerd.runc.v2",
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	if err := store.Create(ctx, vm); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.Get(ctx, "vm-001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if got.Name != "test-agent" {
		t.Errorf("name = %q, want %q", got.Name, "test-agent")
	}
	if got.Role != domain.VMRoleAgent {
		t.Errorf("role = %q, want %q", got.Role, domain.VMRoleAgent)
	}
	if got.State != domain.VMStateCreated {
		t.Errorf("state = %q, want %q", got.State, domain.VMStateCreated)
	}
}

func TestStoreGetNotFound(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if err != domain.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestStoreGetByName(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	vm := &domain.VM{
		ID:        "vm-002",
		Name:      "deploy-agent",
		Role:      domain.VMRoleAgent,
		State:     domain.VMStateCreated,
		Image:     "alpine:latest",
		Runtime:   "io.containerd.runc.v2",
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	store.Create(ctx, vm)

	got, err := store.GetByName(ctx, "deploy-agent")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got.ID != "vm-002" {
		t.Errorf("id = %q, want %q", got.ID, "vm-002")
	}
}

func TestStoreList(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	store.Create(ctx, &domain.VM{ID: "a1", Name: "agent-1", Role: domain.VMRoleAgent, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", CreatedAt: now})
	store.Create(ctx, &domain.VM{ID: "s1", Name: "svc-1", Role: domain.VMRoleService, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", CreatedAt: now})

	// List all
	vms, err := store.List(ctx, domain.VMFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("list count = %d, want 2", len(vms))
	}

	// List by role
	agentRole := domain.VMRoleAgent
	vms, err = store.List(ctx, domain.VMFilter{Role: &agentRole})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(vms) != 1 {
		t.Fatalf("agent count = %d, want 1", len(vms))
	}
	if vms[0].Name != "agent-1" {
		t.Errorf("name = %q, want %q", vms[0].Name, "agent-1")
	}
}

func TestStoreUpdateState(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	store.Create(ctx, &domain.VM{ID: "vm-1", Name: "test", Role: domain.VMRoleAgent, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", CreatedAt: now})

	// Start
	startTime := now.Add(time.Second)
	if err := store.UpdateState(ctx, "vm-1", domain.VMStateRunning, startTime); err != nil {
		t.Fatalf("update to running: %v", err)
	}
	got, _ := store.Get(ctx, "vm-1")
	if got.State != domain.VMStateRunning {
		t.Errorf("state = %q, want running", got.State)
	}
	if got.StartedAt == nil {
		t.Fatal("started_at is nil")
	}

	// Stop
	stopTime := now.Add(2 * time.Second)
	if err := store.UpdateState(ctx, "vm-1", domain.VMStateStopped, stopTime); err != nil {
		t.Fatalf("update to stopped: %v", err)
	}
	got, _ = store.Get(ctx, "vm-1")
	if got.State != domain.VMStateStopped {
		t.Errorf("state = %q, want stopped", got.State)
	}
	if got.StoppedAt == nil {
		t.Fatal("stopped_at is nil")
	}
}

func TestStoreDelete(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	store.Create(ctx, &domain.VM{ID: "vm-del", Name: "deleteme", Role: domain.VMRoleAgent, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", CreatedAt: now})

	if err := store.Delete(ctx, "vm-del"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get(ctx, "vm-del")
	if err != domain.ErrNotFound {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
}
```

File: `internal/infra/sqlite/store_test.go`

### Step 2: Run tests to verify they fail

Run: `go test ./internal/infra/sqlite/ -v`
Expected: FAIL — `Store` type not defined.

### Step 3: Write store.go

```go
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
	return rowToVM(row), nil
}

func (s *Store) GetByName(ctx context.Context, name string) (*domain.VM, error) {
	row, err := s.q.GetVMByName(ctx, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get vm by name: %w", err)
	}
	return rowToVM(row), nil
}

func (s *Store) List(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	if filter.Role != nil {
		rows, err := s.q.ListVMsByRole(ctx, string(*filter.Role))
		if err != nil {
			return nil, fmt.Errorf("list vms by role: %w", err)
		}
		return rowsToVMs(rows), nil
	}
	rows, err := s.q.ListVMs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vms: %w", err)
	}
	return rowsToVMs(rows), nil
}

func (s *Store) UpdateState(ctx context.Context, id string, state domain.VMState, now time.Time) error {
	ts := now.UTC().Format(timeFormat)
	switch state {
	case domain.VMStateRunning:
		return s.q.UpdateVMStarted(ctx, UpdateVMStartedParams{StartedAt: &ts, ID: id})
	case domain.VMStateStopped:
		return s.q.UpdateVMStopped(ctx, UpdateVMStoppedParams{StoppedAt: &ts, ID: id})
	case domain.VMStateCreated:
		return s.q.UpdateVMStateCreated(ctx, id)
	default:
		return fmt.Errorf("unknown state: %s", state)
	}
}

func (s *Store) Delete(ctx context.Context, id string) error {
	return s.q.DeleteVM(ctx, id)
}

// --- type conversion helpers ---

func rowToVM(row GetVMRow) *domain.VM {
	vm := &domain.VM{
		ID:      row.ID,
		Name:    row.Name,
		Role:    domain.VMRole(row.Role),
		State:   domain.VMState(row.State),
		Image:   row.Image,
		Runtime: row.Runtime,
	}
	vm.CreatedAt, _ = time.Parse(timeFormat, row.CreatedAt)
	if row.StartedAt != nil {
		t, _ := time.Parse(timeFormat, *row.StartedAt)
		vm.StartedAt = &t
	}
	if row.StoppedAt != nil {
		t, _ := time.Parse(timeFormat, *row.StoppedAt)
		vm.StoppedAt = &t
	}
	return vm
}

func rowsToVMs[R interface{ toGetVMRow() GetVMRow }](rows []R) []*domain.VM {
	vms := make([]*domain.VM, len(rows))
	for i, r := range rows {
		row := r.toGetVMRow()
		vms[i] = rowToVM(row)
	}
	return vms
}
```

File: `internal/infra/sqlite/store.go`

**Important:** The `rowsToVMs` generic helper depends on sqlc generating compatible row types. If `ListVMs` and `ListVMsByRole` generate different row types with the same fields, you may need to convert them individually instead. Adjust after seeing the actual sqlc output — the pattern is:

```go
// Fallback if generic helper doesn't work with sqlc-generated types:
func listRowsToVMs(rows []ListVMsRow) []*domain.VM {
	vms := make([]*domain.VM, len(rows))
	for i, r := range rows {
		vms[i] = rowToVM(GetVMRow(r))
	}
	return vms
}
```

### Step 4: Run tests to verify they pass

Run: `go test ./internal/infra/sqlite/ -v`
Expected: All 6 tests PASS.

### Step 5: Commit

```bash
git add internal/infra/sqlite/
git commit -m "feat(sqlite): implement VMStore adapter with sqlc"
```

---

## Task 5: containerd Runtime Adapter

**Files:**
- Create: `internal/infra/containerd/runtime.go`
- Create: `internal/infra/containerd/runtime_test.go`

### Step 1: Write runtime.go

```go
// SPDX-License-Identifier: Apache-2.0

// Package containerd implements domain.Runtime using the containerd Go client.
package containerd

import (
	"bytes"
	"context"
	"fmt"
	"syscall"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// Runtime implements domain.Runtime backed by containerd.
type Runtime struct {
	client    *client.Client
	namespace string
}

// New connects to containerd at the given socket path.
func New(socketPath, namespace string) (*Runtime, error) {
	c, err := client.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd: %w", err)
	}
	return &Runtime{client: c, namespace: namespace}, nil
}

// Close closes the containerd connection.
func (r *Runtime) Close() error {
	return r.client.Close()
}

func (r *Runtime) nsCtx(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, r.namespace)
}

func (r *Runtime) Create(ctx context.Context, id, image, runtimeHandler string) error {
	ctx = r.nsCtx(ctx)

	img, err := r.client.Pull(ctx, image, client.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("pull image %s: %w", image, err)
	}

	_, err = r.client.NewContainer(ctx, id,
		client.WithImage(img),
		client.WithNewSnapshot(id+"-snap", img),
		client.WithRuntime(runtimeHandler, nil),
		client.WithNewSpec(oci.WithImageConfig(img)),
	)
	if err != nil {
		return fmt.Errorf("create container %s: %w", id, err)
	}
	return nil
}

func (r *Runtime) Start(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return fmt.Errorf("create task %s: %w", id, err)
	}

	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("start task %s: %w", id, err)
	}
	return nil
}

func (r *Runtime) Stop(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return fmt.Errorf("get task %s: %w", id, err)
	}

	if err := task.Kill(ctx, syscall.SIGTERM); err != nil {
		return fmt.Errorf("kill task %s: %w", id, err)
	}

	ch, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("wait task %s: %w", id, err)
	}
	<-ch

	if _, err := task.Delete(ctx); err != nil {
		return fmt.Errorf("delete task %s: %w", id, err)
	}
	return nil
}

func (r *Runtime) Delete(ctx context.Context, id string) error {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return fmt.Errorf("load container %s: %w", id, err)
	}

	return container.Delete(ctx, client.WithSnapshotCleanup)
}

func (r *Runtime) Exec(ctx context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	ctx = r.nsCtx(ctx)

	container, err := r.client.LoadContainer(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("load container %s: %w", id, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get task %s: %w", id, err)
	}

	var stdout, stderr bytes.Buffer
	pspec := oci.WithProcessArgs(cmd...)

	spec, err := container.Spec(ctx)
	if err != nil {
		return nil, fmt.Errorf("get spec %s: %w", id, err)
	}
	pspec(ctx, nil, spec, spec.Process)

	execID := id + "-exec"
	proc, err := task.Exec(ctx, execID, spec.Process,
		cio.NewCreator(cio.WithStreams(nil, &stdout, &stderr)),
	)
	if err != nil {
		return nil, fmt.Errorf("exec in %s: %w", id, err)
	}

	if err := proc.Start(ctx); err != nil {
		return nil, fmt.Errorf("start exec %s: %w", id, err)
	}

	ch, err := proc.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("wait exec %s: %w", id, err)
	}
	status := <-ch

	proc.Delete(ctx)

	return &domain.ExecResult{
		ExitCode: int(status.ExitCode()),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}, nil
}
```

File: `internal/infra/containerd/runtime.go`

**Note:** The exact containerd v2 import paths and API may need adjustment after `go get`. The key patterns are correct — the details depend on the containerd v2.2.1 module layout. If imports fail, check the containerd v2 Go docs and adjust paths.

### Step 2: Write interface compliance test

```go
// SPDX-License-Identifier: Apache-2.0
package containerd

import (
	"github.com/Work-Fort/Nexus/internal/domain"
)

// Compile-time interface compliance check.
var _ domain.Runtime = (*Runtime)(nil)
```

File: `internal/infra/containerd/runtime_test.go`

### Step 3: Verify compilation

Run: `go build ./internal/infra/containerd/`
Expected: Compiles. If containerd import paths need adjustment, fix them here.

### Step 4: Commit

```bash
git add internal/infra/containerd/
git commit -m "feat(containerd): implement Runtime adapter"
```

---

## Task 6: Application Service

**Files:**
- Create: `internal/app/vm_service.go`
- Create: `internal/app/vm_service_test.go`

### Step 1: Write failing tests

```go
// SPDX-License-Identifier: Apache-2.0
package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
)

// --- mock VMStore ---

type mockStore struct {
	vms map[string]*domain.VM
}

func newMockStore() *mockStore {
	return &mockStore{vms: make(map[string]*domain.VM)}
}

func (m *mockStore) Create(_ context.Context, vm *domain.VM) error {
	if _, ok := m.vms[vm.ID]; ok {
		return domain.ErrAlreadyExists
	}
	m.vms[vm.ID] = vm
	return nil
}

func (m *mockStore) Get(_ context.Context, id string) (*domain.VM, error) {
	vm, ok := m.vms[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return vm, nil
}

func (m *mockStore) GetByName(_ context.Context, name string) (*domain.VM, error) {
	for _, vm := range m.vms {
		if vm.Name == name {
			return vm, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockStore) List(_ context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	var result []*domain.VM
	for _, vm := range m.vms {
		if filter.Role != nil && vm.Role != *filter.Role {
			continue
		}
		result = append(result, vm)
	}
	return result, nil
}

func (m *mockStore) UpdateState(_ context.Context, id string, state domain.VMState, now time.Time) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.State = state
	switch state {
	case domain.VMStateRunning:
		vm.StartedAt = &now
	case domain.VMStateStopped:
		vm.StoppedAt = &now
	}
	return nil
}

func (m *mockStore) Delete(_ context.Context, id string) error {
	delete(m.vms, id)
	return nil
}

// --- mock Runtime ---

type mockRuntime struct {
	containers map[string]bool // id -> running
}

func newMockRuntime() *mockRuntime {
	return &mockRuntime{containers: make(map[string]bool)}
}

func (m *mockRuntime) Create(_ context.Context, id, image, runtime string) error {
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) Start(_ context.Context, id string) error {
	m.containers[id] = true
	return nil
}

func (m *mockRuntime) Stop(_ context.Context, id string) error {
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) Delete(_ context.Context, id string) error {
	delete(m.containers, id)
	return nil
}

func (m *mockRuntime) Exec(_ context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	return &domain.ExecResult{ExitCode: 0, Stdout: "ok\n"}, nil
}

// --- tests ---

func TestCreateVM(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name:    "test-agent",
		Role:    domain.VMRoleAgent,
		Image:   "alpine:latest",
		Runtime: "io.containerd.runc.v2",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if vm.Name != "test-agent" {
		t.Errorf("name = %q, want %q", vm.Name, "test-agent")
	}
	if vm.State != domain.VMStateCreated {
		t.Errorf("state = %q, want created", vm.State)
	}
	if vm.ID == "" {
		t.Error("id is empty")
	}

	// Verify container was created in runtime
	if _, ok := rt.containers[vm.ID]; !ok {
		t.Error("container not created in runtime")
	}

	// Verify VM persisted in store
	got, err := store.Get(context.Background(), vm.ID)
	if err != nil {
		t.Fatalf("store get: %v", err)
	}
	if got.Name != "test-agent" {
		t.Errorf("stored name = %q, want %q", got.Name, "test-agent")
	}
}

func TestCreateVMInvalidRole(t *testing.T) {
	svc := app.NewVMService(newMockStore(), newMockRuntime())

	_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "bad", Role: "invalid", Image: "alpine:latest", Runtime: "runc",
	})
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestStartVM(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "start-me", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	if err := svc.StartVM(context.Background(), vm.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	got, _ := store.Get(context.Background(), vm.ID)
	if got.State != domain.VMStateRunning {
		t.Errorf("state = %q, want running", got.State)
	}
}

func TestStartVMAlreadyRunning(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "running", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	err := svc.StartVM(context.Background(), vm.ID)
	if err != domain.ErrInvalidState {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}

func TestStopVM(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "stop-me", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	if err := svc.StopVM(context.Background(), vm.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}

	got, _ := store.Get(context.Background(), vm.ID)
	if got.State != domain.VMStateStopped {
		t.Errorf("state = %q, want stopped", got.State)
	}
}

func TestDeleteVM(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "delete-me", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	if err := svc.DeleteVM(context.Background(), vm.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get(context.Background(), vm.ID)
	if err != domain.ErrNotFound {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
	if _, ok := rt.containers[vm.ID]; ok {
		t.Error("container still in runtime after delete")
	}
}

func TestListVMs(t *testing.T) {
	store := newMockStore()
	svc := app.NewVMService(store, newMockRuntime())

	svc.CreateVM(context.Background(), domain.CreateVMParams{Name: "a1", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc"})
	svc.CreateVM(context.Background(), domain.CreateVMParams{Name: "s1", Role: domain.VMRoleService, Image: "alpine:latest", Runtime: "runc"})

	vms, err := svc.ListVMs(context.Background(), domain.VMFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(vms) != 2 {
		t.Errorf("count = %d, want 2", len(vms))
	}
}

func TestGetVM(t *testing.T) {
	store := newMockStore()
	svc := app.NewVMService(store, newMockRuntime())

	created, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "get-me", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	got, err := svc.GetVM(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "get-me" {
		t.Errorf("name = %q, want %q", got.Name, "get-me")
	}
}

func TestHandleWebhookCreatesAgent(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	webhook := app.SharkfinWebhook{
		Event:     "message.new",
		Recipient: "deploy-bot",
		Channel:   "ops",
		From:      "dev-agent",
		MessageID: 42,
	}

	if err := svc.HandleWebhook(context.Background(), webhook); err != nil {
		t.Fatalf("webhook: %v", err)
	}

	// Should have created and started a VM named "deploy-bot"
	vm, err := store.GetByName(context.Background(), "deploy-bot")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if vm.Role != domain.VMRoleAgent {
		t.Errorf("role = %q, want agent", vm.Role)
	}
	if vm.State != domain.VMStateRunning {
		t.Errorf("state = %q, want running", vm.State)
	}
}

func TestHandleWebhookStartsExistingStopped(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	// Create and stop an agent
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "existing-bot", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)
	svc.StopVM(context.Background(), vm.ID)

	webhook := app.SharkfinWebhook{
		Event:     "message.new",
		Recipient: "existing-bot",
	}

	if err := svc.HandleWebhook(context.Background(), webhook); err != nil {
		t.Fatalf("webhook: %v", err)
	}

	got, _ := store.Get(context.Background(), vm.ID)
	if got.State != domain.VMStateRunning {
		t.Errorf("state = %q, want running", got.State)
	}
}

func TestHandleWebhookNoopIfRunning(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "active-bot", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	webhook := app.SharkfinWebhook{
		Event:     "message.new",
		Recipient: "active-bot",
	}

	if err := svc.HandleWebhook(context.Background(), webhook); err != nil {
		t.Fatalf("webhook: %v", err)
	}

	// Should still be running, no error
	got, _ := store.Get(context.Background(), vm.ID)
	if got.State != domain.VMStateRunning {
		t.Errorf("state = %q, want running", got.State)
	}
}
```

File: `internal/app/vm_service_test.go`

### Step 2: Run tests to verify they fail

Run: `go test ./internal/app/ -v`
Expected: FAIL — `app.NewVMService` not defined.

### Step 3: Write vm_service.go

```go
// SPDX-License-Identifier: Apache-2.0

// Package app contains application use-cases that orchestrate domain ports.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/charmbracelet/log"
	"github.com/google/uuid"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// SharkfinWebhook is the payload Sharkfin POSTs on mentions and DMs.
type SharkfinWebhook struct {
	Event       string `json:"event"`
	Recipient   string `json:"recipient"`
	Channel     string `json:"channel"`
	ChannelType string `json:"channel_type"`
	From        string `json:"from"`
	MessageID   int64  `json:"message_id"`
	SentAt      string `json:"sent_at"`
}

// VMServiceConfig holds configurable defaults for the VM service.
type VMServiceConfig struct {
	DefaultImage   string
	DefaultRuntime string
}

// VMService orchestrates VM lifecycle operations.
type VMService struct {
	store   domain.VMStore
	runtime domain.Runtime
	config  VMServiceConfig
}

// NewVMService creates a VMService with the given ports and config.
func NewVMService(store domain.VMStore, runtime domain.Runtime, opts ...func(*VMService)) *VMService {
	svc := &VMService{
		store:   store,
		runtime: runtime,
		config: VMServiceConfig{
			DefaultImage:   "docker.io/library/alpine:latest",
			DefaultRuntime: "io.containerd.runc.v2",
		},
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// WithConfig sets the VMService configuration.
func WithConfig(cfg VMServiceConfig) func(*VMService) {
	return func(s *VMService) {
		s.config = cfg
	}
}

func (s *VMService) CreateVM(ctx context.Context, params domain.CreateVMParams) (*domain.VM, error) {
	if !domain.ValidRole(params.Role) {
		return nil, fmt.Errorf("invalid role %q: %w", params.Role, errors.New("validation error"))
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", errors.New("validation error"))
	}
	if params.Image == "" {
		params.Image = s.config.DefaultImage
	}
	if params.Runtime == "" {
		params.Runtime = s.config.DefaultRuntime
	}

	vm := &domain.VM{
		ID:        uuid.New().String(),
		Name:      params.Name,
		Role:      params.Role,
		State:     domain.VMStateCreated,
		Image:     params.Image,
		Runtime:   params.Runtime,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime); err != nil {
		return nil, fmt.Errorf("runtime create: %w", err)
	}

	if err := s.store.Create(ctx, vm); err != nil {
		// Best-effort cleanup of the container we just created.
		s.runtime.Delete(ctx, vm.ID)
		return nil, fmt.Errorf("store create: %w", err)
	}

	log.Info("vm created", "id", vm.ID, "name", vm.Name, "role", vm.Role)
	return vm, nil
}

func (s *VMService) GetVM(ctx context.Context, id string) (*domain.VM, error) {
	return s.store.Get(ctx, id)
}

func (s *VMService) ListVMs(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	return s.store.List(ctx, filter)
}

func (s *VMService) StartVM(ctx context.Context, id string) error {
	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}

	if vm.State == domain.VMStateRunning {
		return domain.ErrInvalidState
	}

	if err := s.runtime.Start(ctx, id); err != nil {
		return fmt.Errorf("runtime start: %w", err)
	}

	if err := s.store.UpdateState(ctx, id, domain.VMStateRunning, time.Now().UTC()); err != nil {
		return fmt.Errorf("store update: %w", err)
	}

	log.Info("vm started", "id", id)
	return nil
}

func (s *VMService) StopVM(ctx context.Context, id string) error {
	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}

	if vm.State != domain.VMStateRunning {
		return domain.ErrInvalidState
	}

	if err := s.runtime.Stop(ctx, id); err != nil {
		return fmt.Errorf("runtime stop: %w", err)
	}

	if err := s.store.UpdateState(ctx, id, domain.VMStateStopped, time.Now().UTC()); err != nil {
		return fmt.Errorf("store update: %w", err)
	}

	log.Info("vm stopped", "id", id)
	return nil
}

func (s *VMService) DeleteVM(ctx context.Context, id string) error {
	// Delete from runtime first (may fail if container doesn't exist, that's ok).
	if err := s.runtime.Delete(ctx, id); err != nil {
		log.Warn("runtime delete failed", "id", id, "err", err)
	}

	if err := s.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("store delete: %w", err)
	}

	log.Info("vm deleted", "id", id)
	return nil
}

func (s *VMService) ExecVM(ctx context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	return s.runtime.Exec(ctx, id, cmd)
}

// HandleWebhook processes a Sharkfin webhook. It finds or creates an agent
// VM for the recipient, and ensures it's running.
func (s *VMService) HandleWebhook(ctx context.Context, wh SharkfinWebhook) error {
	log.Info("webhook received", "event", wh.Event, "recipient", wh.Recipient, "from", wh.From, "channel", wh.Channel)

	vm, err := s.store.GetByName(ctx, wh.Recipient)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("lookup recipient: %w", err)
	}

	if vm == nil {
		// Create a new agent VM for this recipient.
		vm, err = s.CreateVM(ctx, domain.CreateVMParams{
			Name:  wh.Recipient,
			Role:  domain.VMRoleAgent,
			Image: s.config.DefaultImage,
		})
		if err != nil {
			return fmt.Errorf("create agent: %w", err)
		}
	}

	switch vm.State {
	case domain.VMStateRunning:
		log.Info("agent already running", "name", wh.Recipient)
		return nil
	case domain.VMStateCreated, domain.VMStateStopped:
		if err := s.StartVM(ctx, vm.ID); err != nil {
			return fmt.Errorf("start agent: %w", err)
		}
		log.Info("agent started", "name", wh.Recipient)
		return nil
	default:
		return fmt.Errorf("unexpected state %q for %s", vm.State, wh.Recipient)
	}
}
```

File: `internal/app/vm_service.go`

### Step 4: Run tests to verify they pass

Run: `go test ./internal/app/ -v`
Expected: All 10 tests PASS.

### Step 5: Commit

```bash
git add internal/app/
git commit -m "feat(app): implement VM service with webhook handler"
```

---

## Task 7: HTTP API Handlers

**Files:**
- Create: `internal/infra/httpapi/handler.go`
- Create: `internal/infra/httpapi/handler_test.go`
- Create: `internal/infra/httpapi/webhook.go`
- Create: `internal/infra/httpapi/webhook_test.go`

**API Endpoints:**
```
POST   /v1/vms             — create VM
GET    /v1/vms             — list VMs (?role=agent|service)
GET    /v1/vms/{id}        — get VM
DELETE /v1/vms/{id}        — delete VM
POST   /v1/vms/{id}/start  — start VM
POST   /v1/vms/{id}/stop   — stop VM
POST   /v1/vms/{id}/exec   — exec in VM
POST   /webhooks/sharkfin  — Sharkfin webhook receiver
```

### Step 1: Write handler tests

```go
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/httpapi"
)

// --- mock VMStore (same as app tests) ---

type mockStore struct {
	vms map[string]*domain.VM
}

func newMockStore() *mockStore {
	return &mockStore{vms: make(map[string]*domain.VM)}
}

func (m *mockStore) Create(_ context.Context, vm *domain.VM) error {
	if _, ok := m.vms[vm.ID]; ok {
		return domain.ErrAlreadyExists
	}
	m.vms[vm.ID] = vm
	return nil
}

func (m *mockStore) Get(_ context.Context, id string) (*domain.VM, error) {
	vm, ok := m.vms[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return vm, nil
}

func (m *mockStore) GetByName(_ context.Context, name string) (*domain.VM, error) {
	for _, vm := range m.vms {
		if vm.Name == name {
			return vm, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockStore) List(_ context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	var result []*domain.VM
	for _, vm := range m.vms {
		if filter.Role != nil && vm.Role != *filter.Role {
			continue
		}
		result = append(result, vm)
	}
	if result == nil {
		result = []*domain.VM{}
	}
	return result, nil
}

func (m *mockStore) UpdateState(_ context.Context, id string, state domain.VMState, now time.Time) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.State = state
	return nil
}

func (m *mockStore) Delete(_ context.Context, id string) error {
	delete(m.vms, id)
	return nil
}

// --- mock Runtime ---

type mockRuntime struct {
	containers map[string]bool
}

func newMockRuntime() *mockRuntime {
	return &mockRuntime{containers: make(map[string]bool)}
}

func (m *mockRuntime) Create(_ context.Context, id, image, runtime string) error {
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) Start(_ context.Context, id string) error {
	m.containers[id] = true
	return nil
}

func (m *mockRuntime) Stop(_ context.Context, id string) error {
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) Delete(_ context.Context, id string) error {
	delete(m.containers, id)
	return nil
}

func (m *mockRuntime) Exec(_ context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	return &domain.ExecResult{ExitCode: 0, Stdout: "ok\n"}, nil
}

// --- helpers ---

func setupHandler() http.Handler {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)
	return httpapi.NewHandler(svc)
}

// --- tests ---

func TestCreateVM(t *testing.T) {
	h := setupHandler()

	body, _ := json.Marshal(map[string]string{
		"name":  "test-agent",
		"role":  "agent",
		"image": "alpine:latest",
	})

	req := httptest.NewRequest("POST", "/v1/vms", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["name"] != "test-agent" {
		t.Errorf("name = %v, want test-agent", resp["name"])
	}
	if resp["id"] == nil || resp["id"] == "" {
		t.Error("id is empty")
	}
}

func TestListVMsEmpty(t *testing.T) {
	h := setupHandler()

	req := httptest.NewRequest("GET", "/v1/vms", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp) != 0 {
		t.Errorf("count = %d, want 0", len(resp))
	}
}

func TestGetVMNotFound(t *testing.T) {
	h := setupHandler()

	req := httptest.NewRequest("GET", "/v1/vms/nonexistent", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestStartAndStopVM(t *testing.T) {
	h := setupHandler()

	// Create
	body, _ := json.Marshal(map[string]string{"name": "lifecycle", "role": "agent", "image": "alpine:latest"})
	req := httptest.NewRequest("POST", "/v1/vms", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	// Start
	req = httptest.NewRequest("POST", "/v1/vms/"+id+"/start", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("start status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Stop
	req = httptest.NewRequest("POST", "/v1/vms/"+id+"/stop", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("stop status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

func TestDeleteVM(t *testing.T) {
	h := setupHandler()

	// Create
	body, _ := json.Marshal(map[string]string{"name": "delete-me", "role": "service", "image": "alpine:latest"})
	req := httptest.NewRequest("POST", "/v1/vms", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	// Delete
	req = httptest.NewRequest("DELETE", "/v1/vms/"+id, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Verify gone
	req = httptest.NewRequest("GET", "/v1/vms/"+id, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("after delete status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
```

File: `internal/infra/httpapi/handler_test.go`

### Step 2: Write webhook tests

```go
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookCreatesAndStartsAgent(t *testing.T) {
	h := setupHandler()

	body, _ := json.Marshal(map[string]any{
		"event":     "message.new",
		"recipient": "deploy-bot",
		"channel":   "ops",
		"from":      "developer",
		"message_id": 42,
	})

	req := httptest.NewRequest("POST", "/webhooks/sharkfin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestWebhookBadJSON(t *testing.T) {
	h := setupHandler()

	req := httptest.NewRequest("POST", "/webhooks/sharkfin", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
```

File: `internal/infra/httpapi/webhook_test.go`

### Step 3: Run tests to verify they fail

Run: `go test ./internal/infra/httpapi/ -v`
Expected: FAIL — `httpapi.NewHandler` not defined.

### Step 4: Write handler.go

```go
// SPDX-License-Identifier: Apache-2.0

// Package httpapi implements the Nexus HTTP API.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
)

// NewHandler returns an http.Handler with all Nexus API routes.
func NewHandler(svc *app.VMService) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/vms", handleCreateVM(svc))
	mux.HandleFunc("GET /v1/vms", handleListVMs(svc))
	mux.HandleFunc("GET /v1/vms/{id}", handleGetVM(svc))
	mux.HandleFunc("DELETE /v1/vms/{id}", handleDeleteVM(svc))
	mux.HandleFunc("POST /v1/vms/{id}/start", handleStartVM(svc))
	mux.HandleFunc("POST /v1/vms/{id}/stop", handleStopVM(svc))
	mux.HandleFunc("POST /v1/vms/{id}/exec", handleExecVM(svc))
	mux.HandleFunc("POST /webhooks/sharkfin", handleSharkfinWebhook(svc))

	return mux
}

// --- request/response types ---

type createVMRequest struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Image   string `json:"image"`
	Runtime string `json:"runtime"`
}

type vmResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Role      string  `json:"role"`
	State     string  `json:"state"`
	Image     string  `json:"image"`
	Runtime   string  `json:"runtime"`
	CreatedAt string  `json:"created_at"`
	StartedAt *string `json:"started_at,omitempty"`
	StoppedAt *string `json:"stopped_at,omitempty"`
}

type execRequest struct {
	Cmd []string `json:"cmd"`
}

type execResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func mapError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, domain.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "already exists")
	case errors.Is(err, domain.ErrInvalidState):
		writeError(w, http.StatusConflict, "invalid state transition")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func vmToResponse(vm *domain.VM) vmResponse {
	const tf = "2006-01-02T15:04:05.000Z"
	r := vmResponse{
		ID:        vm.ID,
		Name:      vm.Name,
		Role:      string(vm.Role),
		State:     string(vm.State),
		Image:     vm.Image,
		Runtime:   vm.Runtime,
		CreatedAt: vm.CreatedAt.UTC().Format(tf),
	}
	if vm.StartedAt != nil {
		s := vm.StartedAt.UTC().Format(tf)
		r.StartedAt = &s
	}
	if vm.StoppedAt != nil {
		s := vm.StoppedAt.UTC().Format(tf)
		r.StoppedAt = &s
	}
	return r
}

// --- handlers ---

func handleCreateVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createVMRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		vm, err := svc.CreateVM(r.Context(), domain.CreateVMParams{
			Name:    req.Name,
			Role:    domain.VMRole(req.Role),
			Image:   req.Image,
			Runtime: req.Runtime,
		})
		if err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, vmToResponse(vm))
	}
}

func handleListVMs(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var filter domain.VMFilter
		if role := r.URL.Query().Get("role"); role != "" {
			vmRole := domain.VMRole(role)
			filter.Role = &vmRole
		}

		vms, err := svc.ListVMs(r.Context(), filter)
		if err != nil {
			mapError(w, err)
			return
		}

		resp := make([]vmResponse, len(vms))
		for i, vm := range vms {
			resp[i] = vmToResponse(vm)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		vm, err := svc.GetVM(r.Context(), id)
		if err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, vmToResponse(vm))
	}
}

func handleDeleteVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DeleteVM(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleStartVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.StartVM(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleStopVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.StopVM(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleExecVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var req execRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		result, err := svc.ExecVM(r.Context(), id, req.Cmd)
		if err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, execResponse{
			ExitCode: result.ExitCode,
			Stdout:   result.Stdout,
			Stderr:   result.Stderr,
		})
	}
}
```

File: `internal/infra/httpapi/handler.go`

Note: Uses Go 1.22+ path value syntax (`r.PathValue("id")`) and method-aware routing (`"POST /v1/vms"`). The `{id}` wildcard in the route pattern is matched by `r.PathValue("id")`.

### Step 5: Write webhook.go

```go
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/Work-Fort/Nexus/internal/app"
)

func handleSharkfinWebhook(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var wh app.SharkfinWebhook
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if err := svc.HandleWebhook(r.Context(), wh); err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
```

File: `internal/infra/httpapi/webhook.go`

Note: The `handleSharkfinWebhook` is declared in `handler.go`'s `NewHandler` mux. It's defined here in a separate file for organizational clarity — same package, same registration.

### Step 6: Run all handler tests

Run: `go test ./internal/infra/httpapi/ -v`
Expected: All 7 tests PASS.

### Step 7: Commit

```bash
git add internal/infra/httpapi/
git commit -m "feat(httpapi): implement REST API and webhook handlers"
```

---

## Task 8: Server Wiring and Daemon Command

**Files:**
- Create: `cmd/nexusd/daemon.go`
- Modify: `cmd/nexusd/root.go` (add daemon subcommand)

### Step 1: Write daemon.go

```go
// SPDX-License-Identifier: Apache-2.0
package nexusd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/config"
	ctrd "github.com/Work-Fort/Nexus/internal/infra/containerd"
	"github.com/Work-Fort/Nexus/internal/infra/httpapi"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
)

func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Start the Nexus daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := viper.GetString("listen")
			dbPath := filepath.Join(config.GlobalPaths.StateDir, "nexus.db")
			socketPath := viper.GetString("containerd-socket")
			namespace := viper.GetString("namespace")

			// Open SQLite store
			store, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}

			// Connect to containerd
			runtime, err := ctrd.New(socketPath, namespace)
			if err != nil {
				return fmt.Errorf("connect to containerd: %w", err)
			}

			// Build service
			svc := app.NewVMService(store, runtime, app.WithConfig(app.VMServiceConfig{
				DefaultImage:   viper.GetString("agent-image"),
				DefaultRuntime: viper.GetString("runtime"),
			}))

			// Build HTTP handler
			handler := httpapi.NewHandler(svc)

			httpServer := &http.Server{
				Addr:    addr,
				Handler: handler,
			}

			// Signal handling
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			errCh := make(chan error, 1)
			go func() {
				ln, err := net.Listen("tcp4", addr)
				if err != nil {
					errCh <- fmt.Errorf("listen: %w", err)
					return
				}
				fmt.Fprintf(os.Stderr, "nexusd listening on %s\n", ln.Addr())
				if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			select {
			case sig := <-sigCh:
				fmt.Fprintf(os.Stderr, "\nReceived %s, shutting down...\n", sig)
			case err := <-errCh:
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := httpServer.Shutdown(ctx); err != nil {
				log.Error("http shutdown", "err", err)
			}
			runtime.Close()
			store.Close()
			return nil
		},
	}

	cmd.Flags().String("listen", config.DefaultListenAddr, "HTTP listen address")
	cmd.Flags().String("containerd-socket", config.DefaultSocketPath, "containerd socket path")
	cmd.Flags().String("namespace", config.DefaultNamespace, "containerd namespace")
	cmd.Flags().String("runtime", config.DefaultRuntime, "Default container runtime handler")
	cmd.Flags().String("agent-image", config.DefaultAgentImage, "Default OCI image for agent VMs")

	viper.BindPFlag("listen", cmd.Flags().Lookup("listen"))
	viper.BindPFlag("containerd-socket", cmd.Flags().Lookup("containerd-socket"))
	viper.BindPFlag("namespace", cmd.Flags().Lookup("namespace"))
	viper.BindPFlag("runtime", cmd.Flags().Lookup("runtime"))
	viper.BindPFlag("agent-image", cmd.Flags().Lookup("agent-image"))

	return cmd
}
```

File: `cmd/nexusd/daemon.go`

### Step 2: Add daemon subcommand to root.go

Add this line to the `init()` function in `cmd/nexusd/root.go`, after the `BindFlags` call:

```go
rootCmd.AddCommand(newDaemonCmd())
```

### Step 3: Verify compilation

Run: `go build ./cmd/nexusd`
Expected: Builds successfully.

### Step 4: Commit

```bash
git add cmd/nexusd/
git commit -m "feat(nexusd): wire daemon command with containerd, SQLite, and HTTP"
```

---

## Task 9: PAUSE — Manual Smoke Test

This step requires a running containerd daemon and appropriate permissions.

### Step 1: Build the binary

Run:
```bash
CGO_ENABLED=0 go build -o nexusd ./cmd/nexusd
```

### Step 2: Start the daemon

Run:
```bash
./nexusd daemon --listen 127.0.0.1:9600
```

Expected: `nexusd listening on 127.0.0.1:9600`

If it fails to connect to containerd, check:
- Socket path: `ls -la /run/containerd/containerd.sock`
- Permissions: you may need to add your user to the `containerd` group or run with `sudo`

### Step 3: Smoke test with curl

In a separate terminal:

```bash
# Create a VM
curl -s -X POST http://127.0.0.1:9600/v1/vms \
  -H 'Content-Type: application/json' \
  -d '{"name":"test-1","role":"agent","image":"docker.io/library/alpine:latest"}' | jq .

# List VMs
curl -s http://127.0.0.1:9600/v1/vms | jq .

# Get VM (use the id from create response)
curl -s http://127.0.0.1:9600/v1/vms/<id> | jq .

# Start VM
curl -s -X POST http://127.0.0.1:9600/v1/vms/<id>/start

# Stop VM
curl -s -X POST http://127.0.0.1:9600/v1/vms/<id>/stop

# Delete VM
curl -s -X DELETE http://127.0.0.1:9600/v1/vms/<id>

# Test webhook
curl -s -X POST http://127.0.0.1:9600/webhooks/sharkfin \
  -H 'Content-Type: application/json' \
  -d '{"event":"message.new","recipient":"deploy-bot","channel":"ops","from":"dev"}' | jq .
```

### Step 4: Clean up

Stop the daemon with Ctrl+C. Clean up any test containers:
```bash
sudo ctr -n nexus containers list
sudo ctr -n nexus containers delete test-1
```

### Step 5: Commit any fixes from smoke testing

```bash
git add -A
git commit -m "fix(nexusd): fixes from smoke testing"
```
