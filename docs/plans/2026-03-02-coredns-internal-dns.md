# CoreDNS Internal DNS — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement
> this plan task-by-task.

**Goal:** Give VMs inter-VM name resolution via CoreDNS, with per-VM DNS
configuration (custom servers, search domains).

**Architecture:** Nexus manages a CoreDNS child process that serves
`<vm-name>.nexus.local` records from an auto-generated hosts file. Each VM gets
a bind-mounted `/etc/resolv.conf` whose contents are configurable at creation
time. CoreDNS forwards non-local queries to the host's upstream resolvers.

**Tech Stack:** CoreDNS (external binary, not embedded), Go `os/exec` for
process management, `sync.Mutex` for hosts-file concurrency.

---

## Context

VMs already get IPs from CNI (`172.16.0.0/12`, bridge `nexus0`, gateway
`172.16.0.1`). There's no DNS — VMs can only reach each other by raw IP.

**Codebase patterns to follow:**
- Hexagonal: domain types/interfaces in `internal/domain/`, implementations in
  `internal/infra/`
- Functional options on `VMService` (`WithStorage`, `WithDeviceStore`)
- sqlc for queries + goose for migrations. Run `sqlc generate` after editing
  `queries.sql`. The sqlc config lives at `sqlc.yaml` in the project root.
- `vmFromRow()` / `driveFromRow()` / `deviceFromRow()` convert sqlc rows →
  domain types
- Mocks in `internal/app/vm_service_test.go` for all ports
- `NoopNetwork` / `NoopStorage` for disabled features
- `viper.GetBool` flags like `--network-enabled` gate optional features
- Helper binaries with `setcap` for privileged ops (nexus-netns, nexus-cni-exec,
  nexus-quota)

**Files you'll need to read first:**
- `internal/domain/ports.go` — all port interfaces + `CreateConfig`/`CreateOpt`
- `internal/domain/vm.go` — VM struct and params
- `internal/app/vm_service.go` — full service layer (CreateVM, DeleteVM,
  recreateContainer)
- `internal/app/vm_service_test.go` — all mocks and test patterns
- `internal/infra/sqlite/store.go` — `vmFromRow`, `Create`, `Resolve`
- `internal/infra/sqlite/queries.sql` — all sqlc queries
- `internal/infra/containerd/runtime.go` — `Create()` method, how it handles
  `CreateConfig` fields
- `internal/infra/httpapi/handler.go` — request/response types, `handleCreateVM`
- `internal/config/config.go` — defaults and viper setup
- `cmd/daemon.go` — wiring

---

### Task 1: Gateway IP utility

**Files:**
- Create: `internal/infra/cni/gateway.go`
- Test: `internal/infra/cni/gateway_test.go`

**Step 1: Write the failing test**

Create `internal/infra/cni/gateway_test.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later
package cni

import "testing"

func TestGatewayIP(t *testing.T) {
	tests := []struct {
		cidr    string
		want    string
		wantErr bool
	}{
		{"172.16.0.0/12", "172.16.0.1", false},
		{"10.0.0.0/24", "10.0.0.1", false},
		{"192.168.1.0/24", "192.168.1.1", false},
		{"invalid", "", true},
		{"::1/128", "", true}, // IPv6 not supported
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			got, err := GatewayIP(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GatewayIP(%q) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GatewayIP(%q) = %q, want %q", tt.cidr, got, tt.want)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/infra/cni/ -run TestGatewayIP -v`
Expected: FAIL — `GatewayIP` undefined

**Step 3: Write minimal implementation**

Create `internal/infra/cni/gateway.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later
package cni

import (
	"fmt"
	"net"
)

// GatewayIP returns the first usable IP in a CIDR subnet.
// For "172.16.0.0/12" this returns "172.16.0.1".
func GatewayIP(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", cidr)
	}
	gw := make(net.IP, len(ip4))
	copy(gw, ip4)
	gw[3]++
	return gw.String(), nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/infra/cni/ -run TestGatewayIP -v`
Expected: PASS

**Step 5: Commit**

```
feat(cni): add GatewayIP utility to derive gateway from subnet CIDR
```

---

### Task 2: Domain types — DNSManager interface, DNSConfig, WithResolvConf

**Files:**
- Modify: `internal/domain/ports.go`
- Modify: `internal/domain/vm.go`

**Step 1: Add DNSConfig and DNSManager to domain/ports.go**

Add to `internal/domain/ports.go` after the `Storage` interface:

```go
// DNSConfig holds per-VM DNS resolution settings.
// Nil means use defaults (gateway as nameserver, "nexus.local" as search).
type DNSConfig struct {
	Servers []string // nameservers (default: [gateway IP])
	Search  []string // search domains (default: ["nexus.local"])
}

// DNSManager manages internal DNS for VM name resolution.
type DNSManager interface {
	Start(ctx context.Context) error
	Stop() error
	AddRecord(ctx context.Context, name, ip string) error
	RemoveRecord(ctx context.Context, name string) error
	GenerateResolvConf(vmID string, cfg *DNSConfig) (path string, err error)
	CleanupResolvConf(vmID string) error
}
```

**Step 2: Add WithResolvConf to domain/ports.go**

Add `ResolvConfPath` field to `CreateConfig`:

```go
type CreateConfig struct {
	NetNSPath      string
	Mounts         []Mount
	Devices        []DeviceInfo
	ResolvConfPath string
}
```

Add the functional option:

```go
// WithResolvConf bind-mounts a resolv.conf into the container.
func WithResolvConf(path string) CreateOpt {
	return func(c *CreateConfig) {
		c.ResolvConfPath = path
	}
}
```

**Step 3: Add DNSConfig to VM and CreateVMParams in domain/vm.go**

In `internal/domain/vm.go`, add `DNSConfig *DNSConfig` to the VM struct (after
`NetNSPath`):

```go
type VM struct {
	ID        string
	Name      string
	Role      VMRole
	State     VMState
	Image     string
	Runtime   string
	IP        string
	Gateway   string
	NetNSPath string
	DNSConfig *DNSConfig
	CreatedAt time.Time
	StartedAt *time.Time
	StoppedAt *time.Time
}
```

And add it to `CreateVMParams`:

```go
type CreateVMParams struct {
	Name      string
	Role      VMRole
	Image     string
	Runtime   string
	DNSConfig *DNSConfig
}
```

**Step 4: Build to verify it compiles**

Run: `go build ./...`
Expected: PASS (no consumers yet)

**Step 5: Commit**

```
feat(domain): add DNSManager interface, DNSConfig type, WithResolvConf option
```

---

### Task 3: DNS Manager — hosts file and resolv.conf

This is the core infrastructure. Manages the hosts file (add/remove VM records)
and generates per-VM resolv.conf files. Does **not** include CoreDNS process
management yet — that's Task 4.

**Files:**
- Create: `internal/infra/dns/manager.go`
- Create: `internal/infra/dns/noop.go`
- Test: `internal/infra/dns/manager_test.go`

**Step 1: Write the failing tests**

Create `internal/infra/dns/manager_test.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later
package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Work-Fort/Nexus/internal/domain"
)

func TestAddAndRemoveRecord(t *testing.T) {
	stateDir := t.TempDir()
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			StateDir:   stateDir,
			RuntimeDir: runtimeDir,
		},
		records: make(map[string]string),
	}

	// Add two records
	if err := m.addRecord("web", "172.16.0.2"); err != nil {
		t.Fatalf("add web: %v", err)
	}
	if err := m.addRecord("db", "172.16.0.3"); err != nil {
		t.Fatalf("add db: %v", err)
	}

	// Verify hosts file
	data, err := os.ReadFile(filepath.Join(stateDir, "hosts"))
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "172.16.0.2 web.nexus.local web") {
		t.Errorf("hosts missing web entry:\n%s", content)
	}
	if !strings.Contains(content, "172.16.0.3 db.nexus.local db") {
		t.Errorf("hosts missing db entry:\n%s", content)
	}

	// Remove one
	if err := m.removeRecord("web"); err != nil {
		t.Fatalf("remove web: %v", err)
	}
	data, _ = os.ReadFile(filepath.Join(stateDir, "hosts"))
	content = string(data)
	if strings.Contains(content, "web") {
		t.Errorf("hosts still contains web after removal:\n%s", content)
	}
	if !strings.Contains(content, "db") {
		t.Errorf("hosts missing db after removing web:\n%s", content)
	}
}

func TestGenerateResolvConfDefault(t *testing.T) {
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			RuntimeDir: runtimeDir,
		},
	}

	path, err := m.GenerateResolvConf("vm-abc", nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "nameserver 172.16.0.1") {
		t.Errorf("missing default nameserver:\n%s", content)
	}
	if !strings.Contains(content, "search nexus.local") {
		t.Errorf("missing default search:\n%s", content)
	}
}

func TestGenerateResolvConfCustom(t *testing.T) {
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			RuntimeDir: runtimeDir,
		},
	}

	cfg := &domain.DNSConfig{
		Servers: []string{"172.16.0.1", "8.8.8.8"},
		Search:  []string{"nexus.local", "example.com"},
	}
	path, err := m.GenerateResolvConf("vm-xyz", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "nameserver 172.16.0.1") {
		t.Errorf("missing first nameserver:\n%s", content)
	}
	if !strings.Contains(content, "nameserver 8.8.8.8") {
		t.Errorf("missing second nameserver:\n%s", content)
	}
	if !strings.Contains(content, "search nexus.local example.com") {
		t.Errorf("missing search domains:\n%s", content)
	}
}

func TestCleanupResolvConf(t *testing.T) {
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			RuntimeDir: runtimeDir,
		},
	}

	path, _ := m.GenerateResolvConf("vm-cleanup", nil)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist: %v", err)
	}

	if err := m.CleanupResolvConf("vm-cleanup"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted after cleanup")
	}
}

func TestCleanupResolvConfIdempotent(t *testing.T) {
	m := &Manager{
		cfg: Config{RuntimeDir: t.TempDir()},
	}
	// Should not error even if file doesn't exist
	if err := m.CleanupResolvConf("nonexistent"); err != nil {
		t.Fatalf("cleanup nonexistent: %v", err)
	}
}

func TestParseUpstreams(t *testing.T) {
	tmp := t.TempDir()
	resolvPath := filepath.Join(tmp, "resolv.conf")
	os.WriteFile(resolvPath, []byte("# comment\nnameserver 1.2.3.4\nnameserver 5.6.7.8\nsearch example.com\n"), 0644)

	got := parseUpstreamsFrom(resolvPath)
	if len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "5.6.7.8" {
		t.Errorf("parseUpstreams = %v, want [1.2.3.4 5.6.7.8]", got)
	}
}

func TestParseUpstreamsFallback(t *testing.T) {
	got := parseUpstreamsFrom("/nonexistent/resolv.conf")
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Errorf("parseUpstreams fallback = %v, want [1.1.1.1 8.8.8.8]", got)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/infra/dns/ -v`
Expected: FAIL — package doesn't exist yet

**Step 3: Write the Manager implementation**

Create `internal/infra/dns/manager.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

// Package dns manages internal DNS for VM name resolution via CoreDNS.
package dns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// Config holds DNS manager configuration.
type Config struct {
	CoreDNSBin string   // path to coredns binary
	GatewayIP  string   // bridge gateway IP (e.g. "172.16.0.1")
	StateDir   string   // persistent dir for Corefile + hosts
	RuntimeDir string   // runtime dir for per-VM resolv.conf files
	Upstreams  []string // upstream DNS servers (nil = auto-detect)
}

// Manager manages CoreDNS and the hosts file for internal DNS.
type Manager struct {
	cfg     Config
	cmd     *exec.Cmd
	mu      sync.Mutex
	records map[string]string // name → IP
}

// New creates a DNS manager. Call Start() to launch CoreDNS.
func New(cfg Config) (*Manager, error) {
	if cfg.CoreDNSBin != "" {
		if _, err := exec.LookPath(cfg.CoreDNSBin); err != nil {
			return nil, fmt.Errorf("coredns binary not found at %q: %w", cfg.CoreDNSBin, err)
		}
	}
	if err := os.MkdirAll(cfg.StateDir, 0755); err != nil {
		return nil, fmt.Errorf("create dns state dir: %w", err)
	}
	if err := os.MkdirAll(cfg.RuntimeDir, 0755); err != nil {
		return nil, fmt.Errorf("create dns runtime dir: %w", err)
	}
	if len(cfg.Upstreams) == 0 {
		cfg.Upstreams = parseUpstreams()
	}
	return &Manager{
		cfg:     cfg,
		records: make(map[string]string),
	}, nil
}

// Start writes the Corefile and launches the CoreDNS process.
func (m *Manager) Start(ctx context.Context) error {
	if err := m.writeCorefile(); err != nil {
		return fmt.Errorf("write corefile: %w", err)
	}
	if err := m.writeHostsFile(); err != nil {
		return fmt.Errorf("write initial hosts: %w", err)
	}

	if m.cfg.CoreDNSBin == "" {
		return nil // no binary configured, skip process start
	}

	corefilePath := filepath.Join(m.cfg.StateDir, "Corefile")
	m.cmd = exec.CommandContext(ctx, m.cfg.CoreDNSBin, "-conf", corefilePath, "-dns.port", "53")
	m.cmd.Stdout = os.Stderr // CoreDNS logs to stdout
	m.cmd.Stderr = os.Stderr

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("start coredns: %w", err)
	}

	// Monitor in background
	go func() {
		if err := m.cmd.Wait(); err != nil {
			log.Warn("coredns exited", "err", err)
		}
	}()

	log.Info("coredns started", "pid", m.cmd.Process.Pid, "gateway", m.cfg.GatewayIP)
	return nil
}

// Stop gracefully shuts down CoreDNS.
func (m *Manager) Stop() error {
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	if err := m.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return nil // already exited
	}

	done := make(chan struct{})
	go func() {
		m.cmd.Process.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		m.cmd.Process.Kill()
		<-done
	}
	return nil
}

// AddRecord registers a VM name→IP mapping in the hosts file.
func (m *Manager) AddRecord(_ context.Context, name, ip string) error {
	return m.addRecord(name, ip)
}

func (m *Manager) addRecord(name, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[name] = ip
	return m.writeHostsFile()
}

// RemoveRecord removes a VM's DNS record from the hosts file.
func (m *Manager) RemoveRecord(_ context.Context, name string) error {
	return m.removeRecord(name)
}

func (m *Manager) removeRecord(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, name)
	return m.writeHostsFile()
}

// GenerateResolvConf creates a resolv.conf file for a VM and returns its path.
func (m *Manager) GenerateResolvConf(vmID string, cfg *domain.DNSConfig) (string, error) {
	servers := []string{m.cfg.GatewayIP}
	search := []string{"nexus.local"}
	if cfg != nil {
		if len(cfg.Servers) > 0 {
			servers = cfg.Servers
		}
		if len(cfg.Search) > 0 {
			search = cfg.Search
		}
	}

	var buf bytes.Buffer
	for _, s := range servers {
		fmt.Fprintf(&buf, "nameserver %s\n", s)
	}
	fmt.Fprintf(&buf, "search %s\n", strings.Join(search, " "))
	buf.WriteString("options ndots:1\n")

	path := filepath.Join(m.cfg.RuntimeDir, vmID+".resolv.conf")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("write resolv.conf for %s: %w", vmID, err)
	}
	return path, nil
}

// CleanupResolvConf removes a VM's resolv.conf file.
func (m *Manager) CleanupResolvConf(vmID string) error {
	path := filepath.Join(m.cfg.RuntimeDir, vmID+".resolv.conf")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove resolv.conf for %s: %w", vmID, err)
	}
	return nil
}

// writeHostsFile atomically writes all records to the hosts file.
// Must be called with m.mu held.
func (m *Manager) writeHostsFile() error {
	var buf bytes.Buffer
	for name, ip := range m.records {
		fmt.Fprintf(&buf, "%s %s.nexus.local %s\n", ip, name, name)
	}
	hostsPath := filepath.Join(m.cfg.StateDir, "hosts")
	tmp := hostsPath + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write hosts tmp: %w", err)
	}
	return os.Rename(tmp, hostsPath)
}

// writeCorefile generates the CoreDNS configuration file.
func (m *Manager) writeCorefile() error {
	hostsPath := filepath.Join(m.cfg.StateDir, "hosts")
	upstreams := strings.Join(m.cfg.Upstreams, " ")

	corefile := fmt.Sprintf(`nexus.local {
    hosts %s {
        reload 2s
        fallthrough
    }
    log
}

. {
    forward . %s
    log
}
`, hostsPath, upstreams)

	path := filepath.Join(m.cfg.StateDir, "Corefile")
	return os.WriteFile(path, []byte(corefile), 0644)
}

// parseUpstreams reads nameservers from /etc/resolv.conf.
func parseUpstreams() []string {
	return parseUpstreamsFrom("/etc/resolv.conf")
}

// parseUpstreamsFrom reads nameservers from a resolv.conf file.
func parseUpstreamsFrom(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"1.1.1.1", "8.8.8.8"}
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
			if ns != "" && ns != "127.0.0.53" { // skip systemd-resolved stub
				servers = append(servers, ns)
			}
		}
	}
	if len(servers) == 0 {
		return []string{"1.1.1.1", "8.8.8.8"}
	}
	return servers
}
```

**Step 4: Write the NoopManager**

Create `internal/infra/dns/noop.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later
package dns

import (
	"context"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// NoopManager is a DNS manager that does nothing. Used when DNS is disabled.
type NoopManager struct{}

func (n *NoopManager) Start(context.Context) error                              { return nil }
func (n *NoopManager) Stop() error                                              { return nil }
func (n *NoopManager) AddRecord(context.Context, string, string) error          { return nil }
func (n *NoopManager) RemoveRecord(context.Context, string) error               { return nil }
func (n *NoopManager) GenerateResolvConf(string, *domain.DNSConfig) (string, error) { return "", nil }
func (n *NoopManager) CleanupResolvConf(string) error                           { return nil }
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/infra/dns/ -v`
Expected: PASS (all 6 tests)

**Step 6: Run full test suite**

Run: `go test ./...`
Expected: PASS

**Step 7: Commit**

```
feat(dns): add Manager for hosts file and resolv.conf generation
```

---

### Task 4: resolv.conf bind-mount in containerd runtime

Wire `CreateConfig.ResolvConfPath` into the OCI spec as a read-only bind mount
at `/etc/resolv.conf`.

**Files:**
- Modify: `internal/infra/containerd/runtime.go:128-131` (after device handling)

**Step 1: Add resolv.conf mount handling**

In `internal/infra/containerd/runtime.go`, in the `Create()` method, after the
devices block (after `if len(createCfg.Devices) > 0 {`...`}`), add:

```go
if createCfg.ResolvConfPath != "" {
	specOpts = append(specOpts, oci.WithMounts([]specs.Mount{{
		Destination: "/etc/resolv.conf",
		Type:        "bind",
		Source:      createCfg.ResolvConfPath,
		Options:     []string{"rbind", "ro"},
	}}))
}
```

**Step 2: Build to verify it compiles**

Run: `go build ./...`
Expected: PASS

**Step 3: Commit**

```
feat(containerd): add resolv.conf bind-mount support via WithResolvConf
```

---

### Task 5: Per-VM DNS config — migration, queries, store

Add `dns_servers` and `dns_search` nullable TEXT columns to the `vms` table.
Store JSON arrays. Wire through sqlc queries and the store layer.

**Files:**
- Create: `internal/infra/sqlite/migrations/006_add_vm_dns_config.sql`
- Modify: `internal/infra/sqlite/queries.sql`
- Regenerate: `internal/infra/sqlite/queries.sql.go` (via `sqlc generate`)
- Regenerate: `internal/infra/sqlite/models.go` (via `sqlc generate`)
- Modify: `internal/infra/sqlite/store.go`

**Step 1: Create the migration**

Create `internal/infra/sqlite/migrations/006_add_vm_dns_config.sql`:

```sql
-- +goose Up
ALTER TABLE vms ADD COLUMN dns_servers TEXT;
ALTER TABLE vms ADD COLUMN dns_search TEXT;

-- +goose Down
ALTER TABLE vms DROP COLUMN dns_servers;
ALTER TABLE vms DROP COLUMN dns_search;
```

**Step 2: Update queries.sql**

Add `dns_servers, dns_search` to `InsertVM` params and to **every** VM SELECT
query. The column list for VM SELECTs becomes:

```
id, name, role, image, runtime, state, created_at, started_at, stopped_at, ip, gateway, netns_path, dns_servers, dns_search
```

Update these queries:
- `InsertVM` — add `dns_servers, dns_search` to both column list and VALUES
- `GetVM` — add to SELECT
- `GetVMByName` — add to SELECT
- `ListVMs` — add to SELECT
- `ListVMsByRole` — add to SELECT
- `ResolveVM` — add to SELECT

The `InsertVM` query becomes:
```sql
-- name: InsertVM :exec
INSERT INTO vms (id, name, role, image, runtime, state, created_at, ip, gateway, netns_path, dns_servers, dns_search)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
```

**Step 3: Regenerate sqlc**

Run: `sqlc generate`
Expected: regenerates `queries.sql.go` and `models.go` with the new columns

Verify: `go build ./internal/infra/sqlite/`
Expected: FAIL (store.go now broken — `InsertVMParams` has new fields,
`vmFromRow` receives new fields)

**Step 4: Update store.go**

In `store.go`, update `Create()` to marshal DNS config and `vmFromRow()` to
unmarshal it.

Add an import for `"encoding/json"`.

Update `Create()`:
```go
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
	})
}
```

Update `vmFromRow()` to add DNS config parsing at the end (before the return):
```go
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
```

**Step 5: Build to verify it compiles**

Run: `go build ./...`
Expected: PASS

**Step 6: Run tests**

Run: `go test ./...`
Expected: PASS

**Step 7: Commit**

```
feat(sqlite): add dns_servers and dns_search columns to vms table
```

---

### Task 6: Config and daemon wiring

Add `--dns-enabled` and `--coredns-bin` flags. Wire the DNS manager into the
daemon and pass it to VMService.

**Files:**
- Modify: `internal/config/config.go`
- Modify: `cmd/daemon.go`
- Modify: `internal/app/vm_service.go`

**Step 1: Add config defaults**

In `internal/config/config.go`, add constants:

```go
DefaultCoreDNSBin = "coredns"
```

In `InitViper()`, add:

```go
viper.SetDefault("dns-enabled", true)
viper.SetDefault("coredns-bin", DefaultCoreDNSBin)
```

**Step 2: Add WithDNS to VMService**

In `internal/app/vm_service.go`, add a `dns` field to `VMService`:

```go
type VMService struct {
	store       domain.VMStore
	runtime     domain.Runtime
	network     domain.Network
	driveStore  domain.DriveStore
	storage     domain.Storage
	deviceStore domain.DeviceStore
	dns         domain.DNSManager
	config      VMServiceConfig
}
```

Add the option function:

```go
// WithDNS enables internal DNS management.
func WithDNS(dns domain.DNSManager) func(*VMService) {
	return func(s *VMService) {
		s.dns = dns
	}
}
```

**Step 3: Wire DNS into daemon**

In `cmd/daemon.go`, add import for the dns package:
```go
"github.com/Work-Fort/Nexus/internal/infra/dns"
```

After the `network` block (after `network = &cni.NoopNetwork{}`), add:

```go
var dnsManager domain.DNSManager
if viper.GetBool("network-enabled") && viper.GetBool("dns-enabled") {
	gatewayIP, err := cni.GatewayIP(viper.GetString("network-subnet"))
	if err != nil {
		return fmt.Errorf("derive gateway IP: %w", err)
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = fmt.Sprintf("/tmp/nexus-dns-%d", os.Getuid())
	}

	dm, err := dns.New(dns.Config{
		CoreDNSBin: viper.GetString("coredns-bin"),
		GatewayIP:  gatewayIP,
		StateDir:   filepath.Join(config.GlobalPaths.StateDir, "dns"),
		RuntimeDir: filepath.Join(runtimeDir, "nexus", "dns"),
	})
	if err != nil {
		return fmt.Errorf("init dns: %w", err)
	}

	if err := dm.Start(context.Background()); err != nil {
		return fmt.Errorf("start dns: %w", err)
	}
	defer dm.Stop()
	dnsManager = dm
	log.Info("dns enabled", "gateway", gatewayIP)
} else {
	dnsManager = &dns.NoopManager{}
}

svcOpts = append(svcOpts, app.WithDNS(dnsManager))
```

Add daemon flags (in the flags section):
```go
cmd.Flags().Bool("dns-enabled", true, "Enable internal DNS for VM name resolution")
cmd.Flags().String("coredns-bin", config.DefaultCoreDNSBin, "Path to CoreDNS binary")
```

Add `"dns-enabled"` and `"coredns-bin"` to the viper bind loop.

**Step 4: Build to verify it compiles**

Run: `go build ./...`
Expected: PASS

**Step 5: Commit**

```
feat: add DNS config flags and wire DNS manager into daemon
```

---

### Task 7: Integrate DNS into VM lifecycle + tests

Wire DNS operations into CreateVM, DeleteVM, and recreateContainer. Add a
mockDNS to tests and write new test cases.

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`

**Step 1: Add mockDNS to test file**

In `internal/app/vm_service_test.go`, add after the `mockStorage` section:

```go
// --- mock DNSManager ---

type mockDNS struct {
	records    map[string]string // name → IP
	resolvConfs map[string]string // vmID → path
}

func newMockDNS() *mockDNS {
	return &mockDNS{
		records:     make(map[string]string),
		resolvConfs: make(map[string]string),
	}
}

func (m *mockDNS) Start(context.Context) error { return nil }
func (m *mockDNS) Stop() error                 { return nil }

func (m *mockDNS) AddRecord(_ context.Context, name, ip string) error {
	m.records[name] = ip
	return nil
}

func (m *mockDNS) RemoveRecord(_ context.Context, name string) error {
	delete(m.records, name)
	return nil
}

func (m *mockDNS) GenerateResolvConf(vmID string, _ *domain.DNSConfig) (string, error) {
	path := "/mock/dns/" + vmID + ".resolv.conf"
	m.resolvConfs[vmID] = path
	return path, nil
}

func (m *mockDNS) CleanupResolvConf(vmID string) error {
	delete(m.resolvConfs, vmID)
	return nil
}
```

**Step 2: Write failing tests**

Add test cases:

```go
func newSvcWithDNS() (*app.VMService, *mockStore, *mockRuntime, *mockDNS) {
	store := newMockStore()
	rt := newMockRuntime()
	d := newMockDNS()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithDNS(d))
	return svc, store, rt, d
}

func TestCreateVMAddsDNSRecord(t *testing.T) {
	svc, _, _, dns := newSvcWithDNS()

	vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "web-server", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// DNS record should be added (IP may be empty with NoopNetwork, that's ok)
	if _, ok := dns.records["web-server"]; !ok {
		t.Error("DNS record not added for web-server")
	}

	// resolv.conf should be generated
	if _, ok := dns.resolvConfs[vm.ID]; !ok {
		t.Error("resolv.conf not generated")
	}
}

func TestDeleteVMRemovesDNSRecord(t *testing.T) {
	svc, _, _, dns := newSvcWithDNS()

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "cleanup-vm", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	if err := svc.DeleteVM(context.Background(), vm.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, ok := dns.records["cleanup-vm"]; ok {
		t.Error("DNS record not removed after delete")
	}
	if _, ok := dns.resolvConfs[vm.ID]; ok {
		t.Error("resolv.conf not cleaned up after delete")
	}
}

func TestCreateVMWithDNSConfig(t *testing.T) {
	svc, _, _, _ := newSvcWithDNS()

	vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "custom-dns", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
		DNSConfig: &domain.DNSConfig{
			Servers: []string{"8.8.8.8"},
			Search:  []string{"example.com"},
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if vm.DNSConfig == nil {
		t.Fatal("DNSConfig should be set on returned VM")
	}
	if vm.DNSConfig.Servers[0] != "8.8.8.8" {
		t.Errorf("dns server = %q, want 8.8.8.8", vm.DNSConfig.Servers[0])
	}
}
```

**Step 3: Run tests to verify they fail**

Run: `go test ./internal/app/ -run TestCreateVMAddsDNSRecord -v`
Expected: FAIL — DNS record not added (not integrated yet)

**Step 4: Integrate DNS into CreateVM**

In `internal/app/vm_service.go` `CreateVM()`, after the network setup block
(after `vm.NetNSPath = netInfo.NetNSPath`) and before building `createOpts`, add:

```go
vm.DNSConfig = params.DNSConfig

var resolvConfPath string
if s.dns != nil {
	if err := s.dns.AddRecord(ctx, vm.Name, vm.IP); err != nil {
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck
		return nil, fmt.Errorf("dns add record: %w", err)
	}
	path, err := s.dns.GenerateResolvConf(vm.ID, vm.DNSConfig)
	if err != nil {
		s.dns.RemoveRecord(ctx, vm.Name) //nolint:errcheck
		s.network.Teardown(ctx, vm.ID)   //nolint:errcheck
		return nil, fmt.Errorf("dns resolv.conf: %w", err)
	}
	resolvConfPath = path
}
```

Then add to the `createOpts` block (after the `WithNetNS` check):

```go
if resolvConfPath != "" {
	createOpts = append(createOpts, domain.WithResolvConf(resolvConfPath))
}
```

**Step 5: Integrate DNS into DeleteVM**

In `DeleteVM()`, after the `network.Teardown` call, add:

```go
if s.dns != nil {
	s.dns.RemoveRecord(ctx, vm.Name)    //nolint:errcheck
	s.dns.CleanupResolvConf(vm.ID)      //nolint:errcheck
}
```

**Step 6: Integrate DNS into recreateContainer**

In `recreateContainer()`, after building `deviceInfos` and before
`runtime.Delete`, add:

```go
var resolvConfPath string
if s.dns != nil {
	path, err := s.dns.GenerateResolvConf(vm.ID, vm.DNSConfig)
	if err != nil {
		return fmt.Errorf("dns resolv.conf: %w", err)
	}
	resolvConfPath = path
}
```

Then in the `createOpts` section (after `WithDevices`), add:

```go
if resolvConfPath != "" {
	createOpts = append(createOpts, domain.WithResolvConf(resolvConfPath))
}
```

**Step 7: Run tests to verify they pass**

Run: `go test ./internal/app/ -v`
Expected: PASS (all tests including new DNS ones)

**Step 8: Run full test suite**

Run: `go test ./...`
Expected: PASS

**Step 9: Commit**

```
feat(app): integrate DNS into VM create/delete/recreate lifecycle
```

---

### Task 8: HTTP handler — DNS config in request/response

Add optional `dns` field to the create VM request and include DNS config in VM
responses.

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

**Step 1: Add DNS types to handler.go**

Add a new type after `createVMRequest`:

```go
type dnsConfigRequest struct {
	Servers []string `json:"servers,omitempty"`
	Search  []string `json:"search,omitempty"`
}
```

Add `DNS` field to `createVMRequest`:

```go
type createVMRequest struct {
	Name    string            `json:"name"`
	Role    string            `json:"role"`
	Image   string            `json:"image"`
	Runtime string            `json:"runtime"`
	DNS     *dnsConfigRequest `json:"dns,omitempty"`
}
```

Add `DNS` field to `vmResponse`:

```go
type vmResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Role      string            `json:"role"`
	State     string            `json:"state"`
	Image     string            `json:"image"`
	Runtime   string            `json:"runtime"`
	IP        string            `json:"ip,omitempty"`
	Gateway   string            `json:"gateway,omitempty"`
	DNS       *dnsConfigRequest `json:"dns,omitempty"`
	CreatedAt string            `json:"created_at"`
	StartedAt *string           `json:"started_at,omitempty"`
	StoppedAt *string           `json:"stopped_at,omitempty"`
}
```

**Step 2: Update handleCreateVM**

In `handleCreateVM`, convert the DNS config when calling CreateVM:

```go
var dnsCfg *domain.DNSConfig
if req.DNS != nil {
	dnsCfg = &domain.DNSConfig{
		Servers: req.DNS.Servers,
		Search:  req.DNS.Search,
	}
}

vm, err := svc.CreateVM(r.Context(), domain.CreateVMParams{
	Name:      req.Name,
	Role:      domain.VMRole(req.Role),
	Image:     req.Image,
	Runtime:   req.Runtime,
	DNSConfig: dnsCfg,
})
```

**Step 3: Update vmToResponse**

Add DNS config to the response converter:

```go
func vmToResponse(vm *domain.VM) vmResponse {
	r := vmResponse{
		ID:        vm.ID,
		Name:      vm.Name,
		Role:      string(vm.Role),
		State:     string(vm.State),
		Image:     vm.Image,
		Runtime:   vm.Runtime,
		IP:        vm.IP,
		Gateway:   vm.Gateway,
		CreatedAt: vm.CreatedAt.UTC().Format(timeFormatJSON),
	}
	if vm.DNSConfig != nil {
		r.DNS = &dnsConfigRequest{
			Servers: vm.DNSConfig.Servers,
			Search:  vm.DNSConfig.Search,
		}
	}
	if vm.StartedAt != nil {
		s := vm.StartedAt.UTC().Format(timeFormatJSON)
		r.StartedAt = &s
	}
	if vm.StoppedAt != nil {
		s := vm.StoppedAt.UTC().Format(timeFormatJSON)
		r.StoppedAt = &s
	}
	return r
}
```

**Step 4: Build to verify it compiles**

Run: `go build ./...`
Expected: PASS

**Step 5: Run tests**

Run: `go test ./...`
Expected: PASS

**Step 6: Commit**

```
feat(httpapi): add DNS config to create VM request and VM response
```

---

### Task 9: Startup DNS sync

When the daemon restarts, CoreDNS starts with an empty hosts file. Load existing
VM records into the DNS manager at startup.

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `cmd/daemon.go`

**Step 1: Add SyncDNS method**

In `internal/app/vm_service.go`, add:

```go
// SyncDNS loads all existing VM records into the DNS manager.
// Called once at startup to populate the hosts file.
func (s *VMService) SyncDNS(ctx context.Context) error {
	if s.dns == nil {
		return nil
	}
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		return fmt.Errorf("list vms for dns sync: %w", err)
	}
	for _, vm := range vms {
		if vm.IP != "" {
			if err := s.dns.AddRecord(ctx, vm.Name, vm.IP); err != nil {
				return fmt.Errorf("dns sync %s: %w", vm.Name, err)
			}
		}
	}
	log.Info("dns synced", "records", len(vms))
	return nil
}
```

**Step 2: Call SyncDNS from daemon**

In `cmd/daemon.go`, after `svc := app.NewVMService(...)` and before the HTTP
server setup, add:

```go
if err := svc.SyncDNS(context.Background()); err != nil {
	return fmt.Errorf("sync dns: %w", err)
}
```

**Step 3: Build to verify it compiles**

Run: `go build ./...`
Expected: PASS

**Step 4: Run full test suite**

Run: `go test ./...`
Expected: PASS

**Step 5: Commit**

```
feat(app): add SyncDNS to populate hosts file on daemon restart
```

---

## Files Modified Summary

| File | Change |
|------|--------|
| `internal/infra/cni/gateway.go` | **NEW** — GatewayIP utility |
| `internal/infra/cni/gateway_test.go` | **NEW** — tests |
| `internal/domain/ports.go` | DNSManager interface, DNSConfig, WithResolvConf, ResolvConfPath |
| `internal/domain/vm.go` | DNSConfig field on VM and CreateVMParams |
| `internal/infra/dns/manager.go` | **NEW** — CoreDNS process + hosts file + resolv.conf |
| `internal/infra/dns/noop.go` | **NEW** — NoopManager |
| `internal/infra/dns/manager_test.go` | **NEW** — unit tests |
| `internal/infra/containerd/runtime.go` | resolv.conf bind-mount in Create() |
| `internal/infra/sqlite/migrations/006_add_vm_dns_config.sql` | **NEW** — migration |
| `internal/infra/sqlite/queries.sql` | dns_servers, dns_search in all VM queries |
| `internal/infra/sqlite/queries.sql.go` | Regenerated by sqlc |
| `internal/infra/sqlite/models.go` | Regenerated by sqlc |
| `internal/infra/sqlite/store.go` | JSON marshal/unmarshal in Create + vmFromRow |
| `internal/config/config.go` | DefaultCoreDNSBin, viper defaults |
| `internal/app/vm_service.go` | WithDNS, CreateVM/DeleteVM/recreateContainer DNS, SyncDNS |
| `internal/app/vm_service_test.go` | mockDNS, DNS test cases |
| `internal/infra/httpapi/handler.go` | dnsConfigRequest type, DNS in create/response |
| `cmd/daemon.go` | DNS manager wiring, flags, SyncDNS call |

## Prerequisites

- CoreDNS binary installed and in PATH (or specified via `--coredns-bin`)
- `setcap cap_net_bind_service+ep` on the CoreDNS binary (to bind port 53)

## Verification

1. `go build ./...` — all packages compile
2. `go test ./...` — all tests pass
3. Install CoreDNS, setcap it, start daemon with `--dns-enabled`
4. Create two VMs: `POST /v1/vms` with names `web` and `db`
5. Start both VMs
6. Exec in `web`: `nslookup db.nexus.local` — resolves to db's IP
7. Exec in `web`: `nslookup google.com` — forwards upstream, resolves
8. Delete `db` — DNS record removed
9. Exec in `web`: `nslookup db.nexus.local` — NXDOMAIN
10. Create VM with custom DNS: `POST /v1/vms` with
    `{"name":"custom","role":"agent","dns":{"servers":["8.8.8.8"],"search":["example.com"]}}`
    — verify resolv.conf contents via exec
11. Restart daemon — existing VM records re-synced to hosts file
