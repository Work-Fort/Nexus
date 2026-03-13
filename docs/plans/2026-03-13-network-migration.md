# Network Migration on Restart — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect CNI config changes across daemon restarts and automatically rebuild network namespaces for existing VMs.

**Architecture:** Hash the CNI conflist JSON on startup and compare against a stored fingerprint. If changed, tear down and rebuild all VM network namespaces with the new config before starting any VMs. Best-effort IP reuse via IPAM capability args.

**Tech Stack:** Go, CNI (containernetworking/cni/libcni), host-local IPAM, SHA-256, SQLite/Postgres, sqlc

**Spec:** [docs/network-migration-design.md](../network-migration-design.md)

---

## Chunk 1: Domain & Store Layer

### Task 1: Add `SetupOpt` and `ConfigChanged` to `domain.Network`

**Files:**
- Modify: `internal/domain/ports.go:74-79`

- [ ] **Step 1: Add SetupOpt type and WithPreferredIP**

In `internal/domain/ports.go`, add before the `Network` interface:

```go
// SetupConfig holds optional parameters for network setup.
type SetupConfig struct {
	PreferredIP string
}

// SetupOpt configures optional network setup behavior.
type SetupOpt func(*SetupConfig)

// WithPreferredIP requests a specific IP from IPAM (best-effort).
func WithPreferredIP(ip string) SetupOpt {
	return func(c *SetupConfig) { c.PreferredIP = ip }
}
```

- [ ] **Step 2: Update Network interface**

Change the `Network` interface in `internal/domain/ports.go`:

```go
type Network interface {
	Setup(ctx context.Context, id string, opts ...SetupOpt) (*NetworkInfo, error)
	Teardown(ctx context.Context, id string) error
	ResetNetwork(ctx context.Context) error
	ConfigChanged() bool
	SaveConfigHash() error
}
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./internal/domain/...`
Expected: FAIL — `cni.Network` and `cni.NoopNetwork` don't satisfy the interface yet.

---

### Task 2: Update `NoopNetwork` to satisfy new interface

**Files:**
- Modify: `internal/infra/cni/noop.go`

- [ ] **Step 1: Update Setup signature and add ConfigChanged**

```go
func (n *NoopNetwork) Setup(_ context.Context, _ string, _ ...domain.SetupOpt) (*domain.NetworkInfo, error) {
	return &domain.NetworkInfo{}, nil
}

func (n *NoopNetwork) ConfigChanged() bool {
	return false
}

func (n *NoopNetwork) SaveConfigHash() error {
	return nil
}
```

- [ ] **Step 2: Verify noop compiles**

Run: `go build ./internal/infra/cni/...`
Expected: FAIL — `cni.Network` still has old `Setup` signature.

---

### Task 3: Update `cni.Network.Setup` signature

**Files:**
- Modify: `internal/infra/cni/network.go:220-248`

- [ ] **Step 1: Update Setup signature (no behavior change yet)**

Change `Setup` to accept opts but ignore them for now:

```go
func (n *Network) Setup(ctx context.Context, id string, opts ...domain.SetupOpt) (*domain.NetworkInfo, error) {
	nsPath := filepath.Join(n.netnsDir, id)

	out, err := exec.CommandContext(ctx, n.helperBin, "create", nsPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create netns %s: %w: %s", id, err, out)
	}

	rt := &libcni.RuntimeConf{
		ContainerID: id,
		NetNS:       nsPath,
		IfName:      "eth0",
	}

	result, err := n.cni.AddNetworkList(ctx, n.confList, rt)
	if err != nil {
		exec.CommandContext(ctx, n.helperBin, "delete", nsPath).Run() //nolint:errcheck
		return nil, fmt.Errorf("cni setup %s: %w", id, err)
	}

	info := &domain.NetworkInfo{NetNSPath: nsPath}
	if r, err := types100.GetResult(result); err == nil && len(r.IPs) > 0 {
		info.IP = r.IPs[0].Address.IP.String()
		if r.IPs[0].Gateway != nil {
			info.Gateway = r.IPs[0].Gateway.String()
		}
	}
	return info, nil
}
```

- [ ] **Step 2: Add stub ConfigChanged and SaveConfigHash**

Add to `cni.Network`:

```go
func (n *Network) ConfigChanged() bool {
	return false // stub — implemented in Task 6
}

func (n *Network) SaveConfigHash() error {
	return nil // stub — implemented in Task 6
}
```

- [ ] **Step 3: Verify full project compiles**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 4: Run existing tests**

Run: `mise run test`
Expected: All tests pass (no behavior change).

- [ ] **Step 5: Commit**

```bash
git add internal/domain/ports.go internal/infra/cni/noop.go internal/infra/cni/network.go
git commit -m "refactor(network): add SetupOpt and ConfigChanged to Network interface"
```

---

### Task 4: Add `UpdateNetwork` to `VMStore`

**Files:**
- Modify: `internal/domain/ports.go:12-24`
- Modify: `internal/infra/sqlite/queries.sql`
- Modify: `internal/infra/postgres/store.go`

- [ ] **Step 1: Add to VMStore interface**

In `internal/domain/ports.go`, add to the `VMStore` interface:

```go
UpdateNetwork(ctx context.Context, id, ip, gateway, netnsPath string) error
```

- [ ] **Step 2: Add SQLite query**

In `internal/infra/sqlite/queries.sql`, add:

```sql
-- name: UpdateVMNetwork :exec
UPDATE vms SET ip = ?, gateway = ?, netns_path = ? WHERE id = ?;
```

- [ ] **Step 3: Regenerate sqlc**

Run: `cd internal/infra/sqlite && sqlc generate`
Expected: `queries.sql.go` updated with `UpdateVMNetwork` method.

- [ ] **Step 4: Add SQLite store method**

In `internal/infra/sqlite/store.go`, add:

```go
func (s *Store) UpdateNetwork(ctx context.Context, id, ip, gateway, netnsPath string) error {
	return s.q.UpdateVMNetwork(ctx, sqlc.UpdateVMNetworkParams{
		IP:       ip,
		Gateway:  gateway,
		NetnsPath: netnsPath,
		ID:       id,
	})
}
```

Note: The exact param struct name depends on sqlc output. Check `queries.sql.go` after generation.

- [ ] **Step 5: Add Postgres store method**

In `internal/infra/postgres/store.go`, add:

```go
func (s *Store) UpdateNetwork(ctx context.Context, id, ip, gateway, netnsPath string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE vms SET ip = $1, gateway = $2, netns_path = $3 WHERE id = $4`,
		ip, gateway, netnsPath, id)
	return err
}
```

- [ ] **Step 6: Add UpdateNetwork to existing mockStore**

In `internal/app/vm_service_test.go`, add to the `mockStore` struct:

```go
func (m *mockStore) UpdateNetwork(_ context.Context, id, ip, gateway, netnsPath string) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.IP = ip
	vm.Gateway = gateway
	vm.NetNSPath = netnsPath
	return nil
}
```

- [ ] **Step 7: Verify it compiles**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 8: Run tests**

Run: `mise run test`
Expected: All pass.

- [ ] **Step 9: Commit**

```bash
git add internal/domain/ports.go internal/infra/sqlite/queries.sql internal/infra/sqlite/queries.sql.go internal/infra/sqlite/store.go internal/infra/postgres/store.go internal/app/vm_service_test.go
git commit -m "feat(store): add UpdateNetwork method to VMStore"
```

---

## Chunk 2: Config Fingerprint

### Task 5: Write failing tests for config fingerprint

**Files:**
- Create: `internal/infra/cni/fingerprint_test.go`

- [ ] **Step 1: Write tests**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package cni

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFingerprint(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, ".cni-config-hash")

	// Two different configs produce different hashes.
	h1 := configHash(`{"plugins":[{"type":"bridge"}]}`)
	h2 := configHash(`{"plugins":[{"type":"loopback"},{"type":"bridge"}]}`)
	if h1 == h2 {
		t.Fatal("different configs produced same hash")
	}

	// Same config produces same hash.
	h3 := configHash(`{"plugins":[{"type":"bridge"}]}`)
	if h1 != h3 {
		t.Fatal("same config produced different hash")
	}

	// Write and read back.
	if err := writeConfigHash(hashFile, h1); err != nil {
		t.Fatal(err)
	}
	stored, err := readConfigHash(hashFile)
	if err != nil {
		t.Fatal(err)
	}
	if stored != h1 {
		t.Fatalf("stored=%s, want=%s", stored, h1)
	}
}

func TestConfigFingerprintMissing(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, ".cni-config-hash")

	_, err := readConfigHash(hashFile)
	if !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestConfigChanged(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, ".cni-config-hash")

	h1 := configHash(`{"plugins":[{"type":"bridge"}]}`)
	if err := writeConfigHash(hashFile, h1); err != nil {
		t.Fatal(err)
	}

	// Same config — not changed.
	if configChangedCheck(hashFile, h1) {
		t.Fatal("expected no change for same hash")
	}

	// Different config — changed.
	h2 := configHash(`{"plugins":[{"type":"loopback"},{"type":"bridge"}]}`)
	if !configChangedCheck(hashFile, h2) {
		t.Fatal("expected change for different hash")
	}

	// Missing file — treated as changed.
	if !configChangedCheck(filepath.Join(dir, "nonexistent"), h1) {
		t.Fatal("expected changed=true for missing file")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/infra/cni/ -run TestConfig -v`
Expected: FAIL — `configHash`, `writeConfigHash`, `readConfigHash`, `configChangedCheck` undefined.

---

### Task 6: Implement config fingerprint

**Files:**
- Create: `internal/infra/cni/fingerprint.go`
- Modify: `internal/infra/cni/network.go` (struct, New, ConfigChanged)

- [ ] **Step 1: Create fingerprint.go**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package cni

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// configHash returns the SHA-256 hex digest of a CNI config string.
func configHash(confJSON string) string {
	h := sha256.Sum256([]byte(confJSON))
	return fmt.Sprintf("%x", h)
}

// writeConfigHash writes a hash string to the given file path.
func writeConfigHash(path, hash string) error {
	return os.WriteFile(path, []byte(hash), 0o600)
}

// readConfigHash reads a hash string from the given file path.
// Returns os.ErrNotExist if the file does not exist.
func readConfigHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// configChangedCheck returns true if the stored hash differs from current.
// Returns true if the hash file is missing (safe default for upgrades).
func configChangedCheck(hashFile, currentHash string) bool {
	stored, err := readConfigHash(hashFile)
	if err != nil {
		return true // missing file = changed
	}
	return stored != currentHash
}
```

- [ ] **Step 2: Add confHash and hashFile fields to Network struct**

In `internal/infra/cni/network.go`, add to the struct:

```go
confHash string // SHA-256 of the conflist JSON
hashFile string // path to the stored config hash
```

- [ ] **Step 3: Compute and store hash in New()**

In `New()`, after `confJSON` is built (after line ~147), add:

```go
confHashVal := configHash(confJSON)
hashFilePath := filepath.Join(nsDir, ".cni-config-hash")
```

And include them in the returned struct:

```go
confHash: confHashVal,
hashFile: hashFilePath,
```

- [ ] **Step 4: Implement ConfigChanged on Network**

Replace the stub:

```go
func (n *Network) ConfigChanged() bool {
	return configChangedCheck(n.hashFile, n.confHash)
}
```

- [ ] **Step 5: Implement SaveConfigHash**

Replace the stub from Task 3:

```go
// SaveConfigHash writes the current config hash to disk.
// Called after migration check to record the new baseline.
func (n *Network) SaveConfigHash() error {
	return writeConfigHash(n.hashFile, n.confHash)
}
```

- [ ] **Step 6: Run fingerprint tests**

Run: `go test ./internal/infra/cni/ -run TestConfig -v`
Expected: All 3 tests pass.

- [ ] **Step 7: Run full test suite**

Run: `mise run test`
Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add internal/infra/cni/fingerprint.go internal/infra/cni/fingerprint_test.go internal/infra/cni/network.go
git commit -m "feat(cni): add config fingerprint for drift detection"
```

---

## Chunk 3: IP Reuse in Setup

### Task 7: Add preferred IP support to Setup

**Files:**
- Modify: `internal/infra/cni/network.go:220-248`

- [ ] **Step 1: Add `ips` capability to conflist JSON**

In `New()`, update the IPAM block in `confJSON`:

```go
"ipam": {
    "type": "host-local",
    "subnet": %q,
    "dataDir": %q,
    "routes": [{"dst": "0.0.0.0/0"}],
    "capabilities": {"ips": true}
}
```

- [ ] **Step 2: Wire up preferred IP in Setup**

Update `Setup` to apply opts and use `CapabilityArgs`:

```go
func (n *Network) Setup(ctx context.Context, id string, opts ...domain.SetupOpt) (*domain.NetworkInfo, error) {
	var cfg domain.SetupConfig
	for _, o := range opts {
		o(&cfg)
	}

	nsPath := filepath.Join(n.netnsDir, id)

	out, err := exec.CommandContext(ctx, n.helperBin, "create", nsPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create netns %s: %w: %s", id, err, out)
	}

	rt := &libcni.RuntimeConf{
		ContainerID: id,
		NetNS:       nsPath,
		IfName:      "eth0",
	}
	if cfg.PreferredIP != "" {
		rt.CapabilityArgs = map[string]interface{}{
			"ips": []string{cfg.PreferredIP},
		}
	}

	result, err := n.cni.AddNetworkList(ctx, n.confList, rt)
	if err != nil {
		exec.CommandContext(ctx, n.helperBin, "delete", nsPath).Run() //nolint:errcheck
		return nil, fmt.Errorf("cni setup %s: %w", id, err)
	}

	info := &domain.NetworkInfo{NetNSPath: nsPath}
	if r, err := types100.GetResult(result); err == nil && len(r.IPs) > 0 {
		info.IP = r.IPs[0].Address.IP.String()
		if r.IPs[0].Gateway != nil {
			info.Gateway = r.IPs[0].Gateway.String()
		}
	}
	return info, nil
}
```

- [ ] **Step 3: Verify it compiles and tests pass**

Run: `go build ./... && mise run test`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add internal/infra/cni/network.go
git commit -m "feat(cni): add preferred IP support to Setup via CapabilityArgs"
```

---

## Chunk 4: Migration Logic

### Task 8: Add `--network-auto-migrate` config flag

**Files:**
- Modify: `cmd/daemon.go`
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add viper default**

In `internal/config/config.go`, in `InitViper()`, add:

```go
viper.SetDefault("network-auto-migrate", true)
```

- [ ] **Step 2: Add flag**

In `cmd/daemon.go`, in the flags section, add:

```go
cmd.Flags().Bool("network-auto-migrate", true, "Auto-rebuild network namespaces when CNI config changes")
```

- [ ] **Step 3: Add to viper binding loop**

Add `"network-auto-migrate"` to the `[]string` in the `for _, name := range` loop.

- [ ] **Step 4: Verify it compiles**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/daemon.go internal/config/config.go
git commit -m "feat(daemon): add --network-auto-migrate flag"
```

---

### Task 9: Write failing test for migration in RestoreVMs

**Files:**
- Modify: `internal/app/restart_test.go` (create if not exists)

- [ ] **Step 1: Check if restart_test.go exists**

Run: `ls internal/app/restart_test.go`
If it doesn't exist, create it.

- [ ] **Step 2: Write migration test**

This test requires mock interfaces. Check existing test patterns in `internal/app/` for how mocks are structured. The test should:

1. Create a mock network that returns `ConfigChanged() = true`
2. Create a mock store with 2 VMs that have `NetNSPath` set
3. Call `RestoreVMs()`
4. Verify `Teardown` was called for each VM
5. Verify `Setup` was called for each VM with `WithPreferredIP`
6. Verify `UpdateNetwork` was called for each VM

The exact mock structure depends on existing patterns in the codebase. Check `internal/app/` for existing `_test.go` files to follow conventions.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/app/ -run TestRestoreVMsWithNetworkMigration -v`
Expected: FAIL — migration logic not implemented yet.

---

### Task 10: Implement migration in RestoreVMs

**Files:**
- Modify: `internal/app/restart.go:16-64`
- Modify: `internal/app/vm_service.go` (VMServiceConfig if needed)

- [ ] **Step 1: Add auto-migrate config to VMServiceConfig**

In `internal/app/vm_service.go`, add to `VMServiceConfig`:

```go
NetworkAutoMigrate bool
```

- [ ] **Step 2: Wire config in daemon.go**

In `cmd/daemon.go` where the `VMServiceConfig` is built inside `WithConfig`, add:

```go
NetworkAutoMigrate: viper.GetBool("network-auto-migrate"),
```

- [ ] **Step 3: Add migration logic to RestoreVMs**

In `internal/app/restart.go`, add the migration step at the beginning of `RestoreVMs()`, after the `List` call:

```go
func (s *VMService) RestoreVMs(ctx context.Context) {
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		log.Error("restore: list vms", "err", err)
		return
	}

	// Network migration: detect CNI config drift and rebuild namespaces.
	if s.network.ConfigChanged() {
		if s.config.NetworkAutoMigrate {
			s.migrateNetworks(ctx, vms)
		} else {
			log.Warn("network config changed but auto-migrate is disabled")
			// Save hash to avoid re-warning every restart.
			if err := s.network.SaveConfigHash(); err != nil {
				log.Error("save config hash", "err", err)
			}
		}
	} else {
		// Config unchanged — ensure hash file exists for next comparison.
		if err := s.network.SaveConfigHash(); err != nil {
			log.Error("save config hash", "err", err)
		}
	}

	// ... existing restore logic unchanged ...
```

- [ ] **Step 4: Implement migrateNetworks**

Add to `internal/app/restart.go`:

```go
// migrateNetworks tears down and rebuilds network namespaces for all VMs
// when the CNI config has changed.
func (s *VMService) migrateNetworks(ctx context.Context, vms []*domain.VM) {
	var migrated, failed int
	for _, vm := range vms {
		if vm.NetNSPath == "" {
			continue
		}

		prevIP := vm.IP

		// Teardown old namespace (best-effort).
		if err := s.network.Teardown(ctx, vm.ID); err != nil {
			log.Warn("migrate: teardown", "id", vm.ID, "name", vm.Name, "err", err)
		}

		// Setup new namespace with current config.
		var opts []domain.SetupOpt
		if prevIP != "" {
			opts = append(opts, domain.WithPreferredIP(prevIP))
		}
		info, err := s.network.Setup(ctx, vm.ID, opts...)
		if err != nil {
			log.Error("migrate: setup", "id", vm.ID, "name", vm.Name, "err", err)
			// Clear network fields so state is honest.
			s.store.UpdateNetwork(ctx, vm.ID, "", "", "") //nolint:errcheck
			failed++
			continue
		}

		// Update DB with new network info.
		if err := s.store.UpdateNetwork(ctx, vm.ID, info.IP, info.Gateway, info.NetNSPath); err != nil {
			log.Error("migrate: update network", "id", vm.ID, "err", err)
			failed++
			continue
		}

		// Update in-memory VM for subsequent RestoreVMs logic.
		vm.IP = info.IP
		vm.Gateway = info.Gateway
		vm.NetNSPath = info.NetNSPath

		// Update DNS record.
		s.dns.AddRecord(ctx, vm.Name, info.IP) //nolint:errcheck

		migrated++
		if info.IP != prevIP {
			log.Info("vm network migrated", "id", vm.ID, "name", vm.Name, "old_ip", prevIP, "new_ip", info.IP)
		} else {
			log.Info("vm network migrated", "id", vm.ID, "name", vm.Name, "ip", info.IP)
		}
	}

	// Save the new config hash now that migration is complete.
	if err := s.network.SaveConfigHash(); err != nil {
		log.Error("migrate: save config hash", "err", err)
	}

	log.Info("network migration complete", "migrated", migrated, "failed", failed)
}
```

- [ ] **Step 5: Run the migration test**

Run: `go test ./internal/app/ -run TestRestoreVMsWithNetworkMigration -v`
Expected: PASS

- [ ] **Step 6: Run full test suite**

Run: `mise run test`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add internal/app/restart.go internal/app/vm_service.go cmd/daemon.go
git commit -m "feat(app): add network migration on config change in RestoreVMs"
```

---

### Task 11: Write and run additional unit tests

**Files:**
- Modify: `internal/app/restart_test.go`

- [ ] **Step 1: Add TestRestoreVMsNoMigration**

Test that when `ConfigChanged()` returns `false`, no Teardown/Setup calls are made.

- [ ] **Step 2: Add TestRestoreVMsMigrationDisabled**

Test that when `NetworkAutoMigrate` is `false` and `ConfigChanged()` returns `true`, no Teardown/Setup calls are made (only a log warning).

- [ ] **Step 3: Run tests**

Run: `go test ./internal/app/ -run TestRestoreVMs -v`
Expected: All 3 pass.

- [ ] **Step 4: Commit**

```bash
git add internal/app/restart_test.go
git commit -m "test(app): add migration disabled and no-change unit tests"
```

---

## Chunk 5: E2E Tests

### Task 12: Add E2E test for network migration on restart

**Files:**
- Modify: `tests/e2e/nexus_test.go` (or `tests/e2e/restart_test.go`)

- [ ] **Step 1: Add TestNetworkMigrationOnRestart**

Create a VM with networking, stop the daemon, restart it with a different subnet, and verify the VM gets a new IP and has loopback.

The test should:
1. Start daemon with `e2eSubnet` and networking enabled
2. Create and start a VM, note its IP
3. Stop the daemon gracefully
4. Restart daemon with a different subnet (e.g. `10.98.0.0/24`)
5. Verify VM's IP changed to the new subnet
6. Start the VM and verify loopback works (`ip link show lo`)

Check the existing `TestGracefulRestartOnBootPolicy` in `restart_test.go` for the pattern of stopping and restarting daemons with the same namespace.

- [ ] **Step 2: Add TestNetworkNoMigrationSameConfig**

1. Start daemon, create VM, note IP
2. Stop daemon
3. Restart daemon with same config
4. Verify VM keeps the same IP

- [ ] **Step 3: Run the E2E tests**

Run: `mise run e2e -- -run "TestNetworkMigration|TestNetworkNoMigration"`
Expected: Both pass.

- [ ] **Step 4: Run full E2E suite**

Run: `mise run e2e`
Expected: All pass.

- [ ] **Step 5: Run E2E cleanup**

Run: `mise run e2e:clean`

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/
git commit -m "test(e2e): add network migration on restart tests"
```

---

## Chunk 6: Final Verification

### Task 13: Full verification and commit

- [ ] **Step 1: Run unit tests**

Run: `mise run test`
Expected: All pass.

- [ ] **Step 2: Run E2E tests**

Run: `mise run e2e`
Expected: All pass.

- [ ] **Step 3: Run E2E cleanup**

Run: `mise run e2e:clean`

- [ ] **Step 4: Verify no uncommitted changes**

Run: `git status`
Expected: Clean working tree.

- [ ] **Step 5: Push**

Run: `git push origin master`
