// SPDX-License-Identifier: GPL-3.0-or-later
package app_test

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
)

// --- mock network for restart tests ---

type mockNetworkForRestart struct {
	mu              sync.Mutex
	configChanged   bool
	teardownCalls   []string // VM IDs
	setupCalls      []string // VM IDs
	saveHashCalled  bool
	setupResult     *domain.NetworkInfo
	setupErr        error
}

func (m *mockNetworkForRestart) Setup(_ context.Context, id string, _ ...domain.SetupOpt) (*domain.NetworkInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setupCalls = append(m.setupCalls, id)
	if m.setupErr != nil {
		return nil, m.setupErr
	}
	return m.setupResult, nil
}

func (m *mockNetworkForRestart) Teardown(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.teardownCalls = append(m.teardownCalls, id)
	return nil
}

func (m *mockNetworkForRestart) ResetNetwork(_ context.Context) error {
	return nil
}

func (m *mockNetworkForRestart) ConfigChanged() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.configChanged
}

func (m *mockNetworkForRestart) SaveConfigHash() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveHashCalled = true
	return nil
}

// --- mock runtime for restart tests ---

type mockRuntimeForRestart struct {
	mu         sync.Mutex
	stopCalls  []string
	startCalls []string
}

func (m *mockRuntimeForRestart) Create(_ context.Context, _, _, _ string, _ ...domain.CreateOpt) error {
	return nil
}

func (m *mockRuntimeForRestart) Start(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalls = append(m.startCalls, id)
	return nil
}

func (m *mockRuntimeForRestart) Stop(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalls = append(m.stopCalls, id)
	return nil
}

func (m *mockRuntimeForRestart) Delete(_ context.Context, _ string) error {
	return nil
}

func (m *mockRuntimeForRestart) Exec(_ context.Context, _ string, _ []string) (*domain.ExecResult, error) {
	return &domain.ExecResult{ExitCode: 0}, nil
}

func (m *mockRuntimeForRestart) ExecStream(_ context.Context, _ string, _ []string, _, _ io.Writer) (int, error) {
	return 0, nil
}

func (m *mockRuntimeForRestart) ExecConsole(_ context.Context, _ string, _ []string, _, _ uint16) (*domain.ConsoleSession, error) {
	return nil, nil
}

func (m *mockRuntimeForRestart) SetSnapshotQuota(_ context.Context, _ string, _ int64) error {
	return nil
}

func (m *mockRuntimeForRestart) DetectDistro(_ context.Context, _ string) (string, error) {
	return "alpine", nil
}

func (m *mockRuntimeForRestart) ExportImage(_ context.Context, _ string, _ io.Writer) error {
	return nil
}

func (m *mockRuntimeForRestart) ImportImage(_ context.Context, _ io.Reader) (string, error) {
	return "", nil
}

func (m *mockRuntimeForRestart) WatchExits(_ context.Context, _ func(string, uint32)) error {
	return nil
}

func (m *mockRuntimeForRestart) SnapshotRootfs(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockRuntimeForRestart) RestoreRootfs(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockRuntimeForRestart) DeleteRootfsSnapshot(_ context.Context, _ string) error {
	return nil
}

func TestRestoreVMsWithNetworkMigration(t *testing.T) {
	store := newMockStore()
	rt := &mockRuntimeForRestart{}
	net := &mockNetworkForRestart{
		configChanged: true,
		setupResult: &domain.NetworkInfo{
			IP:        "172.16.0.50",
			Gateway:   "172.16.0.1",
			NetNSPath: "/run/netns/new-ns",
		},
	}

	svc := app.NewVMService(store, rt, net, app.WithConfig(app.VMServiceConfig{
		DefaultImage:       "alpine:latest",
		DefaultRuntime:     "runc",
		NetworkAutoMigrate: true,
	}))

	ctx := context.Background()

	// Pre-populate two VMs in the store with network info.
	vm1 := &domain.VM{
		ID:            "vm-001",
		Name:          "alpha",
		State:         domain.VMStateStopped,
		IP:            "172.16.0.10",
		Gateway:       "172.16.0.1",
		NetNSPath:     "/run/netns/old-ns-1",
		RestartPolicy: domain.RestartPolicyNone,
	}
	vm2 := &domain.VM{
		ID:            "vm-002",
		Name:          "beta",
		State:         domain.VMStateStopped,
		IP:            "172.16.0.11",
		Gateway:       "172.16.0.1",
		NetNSPath:     "/run/netns/old-ns-2",
		RestartPolicy: domain.RestartPolicyNone,
	}
	store.Create(ctx, vm1) //nolint:errcheck
	store.Create(ctx, vm2) //nolint:errcheck

	svc.RestoreVMs(ctx)

	// Verify teardown was called for both VMs.
	net.mu.Lock()
	defer net.mu.Unlock()

	if len(net.teardownCalls) != 2 {
		t.Fatalf("expected 2 teardown calls, got %d", len(net.teardownCalls))
	}
	if len(net.setupCalls) != 2 {
		t.Fatalf("expected 2 setup calls, got %d", len(net.setupCalls))
	}
	if !net.saveHashCalled {
		t.Fatal("expected SaveConfigHash to be called")
	}

	// Verify store was updated with new network info.
	got1, _ := store.Get(ctx, "vm-001")
	if got1.IP != "172.16.0.50" {
		t.Errorf("vm1 IP: got %q, want %q", got1.IP, "172.16.0.50")
	}
	if got1.NetNSPath != "/run/netns/new-ns" {
		t.Errorf("vm1 NetNSPath: got %q, want %q", got1.NetNSPath, "/run/netns/new-ns")
	}

	got2, _ := store.Get(ctx, "vm-002")
	if got2.IP != "172.16.0.50" {
		t.Errorf("vm2 IP: got %q, want %q", got2.IP, "172.16.0.50")
	}
}

func TestRestoreVMsNoMigration(t *testing.T) {
	store := newMockStore()
	rt := &mockRuntimeForRestart{}
	net := &mockNetworkForRestart{
		configChanged: false,
		setupResult: &domain.NetworkInfo{
			IP:        "172.16.0.50",
			Gateway:   "172.16.0.1",
			NetNSPath: "/run/netns/new-ns",
		},
	}

	svc := app.NewVMService(store, rt, net, app.WithConfig(app.VMServiceConfig{
		DefaultImage:       "alpine:latest",
		DefaultRuntime:     "runc",
		NetworkAutoMigrate: true,
	}))

	ctx := context.Background()

	vm := &domain.VM{
		ID:            "vm-001",
		Name:          "alpha",
		State:         domain.VMStateStopped,
		IP:            "172.16.0.10",
		Gateway:       "172.16.0.1",
		NetNSPath:     "/run/netns/old-ns",
		RestartPolicy: domain.RestartPolicyNone,
	}
	store.Create(ctx, vm) //nolint:errcheck

	svc.RestoreVMs(ctx)

	net.mu.Lock()
	defer net.mu.Unlock()

	if len(net.teardownCalls) != 0 {
		t.Fatalf("expected 0 teardown calls, got %d", len(net.teardownCalls))
	}
	if len(net.setupCalls) != 0 {
		t.Fatalf("expected 0 setup calls, got %d", len(net.setupCalls))
	}
	if !net.saveHashCalled {
		t.Fatal("expected SaveConfigHash to be called (for ensuring hash exists)")
	}

	// Verify store was NOT updated (IP should be unchanged).
	got, _ := store.Get(ctx, "vm-001")
	if got.IP != "172.16.0.10" {
		t.Errorf("vm IP should be unchanged: got %q, want %q", got.IP, "172.16.0.10")
	}
}

func TestRestoreVMsMigrationDisabled(t *testing.T) {
	store := newMockStore()
	rt := &mockRuntimeForRestart{}
	net := &mockNetworkForRestart{
		configChanged: true,
		setupResult: &domain.NetworkInfo{
			IP:        "172.16.0.50",
			Gateway:   "172.16.0.1",
			NetNSPath: "/run/netns/new-ns",
		},
	}

	svc := app.NewVMService(store, rt, net, app.WithConfig(app.VMServiceConfig{
		DefaultImage:       "alpine:latest",
		DefaultRuntime:     "runc",
		NetworkAutoMigrate: false,
	}))

	ctx := context.Background()

	vm := &domain.VM{
		ID:            "vm-001",
		Name:          "alpha",
		State:         domain.VMStateStopped,
		IP:            "172.16.0.10",
		Gateway:       "172.16.0.1",
		NetNSPath:     "/run/netns/old-ns",
		RestartPolicy: domain.RestartPolicyNone,
	}
	store.Create(ctx, vm) //nolint:errcheck

	svc.RestoreVMs(ctx)

	net.mu.Lock()
	defer net.mu.Unlock()

	if len(net.teardownCalls) != 0 {
		t.Fatalf("expected 0 teardown calls, got %d", len(net.teardownCalls))
	}
	if len(net.setupCalls) != 0 {
		t.Fatalf("expected 0 setup calls, got %d", len(net.setupCalls))
	}
	if !net.saveHashCalled {
		t.Fatal("expected SaveConfigHash to be called even when migration disabled")
	}

	// Verify store was NOT updated (IP should be unchanged).
	got, _ := store.Get(ctx, "vm-001")
	if got.IP != "172.16.0.10" {
		t.Errorf("vm IP should be unchanged: got %q, want %q", got.IP, "172.16.0.10")
	}
}
