// SPDX-License-Identifier: GPL-3.0-or-later
package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
)

// openTestStore opens an in-memory SQLite store and returns it as the infra.Store
// port interface. All tests exercise the domain-level port contract, not
// SQLite-specific internals. See architecture-reference.md §"Test Fixture Return Types".
func openTestStore(t *testing.T) infra.Store {
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
		ID:              "vm-001",
		Name:            "test-agent",
		Tags:            []string{"agent"},
		State:           domain.VMStateCreated,
		Image:           "alpine:latest",
		Runtime:         "io.containerd.runc.v2",
		RestartPolicy:   domain.RestartPolicyNone,
		RestartStrategy: domain.RestartStrategyBackoff,
		CreatedAt:       time.Now().UTC().Truncate(time.Millisecond),
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
	if len(got.Tags) != 1 || got.Tags[0] != "agent" {
		t.Errorf("tags = %v, want [agent]", got.Tags)
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
		ID:              "vm-002",
		Name:            "deploy-agent",
		Tags:            []string{"agent"},
		State:           domain.VMStateCreated,
		Image:           "alpine:latest",
		Runtime:         "io.containerd.runc.v2",
		RestartPolicy:   domain.RestartPolicyNone,
		RestartStrategy: domain.RestartStrategyBackoff,
		CreatedAt:       time.Now().UTC().Truncate(time.Millisecond),
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

	store.Create(ctx, &domain.VM{ID: "a1", Name: "agent-1", Tags: []string{"agent"}, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})
	store.Create(ctx, &domain.VM{ID: "s1", Name: "svc-1", Tags: []string{"service"}, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})

	// List all
	vms, err := store.List(ctx, domain.VMFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("list count = %d, want 2", len(vms))
	}

	// List by tag
	vms, err = store.List(ctx, domain.VMFilter{Tags: []string{"agent"}})
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

	store.Create(ctx, &domain.VM{ID: "vm-1", Name: "test", Tags: []string{"agent"}, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})

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

	store.Create(ctx, &domain.VM{ID: "vm-del", Name: "deleteme", Tags: []string{"agent"}, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})

	if err := store.Delete(ctx, "vm-del"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get(ctx, "vm-del")
	if err != domain.ErrNotFound {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
}
