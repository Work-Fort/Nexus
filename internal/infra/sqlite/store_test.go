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
		ID:              "vm-001",
		Name:            "test-agent",
		Role:            domain.VMRoleAgent,
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
		ID:              "vm-002",
		Name:            "deploy-agent",
		Role:            domain.VMRoleAgent,
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

	store.Create(ctx, &domain.VM{ID: "a1", Name: "agent-1", Role: domain.VMRoleAgent, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})
	store.Create(ctx, &domain.VM{ID: "s1", Name: "svc-1", Role: domain.VMRoleService, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})

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

	store.Create(ctx, &domain.VM{ID: "vm-1", Name: "test", Role: domain.VMRoleAgent, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})

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

	store.Create(ctx, &domain.VM{ID: "vm-del", Name: "deleteme", Role: domain.VMRoleAgent, State: domain.VMStateCreated, Image: "alpine:latest", Runtime: "runc", RestartPolicy: domain.RestartPolicyNone, RestartStrategy: domain.RestartStrategyBackoff, CreatedAt: now})

	if err := store.Delete(ctx, "vm-del"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := store.Get(ctx, "vm-del")
	if err != domain.ErrNotFound {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
}
