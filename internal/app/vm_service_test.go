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
	if _, ok := rt.containers[vm.ID]; !ok {
		t.Error("container not created in runtime")
	}
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

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "existing-bot", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)
	svc.StopVM(context.Background(), vm.ID)

	webhook := app.SharkfinWebhook{Event: "message.new", Recipient: "existing-bot"}

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

	webhook := app.SharkfinWebhook{Event: "message.new", Recipient: "active-bot"}

	if err := svc.HandleWebhook(context.Background(), webhook); err != nil {
		t.Fatalf("webhook: %v", err)
	}

	got, _ := store.Get(context.Background(), vm.ID)
	if got.State != domain.VMStateRunning {
		t.Errorf("state = %q, want running", got.State)
	}
}
