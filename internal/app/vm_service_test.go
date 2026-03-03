// SPDX-License-Identifier: Apache-2.0
package app_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/cni"
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

func (m *mockStore) Resolve(_ context.Context, ref string) (*domain.VM, error) {
	// Try by ID first
	if vm, ok := m.vms[ref]; ok {
		return vm, nil
	}
	// Fall back to name
	for _, vm := range m.vms {
		if vm.Name == ref {
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

func (m *mockStore) UpdateRootSize(_ context.Context, id string, rootSize int64) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.RootSize = rootSize
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

func (m *mockRuntime) Create(_ context.Context, id, image, runtime string, _ ...domain.CreateOpt) error {
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

func (m *mockRuntime) SetSnapshotQuota(_ context.Context, _ string, _ int64) error {
	return nil
}

func (m *mockRuntime) ExportImage(_ context.Context, _ string, _ io.Writer) error {
	return nil
}

func (m *mockRuntime) ImportImage(_ context.Context, _ io.Reader) (string, error) {
	return "", nil
}

// --- mock DriveStore ---

type mockDriveStore struct {
	drives map[string]*domain.Drive
}

func newMockDriveStore() *mockDriveStore {
	return &mockDriveStore{drives: make(map[string]*domain.Drive)}
}

func (m *mockDriveStore) CreateDrive(_ context.Context, d *domain.Drive) error {
	if _, ok := m.drives[d.ID]; ok {
		return domain.ErrAlreadyExists
	}
	for _, existing := range m.drives {
		if existing.Name == d.Name {
			return domain.ErrAlreadyExists
		}
	}
	m.drives[d.ID] = d
	return nil
}

func (m *mockDriveStore) GetDrive(_ context.Context, id string) (*domain.Drive, error) {
	d, ok := m.drives[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return d, nil
}

func (m *mockDriveStore) GetDriveByName(_ context.Context, name string) (*domain.Drive, error) {
	for _, d := range m.drives {
		if d.Name == name {
			return d, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockDriveStore) ResolveDrive(_ context.Context, ref string) (*domain.Drive, error) {
	if d, ok := m.drives[ref]; ok {
		return d, nil
	}
	for _, d := range m.drives {
		if d.Name == ref {
			return d, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockDriveStore) ListDrives(_ context.Context) ([]*domain.Drive, error) {
	var result []*domain.Drive
	for _, d := range m.drives {
		result = append(result, d)
	}
	return result, nil
}

func (m *mockDriveStore) AttachDrive(_ context.Context, driveID, vmID string) error {
	d, ok := m.drives[driveID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = vmID
	return nil
}

func (m *mockDriveStore) DetachDrive(_ context.Context, driveID string) error {
	d, ok := m.drives[driveID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = ""
	return nil
}

func (m *mockDriveStore) DetachAllDrives(_ context.Context, vmID string) error {
	for _, d := range m.drives {
		if d.VMID == vmID {
			d.VMID = ""
		}
	}
	return nil
}

func (m *mockDriveStore) GetDrivesByVM(_ context.Context, vmID string) ([]*domain.Drive, error) {
	var result []*domain.Drive
	for _, d := range m.drives {
		if d.VMID == vmID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (m *mockDriveStore) DeleteDrive(_ context.Context, id string) error {
	delete(m.drives, id)
	return nil
}

// --- mock DeviceStore ---

type mockDeviceStore struct {
	devices map[string]*domain.Device
}

func newMockDeviceStore() *mockDeviceStore {
	return &mockDeviceStore{devices: make(map[string]*domain.Device)}
}

func (m *mockDeviceStore) CreateDevice(_ context.Context, d *domain.Device) error {
	if _, ok := m.devices[d.ID]; ok {
		return domain.ErrAlreadyExists
	}
	m.devices[d.ID] = d
	return nil
}

func (m *mockDeviceStore) GetDevice(_ context.Context, id string) (*domain.Device, error) {
	d, ok := m.devices[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return d, nil
}

func (m *mockDeviceStore) GetDeviceByName(_ context.Context, name string) (*domain.Device, error) {
	for _, d := range m.devices {
		if d.Name == name {
			return d, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockDeviceStore) ResolveDevice(_ context.Context, ref string) (*domain.Device, error) {
	if d, ok := m.devices[ref]; ok {
		return d, nil
	}
	for _, d := range m.devices {
		if d.Name == ref {
			return d, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockDeviceStore) ListDevices(_ context.Context) ([]*domain.Device, error) {
	var result []*domain.Device
	for _, d := range m.devices {
		result = append(result, d)
	}
	return result, nil
}

func (m *mockDeviceStore) AttachDevice(_ context.Context, deviceID, vmID string) error {
	d, ok := m.devices[deviceID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = vmID
	return nil
}

func (m *mockDeviceStore) DetachDevice(_ context.Context, deviceID string) error {
	d, ok := m.devices[deviceID]
	if !ok {
		return domain.ErrNotFound
	}
	d.VMID = ""
	return nil
}

func (m *mockDeviceStore) DetachAllDevices(_ context.Context, vmID string) error {
	for _, d := range m.devices {
		if d.VMID == vmID {
			d.VMID = ""
		}
	}
	return nil
}

func (m *mockDeviceStore) GetDevicesByVM(_ context.Context, vmID string) ([]*domain.Device, error) {
	var result []*domain.Device
	for _, d := range m.devices {
		if d.VMID == vmID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (m *mockDeviceStore) DeleteDevice(_ context.Context, id string) error {
	delete(m.devices, id)
	return nil
}

// --- mock DNSManager ---

type mockDNS struct {
	records     map[string]string // name → IP
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

// --- mock Storage ---

type mockStorage struct {
	volumes map[string]bool
}

func newMockStorage() *mockStorage {
	return &mockStorage{volumes: make(map[string]bool)}
}

func (m *mockStorage) CreateVolume(_ context.Context, name string, _ uint64) (string, error) {
	m.volumes[name] = true
	return "/mock/drives/" + name, nil
}

func (m *mockStorage) DeleteVolume(_ context.Context, name string) error {
	delete(m.volumes, name)
	return nil
}

func (m *mockStorage) VolumePath(name string) string {
	return "/mock/drives/" + name
}

func (m *mockStorage) SendVolume(_ context.Context, _ string, _ io.Writer) error {
	return nil
}

func (m *mockStorage) ReceiveVolume(_ context.Context, _ string, _ io.Reader) error {
	return nil
}

// --- helper ---

func newSvcWithDrives() (*app.VMService, *mockStore, *mockRuntime, *mockDriveStore, *mockStorage) {
	store := newMockStore()
	rt := newMockRuntime()
	ds := newMockDriveStore()
	st := newMockStorage()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithStorage(ds, st))
	return svc, store, rt, ds, st
}

func newSvcWithDevices() (*app.VMService, *mockStore, *mockRuntime, *mockDeviceStore) {
	store := newMockStore()
	rt := newMockRuntime()
	devStore := newMockDeviceStore()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithDeviceStore(devStore))
	return svc, store, rt, devStore
}

// --- tests ---

func TestCreateVM(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

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

func TestCreateVMWithRootSize(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "sized-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 1_000_000_000, // 1G
	})
	if err != nil {
		t.Fatalf("CreateVM error: %v", err)
	}
	if vm.RootSize != 1_000_000_000 {
		t.Errorf("RootSize = %d, want 1000000000", vm.RootSize)
	}
}

func TestCreateVMRootSizeTooSmall(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "tiny-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 1_000_000, // 1M — below 64M minimum
	})
	if err == nil {
		t.Fatal("expected error for root_size below minimum")
	}
	if !errors.Is(err, domain.ErrValidation) {
		t.Errorf("err = %v, want ErrValidation", err)
	}
}

func TestExpandRootSize(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "expand-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 1_000_000_000,
	})

	err := svc.ExpandRootSize(context.Background(), vm.ID, 2_000_000_000)
	if err != nil {
		t.Fatalf("ExpandRootSize error: %v", err)
	}

	got, _ := svc.GetVM(context.Background(), vm.ID)
	if got.RootSize != 2_000_000_000 {
		t.Errorf("RootSize = %d, want 2000000000", got.RootSize)
	}
}

func TestExpandRootSizeShrinkFails(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "shrink-vm", Role: domain.VMRoleAgent, Image: "alpine:latest",
		Runtime: "runc", RootSize: 2_000_000_000,
	})

	err := svc.ExpandRootSize(context.Background(), vm.ID, 1_000_000_000)
	if err == nil {
		t.Fatal("expected error when shrinking")
	}
}

func TestCreateVMInvalidRole(t *testing.T) {
	svc := app.NewVMService(newMockStore(), newMockRuntime(), &cni.NoopNetwork{})
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
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

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
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

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
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

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
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

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
	svc := app.NewVMService(store, newMockRuntime(), &cni.NoopNetwork{})

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
	svc := app.NewVMService(store, newMockRuntime(), &cni.NoopNetwork{})

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

func TestExecVMEmptyCmd(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "exec-empty", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	_, err := svc.ExecVM(context.Background(), vm.ID, []string{})
	if err == nil {
		t.Fatal("expected error for empty cmd")
	}
}

func TestResetNetworkNoVMs(t *testing.T) {
	svc := app.NewVMService(newMockStore(), newMockRuntime(), &cni.NoopNetwork{})

	if err := svc.ResetNetwork(context.Background()); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

func TestResetNetworkWithVMs(t *testing.T) {
	store := newMockStore()
	svc := app.NewVMService(store, newMockRuntime(), &cni.NoopNetwork{})

	svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "blocker", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	err := svc.ResetNetwork(context.Background())
	if err == nil {
		t.Fatal("expected error when VMs exist")
	}
	if !errors.Is(err, domain.ErrNetworkInUse) {
		t.Errorf("err = %v, want ErrNetworkInUse", err)
	}
}

// --- drive tests ---

func TestCreateDrive(t *testing.T) {
	svc, _, _, ds, st := newSvcWithDrives()

	d, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "test-data", Size: "1G", MountPath: "/data",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.Name != "test-data" {
		t.Errorf("name = %q, want %q", d.Name, "test-data")
	}
	if d.SizeBytes != 1_000_000_000 {
		t.Errorf("size = %d, want 1000000000", d.SizeBytes)
	}
	if d.MountPath != "/data" {
		t.Errorf("mount_path = %q, want /data", d.MountPath)
	}
	if _, ok := ds.drives[d.ID]; !ok {
		t.Error("drive not in store")
	}
	if !st.volumes[d.Name] {
		t.Error("volume not created in storage")
	}
}

func TestCreateDriveValidation(t *testing.T) {
	svc, _, _, _, _ := newSvcWithDrives()

	tests := []struct {
		name   string
		params domain.CreateDriveParams
	}{
		{"empty name", domain.CreateDriveParams{Size: "1G", MountPath: "/data"}},
		{"empty size", domain.CreateDriveParams{Name: "d", MountPath: "/data"}},
		{"empty mount_path", domain.CreateDriveParams{Name: "d", Size: "1G"}},
		{"invalid size", domain.CreateDriveParams{Name: "d", Size: "abc", MountPath: "/data"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateDrive(context.Background(), tt.params)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDeleteDrive(t *testing.T) {
	svc, _, _, ds, st := newSvcWithDrives()

	d, _ := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "delete-me", Size: "500M", MountPath: "/data",
	})

	if err := svc.DeleteDrive(context.Background(), d.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := ds.drives[d.ID]; ok {
		t.Error("drive still in store")
	}
	if st.volumes[d.Name] {
		t.Error("volume still in storage")
	}
}

func TestDeleteDriveAttached(t *testing.T) {
	svc, _, _, _, _ := newSvcWithDrives()

	d, _ := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "attached", Size: "1G", MountPath: "/data",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "vm1", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDrive(context.Background(), d.ID, vm.ID)

	err := svc.DeleteDrive(context.Background(), d.ID)
	if !errors.Is(err, domain.ErrDriveAttached) {
		t.Errorf("err = %v, want ErrDriveAttached", err)
	}
}

func TestAttachDetachDrive(t *testing.T) {
	svc, store, rt, ds, _ := newSvcWithDrives()

	d, _ := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "workspace", Size: "2G", MountPath: "/workspace",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "worker", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	// Attach
	if err := svc.AttachDrive(context.Background(), d.ID, vm.ID); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got, _ := ds.GetDrive(context.Background(), d.ID)
	if got.VMID != vm.ID {
		t.Errorf("drive vm_id = %q, want %q", got.VMID, vm.ID)
	}
	// Container should be recreated
	if _, ok := rt.containers[vm.ID]; !ok {
		t.Error("container not recreated after attach")
	}

	// VM state should still be created (not started)
	vmGot, _ := store.Get(context.Background(), vm.ID)
	if vmGot.State != domain.VMStateCreated {
		t.Errorf("vm state = %q, want created", vmGot.State)
	}

	// Detach
	if err := svc.DetachDrive(context.Background(), d.ID); err != nil {
		t.Fatalf("detach: %v", err)
	}
	got, _ = ds.GetDrive(context.Background(), d.ID)
	if got.VMID != "" {
		t.Errorf("drive vm_id = %q, want empty", got.VMID)
	}
}

func TestAttachDriveRunningVMFails(t *testing.T) {
	svc, _, _, _, _ := newSvcWithDrives()

	d, _ := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "data", Size: "1G", MountPath: "/data",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "running-vm", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	err := svc.AttachDrive(context.Background(), d.ID, vm.ID)
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}

func TestDeleteVMAutoDetachesDrives(t *testing.T) {
	svc, _, _, ds, _ := newSvcWithDrives()

	d, _ := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "persistent", Size: "1G", MountPath: "/data",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "ephemeral-vm", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDrive(context.Background(), d.ID, vm.ID)

	// Delete the VM
	if err := svc.DeleteVM(context.Background(), vm.ID); err != nil {
		t.Fatalf("delete vm: %v", err)
	}

	// Drive should still exist but be detached
	got, err := ds.GetDrive(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("get drive after vm delete: %v", err)
	}
	if got.VMID != "" {
		t.Errorf("drive vm_id = %q, want empty after VM delete", got.VMID)
	}
}

func TestListDrives(t *testing.T) {
	svc, _, _, _, _ := newSvcWithDrives()

	svc.CreateDrive(context.Background(), domain.CreateDriveParams{Name: "d1", Size: "1G", MountPath: "/a"})
	svc.CreateDrive(context.Background(), domain.CreateDriveParams{Name: "d2", Size: "2G", MountPath: "/b"})

	drives, err := svc.ListDrives(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(drives) != 2 {
		t.Errorf("count = %d, want 2", len(drives))
	}
}

func TestGetDrive(t *testing.T) {
	svc, _, _, _, _ := newSvcWithDrives()

	created, _ := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "get-me", Size: "500Mi", MountPath: "/data",
	})

	got, err := svc.GetDrive(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "get-me" {
		t.Errorf("name = %q, want %q", got.Name, "get-me")
	}
}

// --- device tests ---

func TestCreateDevice(t *testing.T) {
	svc, _, _, devStore := newSvcWithDevices()

	d, err := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name:          "my-null",
		HostPath:      "/dev/null",
		ContainerPath: "/dev/null",
		Permissions:   "rw",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.HostPath != "/dev/null" {
		t.Errorf("host_path = %q, want /dev/null", d.HostPath)
	}
	if d.ContainerPath != "/dev/null" {
		t.Errorf("container_path = %q, want /dev/null", d.ContainerPath)
	}
	if d.Permissions != "rw" {
		t.Errorf("permissions = %q, want rw", d.Permissions)
	}
	if d.ID == "" {
		t.Error("id is empty")
	}
	if _, ok := devStore.devices[d.ID]; !ok {
		t.Error("device not in store")
	}
}

func TestCreateDeviceValidation(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	tests := []struct {
		name   string
		params domain.CreateDeviceParams
	}{
		{"missing name", domain.CreateDeviceParams{HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw"}},
		{"empty host_path", domain.CreateDeviceParams{Name: "dev1", ContainerPath: "/dev/x", Permissions: "rw"}},
		{"nonexistent host_path", domain.CreateDeviceParams{Name: "dev2", HostPath: "/dev/nonexistent-device-xyz", ContainerPath: "/dev/x", Permissions: "rw"}},
		{"host_path not a device", domain.CreateDeviceParams{Name: "dev3", HostPath: "/tmp", ContainerPath: "/dev/x", Permissions: "rw"}},
		{"empty container_path", domain.CreateDeviceParams{Name: "dev4", HostPath: "/dev/null", Permissions: "rw"}},
		{"non-absolute container_path", domain.CreateDeviceParams{Name: "dev5", HostPath: "/dev/null", ContainerPath: "dev/x", Permissions: "rw"}},
		{"empty permissions", domain.CreateDeviceParams{Name: "dev6", HostPath: "/dev/null", ContainerPath: "/dev/x"}},
		{"invalid permissions char", domain.CreateDeviceParams{Name: "dev7", HostPath: "/dev/null", ContainerPath: "/dev/x", Permissions: "rwx"}},
		{"duplicate permissions", domain.CreateDeviceParams{Name: "dev8", HostPath: "/dev/null", ContainerPath: "/dev/x", Permissions: "rrw"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateDevice(context.Background(), tt.params)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDeleteDevice(t *testing.T) {
	svc, _, _, devStore := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "del-me", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})

	if err := svc.DeleteDevice(context.Background(), d.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := devStore.devices[d.ID]; ok {
		t.Error("device still in store")
	}
}

func TestDeleteDeviceAttached(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "attached-dev", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "vm1", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDevice(context.Background(), d.ID, vm.ID)

	err := svc.DeleteDevice(context.Background(), d.ID)
	if !errors.Is(err, domain.ErrDeviceAttached) {
		t.Errorf("err = %v, want ErrDeviceAttached", err)
	}
}

func TestAttachDetachDevice(t *testing.T) {
	svc, store, rt, devStore := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "attach-dev", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "worker", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	// Attach
	if err := svc.AttachDevice(context.Background(), d.ID, vm.ID); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got, _ := devStore.GetDevice(context.Background(), d.ID)
	if got.VMID != vm.ID {
		t.Errorf("device vm_id = %q, want %q", got.VMID, vm.ID)
	}
	// Container should be recreated
	if _, ok := rt.containers[vm.ID]; !ok {
		t.Error("container not recreated after attach")
	}
	// VM state should still be created (not started)
	vmGot, _ := store.Get(context.Background(), vm.ID)
	if vmGot.State != domain.VMStateCreated {
		t.Errorf("vm state = %q, want created", vmGot.State)
	}

	// Detach
	if err := svc.DetachDevice(context.Background(), d.ID); err != nil {
		t.Fatalf("detach: %v", err)
	}
	got, _ = devStore.GetDevice(context.Background(), d.ID)
	if got.VMID != "" {
		t.Errorf("device vm_id = %q, want empty", got.VMID)
	}
}

func TestAttachDeviceRunningVMFails(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "run-dev", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "running-vm", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	err := svc.AttachDevice(context.Background(), d.ID, vm.ID)
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}

func TestDeleteVMAutoDetachesDevices(t *testing.T) {
	svc, _, _, devStore := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "auto-detach", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "ephemeral-vm", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDevice(context.Background(), d.ID, vm.ID)

	// Delete the VM
	if err := svc.DeleteVM(context.Background(), vm.ID); err != nil {
		t.Fatalf("delete vm: %v", err)
	}

	// Device should still exist but be detached
	got, err := devStore.GetDevice(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("get device after vm delete: %v", err)
	}
	if got.VMID != "" {
		t.Errorf("device vm_id = %q, want empty after VM delete", got.VMID)
	}
}

func TestListDevices(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "list-null", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "r",
	})
	svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "list-zero", HostPath: "/dev/zero", ContainerPath: "/dev/zero", Permissions: "rw",
	})

	devices, err := svc.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 2 {
		t.Errorf("count = %d, want 2", len(devices))
	}
}

func TestGetDevice(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	created, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "get-dev", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw", GID: 10,
	})

	got, err := svc.GetDevice(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GID != 10 {
		t.Errorf("gid = %d, want 10", got.GID)
	}
}

func TestDetachDeviceAlreadyDetached(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "unattached", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})

	// Detach an unattached device — should be idempotent (no error)
	if err := svc.DetachDevice(context.Background(), d.ID); err != nil {
		t.Fatalf("detach unattached: %v", err)
	}
}

func TestAttachDeviceAlreadyAttached(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "double-attach", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vmA, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "vm-a", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	vmB, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "vm-b", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDevice(context.Background(), d.ID, vmA.ID)

	err := svc.AttachDevice(context.Background(), d.ID, vmB.ID)
	if !errors.Is(err, domain.ErrDeviceAttached) {
		t.Errorf("err = %v, want ErrDeviceAttached", err)
	}
}

func TestDetachDeviceRunningVMFails(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "detach-run", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "running-vm", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDevice(context.Background(), d.ID, vm.ID)
	svc.StartVM(context.Background(), vm.ID)

	err := svc.DetachDevice(context.Background(), d.ID)
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}

func TestCreateDeviceWithGID(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, err := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name:          "gid-dev",
		HostPath:      "/dev/null",
		ContainerPath: "/dev/null",
		Permissions:   "rw",
		GID:           44,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.GID != 44 {
		t.Errorf("gid = %d, want 44", d.GID)
	}
}

func TestCreateVMInvalidName(t *testing.T) {
	svc := app.NewVMService(newMockStore(), newMockRuntime(), &cni.NoopNetwork{})
	tests := []struct {
		name   string
		vmName string
	}{
		{"starts with dash", "-bad"},
		{"ends with dash", "bad-"},
		{"uppercase", "Bad"},
		{"too long", "abcdefghijklmnopqrstuvwxy"}, // 25 chars
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
				Name: tt.vmName, Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
			})
			if !errors.Is(err, domain.ErrValidation) {
				t.Errorf("err = %v, want ErrValidation", err)
			}
		})
	}
}

func TestCreateDriveInvalidName(t *testing.T) {
	svc, _, _, _, _ := newSvcWithDrives()
	tests := []struct {
		name      string
		driveName string
	}{
		{"starts with dash", "-bad"},
		{"ends with dash", "bad-"},
		{"uppercase", "Bad"},
		{"too long", "abcdefghijklmnopqrstuvwxy"}, // 25 chars
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
				Name: tt.driveName, Size: "1G", MountPath: "/data",
			})
			if !errors.Is(err, domain.ErrValidation) {
				t.Errorf("err = %v, want ErrValidation", err)
			}
		})
	}
}

func TestCreateDeviceInvalidName(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()
	tests := []struct {
		name       string
		deviceName string
	}{
		{"starts with dash", "-bad"},
		{"ends with dash", "bad-"},
		{"uppercase", "Bad"},
		{"too long", "abcdefghijklmnopqrstuvwxy"}, // 25 chars
		{"missing name", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
				Name: tt.deviceName, HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
			})
			if !errors.Is(err, domain.ErrValidation) {
				t.Errorf("err = %v, want ErrValidation", err)
			}
		})
	}
}

func TestGetVMByName(t *testing.T) {
	store := newMockStore()
	svc := app.NewVMService(store, newMockRuntime(), &cni.NoopNetwork{})

	created, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "find-me", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	got, err := svc.GetVM(context.Background(), "find-me")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("id = %q, want %q", got.ID, created.ID)
	}
}

func TestDeleteVMByName(t *testing.T) {
	store := newMockStore()
	svc := app.NewVMService(store, newMockRuntime(), &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "delete-by-name", Role: domain.VMRoleAgent, Image: "alpine:latest", Runtime: "runc",
	})

	if err := svc.DeleteVM(context.Background(), "delete-by-name"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := store.Get(context.Background(), vm.ID)
	if err != domain.ErrNotFound {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
}

// --- DNS lifecycle tests ---

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
