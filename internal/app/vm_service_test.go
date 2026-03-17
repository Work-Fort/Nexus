// SPDX-License-Identifier: GPL-3.0-or-later
package app_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
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
		if len(filter.Tags) > 0 && !matchTags(vm.Tags, filter.Tags, filter.TagMatch) {
			continue
		}
		result = append(result, vm)
	}
	return result, nil
}

func matchTags(vmTags, filterTags []string, mode string) bool {
	if mode == "any" {
		for _, ft := range filterTags {
			for _, vt := range vmTags {
				if vt == ft {
					return true
				}
			}
		}
		return false
	}
	// Default: AND — all filter tags must be present
	for _, ft := range filterTags {
		found := false
		for _, vt := range vmTags {
			if vt == ft {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (m *mockStore) SetTags(_ context.Context, vmID string, tags []string) error {
	vm, ok := m.vms[vmID]
	if !ok {
		return domain.ErrNotFound
	}
	vm.Tags = tags
	return nil
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

func (m *mockStore) UpdateRestartPolicy(_ context.Context, id string, policy domain.RestartPolicy, strategy domain.RestartStrategy) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.RestartPolicy = policy
	vm.RestartStrategy = strategy
	return nil
}

func (m *mockStore) UpdateShell(_ context.Context, id, shell string) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.Shell = shell
	return nil
}

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

func (m *mockStore) UpdateEnv(_ context.Context, id string, env map[string]string) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.Env = env
	return nil
}

func (m *mockStore) Delete(_ context.Context, id string) error {
	delete(m.vms, id)
	return nil
}

// --- mock Runtime ---

type mockRuntime struct {
	containers   map[string]bool // id -> running
	execResult   *domain.ExecResult
	execErr      error
	detectDistro string
	lastMounts   []domain.Mount
	initScript   string // last InitScriptPath passed to Create
	mu           sync.Mutex
	execCalled   bool
	lastExecCmd  []string
	allExecCmds  [][]string
	execSignal   chan struct{} // closed on each exec call
	stopCalls    []string     // IDs passed to Stop
}

func newMockRuntime() *mockRuntime {
	return &mockRuntime{
		containers: make(map[string]bool),
		execResult: &domain.ExecResult{ExitCode: 0, Stdout: "ok\n"},
	}
}

func (m *mockRuntime) Create(_ context.Context, id, image, runtime string, opts ...domain.CreateOpt) error {
	cfg := &domain.CreateConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	m.lastMounts = cfg.Mounts
	m.initScript = cfg.InitScriptPath
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) Start(_ context.Context, id string, _ ...domain.CreateOpt) error {
	m.containers[id] = true
	return nil
}

func (m *mockRuntime) Stop(_ context.Context, id string) error {
	m.containers[id] = false
	m.stopCalls = append(m.stopCalls, id)
	return nil
}

func (m *mockRuntime) Delete(_ context.Context, id string) error {
	delete(m.containers, id)
	return nil
}

func (m *mockRuntime) Exec(_ context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	m.mu.Lock()
	m.execCalled = true
	m.lastExecCmd = cmd
	m.allExecCmds = append(m.allExecCmds, cmd)
	sig := m.execSignal
	m.mu.Unlock()
	if sig != nil {
		sig <- struct{}{} // buffered channel, won't block
	}
	if m.execErr != nil {
		return nil, m.execErr
	}
	return m.execResult, nil
}

// waitForExecs blocks until n exec calls have been received, or returns false on timeout.
func (m *mockRuntime) waitForExecs(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for range n {
		select {
		case <-m.execSignal:
		case <-deadline:
			return false
		}
	}
	return true
}

// hasExecCmd returns true if any recorded exec call starts with the given binary.
func (m *mockRuntime) hasExecCmd(bin string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cmd := range m.allExecCmds {
		if len(cmd) > 0 && cmd[0] == bin {
			return true
		}
	}
	return false
}

func (m *mockRuntime) hasMount(containerPath string) bool {
	for _, mount := range m.lastMounts {
		if mount.ContainerPath == containerPath {
			return true
		}
	}
	return false
}

func (m *mockRuntime) ExecStream(_ context.Context, id string, cmd []string, stdout, stderr io.Writer) (int, error) {
	stdout.Write([]byte("ok\n")) //nolint:errcheck
	return 0, nil
}

func (m *mockRuntime) ExecConsole(_ context.Context, id string, cmd []string, cols, rows uint16) (*domain.ConsoleSession, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockRuntime) SetSnapshotQuota(_ context.Context, _ string, _ int64) error {
	return nil
}

func (m *mockRuntime) DetectDistro(_ context.Context, _ string) (string, error) {
	if m.detectDistro != "" {
		return m.detectDistro, nil
	}
	return "alpine", nil
}

func (m *mockRuntime) ExportImage(_ context.Context, _ string, w io.Writer) error {
	_, err := w.Write([]byte("mock-image-data"))
	return err
}

func (m *mockRuntime) ImportImage(_ context.Context, r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("empty image data")
	}
	return "imported:latest", nil
}

func (m *mockRuntime) WatchExits(_ context.Context, _ func(string, uint32)) error {
	return nil
}

func (m *mockRuntime) SnapshotRootfs(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockRuntime) RestoreRootfs(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockRuntime) DeleteRootfsSnapshot(_ context.Context, _ string) error {
	return nil
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

func (m *mockStorage) SendVolume(_ context.Context, name string, w io.Writer) error {
	_, err := w.Write([]byte("btrfs-stream-" + name))
	return err
}

func (m *mockStorage) ReceiveVolume(_ context.Context, name string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("empty btrfs stream")
	}
	m.volumes[name] = true
	return nil
}

func (m *mockStorage) SnapshotVolume(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockStorage) RestoreVolume(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockStorage) DeleteVolumeSnapshot(_ context.Context, _ string) error {
	return nil
}

func (m *mockStorage) SendVolumeSnapshot(_ context.Context, _ string, w io.Writer) error {
	_, err := w.Write([]byte("btrfs-snapshot-stream"))
	return err
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

// --- mock TemplateStore ---

type mockTemplateStore struct {
	templates map[string]*domain.Template
}

func newMockTemplateStore() *mockTemplateStore {
	return &mockTemplateStore{templates: make(map[string]*domain.Template)}
}

func (m *mockTemplateStore) CreateTemplate(_ context.Context, t *domain.Template) error {
	m.templates[t.ID] = t
	return nil
}

func (m *mockTemplateStore) GetTemplate(_ context.Context, id string) (*domain.Template, error) {
	t, ok := m.templates[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return t, nil
}

func (m *mockTemplateStore) GetTemplateByName(_ context.Context, name string) (*domain.Template, error) {
	for _, t := range m.templates {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockTemplateStore) GetTemplateByDistro(_ context.Context, distro string) (*domain.Template, error) {
	for _, t := range m.templates {
		if t.Distro == distro {
			return t, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockTemplateStore) ResolveTemplate(_ context.Context, ref string) (*domain.Template, error) {
	if t, ok := m.templates[ref]; ok {
		return t, nil
	}
	for _, t := range m.templates {
		if t.Name == ref {
			return t, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockTemplateStore) ListTemplates(_ context.Context) ([]*domain.Template, error) {
	var result []*domain.Template
	for _, t := range m.templates {
		result = append(result, t)
	}
	return result, nil
}

func (m *mockTemplateStore) UpdateTemplate(_ context.Context, id, name, distro, script string) error {
	t, ok := m.templates[id]
	if !ok {
		return domain.ErrNotFound
	}
	t.Name = name
	t.Distro = distro
	t.Script = script
	return nil
}

func (m *mockTemplateStore) DeleteTemplate(_ context.Context, id string) error {
	delete(m.templates, id)
	return nil
}

func (m *mockTemplateStore) CountTemplateRefs(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// --- tests ---

func TestCreateVM(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name:    "test-agent",
		Tags:    []string{"agent"},
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
		Name: "sized-vm", Tags: []string{"agent"}, Image: "alpine:latest",
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
		Name: "tiny-vm", Tags: []string{"agent"}, Image: "alpine:latest",
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
		Name: "expand-vm", Tags: []string{"agent"}, Image: "alpine:latest",
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
		Name: "shrink-vm", Tags: []string{"agent"}, Image: "alpine:latest",
		Runtime: "runc", RootSize: 2_000_000_000,
	})

	err := svc.ExpandRootSize(context.Background(), vm.ID, 1_000_000_000)
	if err == nil {
		t.Fatal("expected error when shrinking")
	}
}

func TestCreateVMInvalidTag(t *testing.T) {
	svc := app.NewVMService(newMockStore(), newMockRuntime(), &cni.NoopNetwork{})
	_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "bad", Tags: []string{"INVALID"}, Image: "alpine:latest", Runtime: "runc",
	})
	if err == nil {
		t.Fatal("expected error for invalid tag")
	}
}

func TestStartVM(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "start-me", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "running", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "stop-me", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "delete-me", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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

	svc.CreateVM(context.Background(), domain.CreateVMParams{Name: "a1", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc"})
	svc.CreateVM(context.Background(), domain.CreateVMParams{Name: "s1", Tags: []string{"service"}, Image: "alpine:latest", Runtime: "runc"})

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
		Name: "get-me", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "exec-empty", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	_, err := svc.ExecVM(context.Background(), vm.ID, []string{})
	if err == nil {
		t.Fatal("expected error for empty cmd")
	}
}

func TestExecStreamVMRejectsStopped(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "stream-stopped", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})

	var stdout, stderr bytes.Buffer
	_, err := svc.ExecStreamVM(context.Background(), vm.ID, []string{"ls"}, &stdout, &stderr)
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestExecStreamVMEmptyCmd(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "stream-empty", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	var stdout, stderr bytes.Buffer
	_, err := svc.ExecStreamVM(context.Background(), vm.ID, []string{}, &stdout, &stderr)
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
}

func TestExecStreamVMSuccess(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "stream-ok", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(context.Background(), vm.ID)

	var stdout, stderr bytes.Buffer
	exitCode, err := svc.ExecStreamVM(context.Background(), vm.ID, []string{"echo", "hi"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if stdout.String() != "ok\n" {
		t.Fatalf("expected stdout %q, got %q", "ok\n", stdout.String())
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
		Name: "blocker", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "vm1", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "worker", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "running-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "ephemeral-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "vm1", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "worker", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "running-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "ephemeral-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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

// --- export/import integration tests ---

func TestExportImportRoundTrip(t *testing.T) {
	svc, store, _, ds, st, _, _ := newSvcFull()
	ctx := context.Background()

	// Create a VM with a drive attached.
	vm, err := svc.CreateVM(ctx, domain.CreateVMParams{
		Name: "export-me", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	d, err := svc.CreateDrive(ctx, domain.CreateDriveParams{
		Name: "data", Size: "1G", MountPath: "/data",
	})
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := svc.AttachDrive(ctx, d.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// Export the VM.
	var archive bytes.Buffer
	if err := svc.ExportVM(ctx, vm.ID, false, &archive); err != nil {
		t.Fatalf("ExportVM: %v", err)
	}
	if archive.Len() == 0 {
		t.Fatal("archive is empty")
	}

	// Delete the original VM and drive so names don't conflict.
	if err := svc.DetachDrive(ctx, d.ID); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if err := svc.DeleteVM(ctx, vm.ID); err != nil {
		t.Fatalf("delete VM: %v", err)
	}
	if err := svc.DeleteDrive(ctx, d.ID); err != nil {
		t.Fatalf("delete drive: %v", err)
	}

	// Import the archive.
	result, err := svc.ImportVM(ctx, &archive, false)
	if err != nil {
		t.Fatalf("ImportVM: %v", err)
	}

	// Verify imported VM.
	if result.VM.Name != "export-me" {
		t.Errorf("imported name = %q, want %q", result.VM.Name, "export-me")
	}
	if len(result.VM.Tags) != 1 || result.VM.Tags[0] != "agent" {
		t.Errorf("imported tags = %v, want [agent]", result.VM.Tags)
	}
	if result.VM.State != domain.VMStateCreated {
		t.Errorf("imported state = %q, want created", result.VM.State)
	}
	if result.VM.Image != "alpine:latest" {
		t.Errorf("imported image = %q, want alpine:latest", result.VM.Image)
	}

	// Verify VM is in the store.
	got, err := store.Get(ctx, result.VM.ID)
	if err != nil {
		t.Fatalf("get imported VM: %v", err)
	}
	if got.Name != "export-me" {
		t.Errorf("stored name = %q, want %q", got.Name, "export-me")
	}

	// Verify drive was imported and attached.
	drives, err := ds.GetDrivesByVM(ctx, result.VM.ID)
	if err != nil {
		t.Fatalf("get drives: %v", err)
	}
	if len(drives) != 1 {
		t.Fatalf("drive count = %d, want 1", len(drives))
	}
	if drives[0].Name != "data" {
		t.Errorf("drive name = %q, want %q", drives[0].Name, "data")
	}
	if drives[0].MountPath != "/data" {
		t.Errorf("drive mount_path = %q, want /data", drives[0].MountPath)
	}

	// Verify storage volume was received.
	if !st.volumes["data"] {
		t.Error("storage volume 'data' not received")
	}
}

func TestExportRunningVMFails(t *testing.T) {
	svc, _, _, _, _, _, _ := newSvcFull()
	ctx := context.Background()

	vm, _ := svc.CreateVM(ctx, domain.CreateVMParams{
		Name: "running-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	svc.StartVM(ctx, vm.ID)

	var buf bytes.Buffer
	err := svc.ExportVM(ctx, vm.ID, false, &buf)
	if err == nil {
		t.Fatal("expected error exporting running VM")
	}
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}

func TestImportNameConflict(t *testing.T) {
	svc, _, _, _, _, _, _ := newSvcFull()
	ctx := context.Background()

	// Create a VM and export it.
	vm, _ := svc.CreateVM(ctx, domain.CreateVMParams{
		Name: "conflict-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	var archive bytes.Buffer
	if err := svc.ExportVM(ctx, vm.ID, false, &archive); err != nil {
		t.Fatalf("ExportVM: %v", err)
	}

	// Import without deleting the original — name conflict.
	_, err := svc.ImportVM(ctx, &archive, false)
	if err == nil {
		t.Fatal("expected error for name conflict")
	}
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestExportWithDNS(t *testing.T) {
	svc, _, _, _, _, _, _ := newSvcFull()
	ctx := context.Background()

	vm, _ := svc.CreateVM(ctx, domain.CreateVMParams{
		Name: "dns-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
		DNSConfig: &domain.DNSConfig{
			Servers: []string{"8.8.8.8"},
			Search:  []string{"test.local"},
		},
	})

	var archive bytes.Buffer
	if err := svc.ExportVM(ctx, vm.ID, false, &archive); err != nil {
		t.Fatalf("ExportVM: %v", err)
	}

	// Delete original, import, and verify DNS config is restored.
	svc.DeleteVM(ctx, vm.ID)

	result, err := svc.ImportVM(ctx, &archive, false)
	if err != nil {
		t.Fatalf("ImportVM: %v", err)
	}
	if result.VM.DNSConfig == nil {
		t.Fatal("DNS config not restored")
	}
	if result.VM.DNSConfig.Servers[0] != "8.8.8.8" {
		t.Errorf("dns server = %q, want 8.8.8.8", result.VM.DNSConfig.Servers[0])
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
		Name: "vm-a", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	vmB, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "vm-b", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
	})
	svc.AttachDevice(context.Background(), d.ID, vmA.ID)

	err := svc.AttachDevice(context.Background(), d.ID, vmB.ID)
	if !errors.Is(err, domain.ErrDeviceAttached) {
		t.Errorf("err = %v, want ErrDeviceAttached", err)
	}
}

func newSvcFull() (*app.VMService, *mockStore, *mockRuntime, *mockDriveStore, *mockStorage, *mockDeviceStore, *mockDNS) {
	store := newMockStore()
	rt := newMockRuntime()
	ds := newMockDriveStore()
	st := newMockStorage()
	devStore := newMockDeviceStore()
	dns := newMockDNS()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
		app.WithStorage(ds, st),
		app.WithDeviceStore(devStore),
		app.WithDNS(dns),
	)
	return svc, store, rt, ds, st, devStore, dns
}

func TestDetachDeviceRunningVMFails(t *testing.T) {
	svc, _, _, _ := newSvcWithDevices()

	d, _ := svc.CreateDevice(context.Background(), domain.CreateDeviceParams{
		Name: "detach-run", HostPath: "/dev/null", ContainerPath: "/dev/null", Permissions: "rw",
	})
	vm, _ := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name: "running-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
				Name: tt.vmName, Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "find-me", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "delete-by-name", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "web-server", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "cleanup-vm", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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
		Name: "custom-dns", Tags: []string{"agent"}, Image: "alpine:latest", Runtime: "runc",
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

func TestSyncShell(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/bash\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateRunning,
		}
		store.vms[vm.ID] = vm

		got, err := svc.SyncShell(context.Background(), "vm-1")
		if err != nil {
			t.Fatalf("SyncShell: %v", err)
		}
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash", got.Shell)
		}
	})

	t.Run("no-op when shell unchanged", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/bash\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateRunning,
			Shell: "/bin/bash",
		}
		store.vms[vm.ID] = vm

		got, err := svc.SyncShell(context.Background(), "vm-1")
		if err != nil {
			t.Fatalf("SyncShell: %v", err)
		}
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash", got.Shell)
		}
	})

	t.Run("not running", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm

		_, err := svc.SyncShell(context.Background(), "vm-1")
		if !errors.Is(err, domain.ErrInvalidState) {
			t.Errorf("err = %v, want ErrInvalidState", err)
		}
	})

	t.Run("exec failure", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execErr = fmt.Errorf("exec failed")
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateRunning,
		}
		store.vms[vm.ID] = vm

		_, err := svc.SyncShell(context.Background(), "vm-1")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("malformed output", func(t *testing.T) {
		cases := []struct {
			name     string
			stdout   string
			exitCode int
		}{
			{"too few fields", "root:x:0:0\n", 0},
			{"empty shell", "root:x:0:0:root:/root:\n", 0},
			{"relative path", "root:x:0:0:root:/root:bash\n", 0},
			{"empty output", "", 0},
			{"non-zero exit", "", 1},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				store := newMockStore()
				rt := newMockRuntime()
				rt.execResult = &domain.ExecResult{
					ExitCode: tc.exitCode,
					Stdout:   tc.stdout,
				}
				svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

				vm := &domain.VM{
					ID: "vm-1", Name: "test", State: domain.VMStateRunning,
				}
				store.vms[vm.ID] = vm

				_, err := svc.SyncShell(context.Background(), "vm-1")
				if err == nil {
					t.Fatal("expected error for malformed output")
				}
			})
		}
	})
}

func TestStartVM_AutoSyncShell(t *testing.T) {
	t.Run("syncs shell when empty", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/bash\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-1"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		// Auto-sync runs in a goroutine; give it a moment.
		time.Sleep(100 * time.Millisecond)

		got := store.vms["vm-1"]
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash", got.Shell)
		}
	})

	t.Run("skips sync when shell already set", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{
			ExitCode: 0,
			Stdout:   "root:x:0:0:root:/root:/bin/zsh\n",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
			Shell: "/bin/bash",
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-1"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		time.Sleep(100 * time.Millisecond)

		got := store.vms["vm-1"]
		if got.Shell != "/bin/bash" {
			t.Errorf("Shell = %q, want /bin/bash (unchanged)", got.Shell)
		}
	})
}

func TestTemplateCRUD(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	ts := newMockTemplateStore()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithTemplateStore(ts))

	ctx := context.Background()

	// Create
	tmpl, err := svc.CreateTemplate(ctx, domain.CreateTemplateParams{
		Name:   "test-openrc",
		Distro: "test",
		Script: "#!/bin/sh\nexec /sbin/init",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tmpl.Name != "test-openrc" {
		t.Errorf("name = %q", tmpl.Name)
	}

	// Get
	got, err := svc.GetTemplate(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Distro != "test" {
		t.Errorf("distro = %q", got.Distro)
	}

	// List
	all, err := svc.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("list count = %d", len(all))
	}

	// Update
	updated, err := svc.UpdateTemplate(ctx, tmpl.ID, domain.CreateTemplateParams{
		Name:   "test-openrc-v2",
		Script: "#!/bin/sh\nexec /sbin/init --new",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "test-openrc-v2" {
		t.Errorf("updated name = %q", updated.Name)
	}

	// Delete
	if err := svc.DeleteTemplate(ctx, tmpl.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestCreateTemplateValidation(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	ts := newMockTemplateStore()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithTemplateStore(ts))

	ctx := context.Background()

	tests := []struct {
		name   string
		params domain.CreateTemplateParams
	}{
		{"missing name", domain.CreateTemplateParams{Distro: "x", Script: "x"}},
		{"missing distro", domain.CreateTemplateParams{Name: "x", Script: "x"}},
		{"missing script", domain.CreateTemplateParams{Name: "x", Distro: "x"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateTemplate(ctx, tc.params)
			if !errors.Is(err, domain.ErrValidation) {
				t.Errorf("err = %v, want ErrValidation", err)
			}
		})
	}
}

func TestCreateVMWithInit(t *testing.T) {
	t.Run("auto-detect distro", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.detectDistro = "alpine"
		ts := newMockTemplateStore()
		ts.templates["tpl-1"] = &domain.Template{
			ID: "tpl-1", Name: "alpine-openrc", Distro: "alpine",
			Script: "#!/bin/sh\nexec /sbin/init",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithTemplateStore(ts))

		vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name: "init-test",
			Init: true,
		})
		if err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		if !vm.Init {
			t.Error("Init = false")
		}
		if vm.TemplateID != "tpl-1" {
			t.Errorf("TemplateID = %q, want tpl-1", vm.TemplateID)
		}
		if rt.initScript == "" {
			t.Error("expected init script path to be set")
		}
	})

	t.Run("explicit template name", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		ts := newMockTemplateStore()
		ts.templates["tpl-1"] = &domain.Template{
			ID: "tpl-1", Name: "my-template", Distro: "custom",
			Script: "#!/bin/sh\necho custom",
		}
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithTemplateStore(ts))

		vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name:         "init-test2",
			Init:         true,
			TemplateName: "my-template",
		})
		if err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		if vm.TemplateID != "tpl-1" {
			t.Errorf("TemplateID = %q, want tpl-1", vm.TemplateID)
		}
	})

	t.Run("no matching template fails", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.detectDistro = "unknown"
		ts := newMockTemplateStore()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{}, app.WithTemplateStore(ts))

		_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name: "init-fail",
			Init: true,
		})
		if err == nil {
			t.Fatal("expected error for missing template")
		}
	})

	t.Run("no template store fails", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name: "init-fail",
			Init: true,
		})
		if !errors.Is(err, domain.ErrValidation) {
			t.Errorf("err = %v, want ErrValidation", err)
		}
	})
}

func TestCreateVM_MetricsBindMount(t *testing.T) {
	t.Run("adds bind mount when node_exporter path set", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
			app.WithConfig(app.VMServiceConfig{
				DefaultImage:   "alpine:latest",
				DefaultRuntime: "io.containerd.runc.v2",
				Metrics: app.MetricsConfig{
					NodeExporterPath: "/opt/nexus/bin/node_exporter",
					ListenPort:       9100,
					Collectors:       []string{"cpu", "meminfo"},
				},
			}),
		)

		_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name: "metrics-test",
		})
		if err != nil {
			t.Fatalf("CreateVM: %v", err)
		}

		if !rt.hasMount("/usr/local/bin/node_exporter") {
			t.Error("expected node_exporter bind mount in create opts")
		}
	})

	t.Run("skips bind mount when node_exporter path empty", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
			app.WithConfig(app.VMServiceConfig{
				DefaultImage:   "alpine:latest",
				DefaultRuntime: "io.containerd.runc.v2",
			}),
		)

		_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name: "no-metrics",
		})
		if err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		if rt.hasMount("/usr/local/bin/node_exporter") {
			t.Error("unexpected node_exporter bind mount")
		}
	})
}

func TestStartVM_MetricsExec(t *testing.T) {
	t.Run("execs node_exporter for non-init VMs when metrics enabled", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{ExitCode: 0, Stdout: "root:x:0:0:root:/root:/bin/sh\n"}
		rt.execSignal = make(chan struct{}, 10)

		svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
			app.WithConfig(app.VMServiceConfig{
				DefaultImage:   "alpine:latest",
				DefaultRuntime: "io.containerd.runc.v2",
				Metrics: app.MetricsConfig{
					NodeExporterPath: "/opt/nexus/bin/node_exporter",
					ListenPort:       9100,
					Collectors:       []string{"cpu", "meminfo"},
				},
			}),
		)

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-1"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		// Wait for both background execs: node_exporter + SyncShell.
		if !rt.waitForExecs(2, 5*time.Second) {
			t.Fatal("timed out waiting for background exec calls")
		}

		if !rt.hasExecCmd("/usr/local/bin/node_exporter") {
			rt.mu.Lock()
			t.Errorf("expected node_exporter exec, got: %v", rt.allExecCmds)
			rt.mu.Unlock()
		}
	})

	t.Run("skips exec for init VMs (supervised by init system)", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{ExitCode: 0, Stdout: "root:x:0:0:root:/root:/bin/sh\n"}
		rt.execSignal = make(chan struct{}, 10)

		svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
			app.WithConfig(app.VMServiceConfig{
				DefaultImage:   "alpine:latest",
				DefaultRuntime: "io.containerd.runc.v2",
				Metrics: app.MetricsConfig{
					NodeExporterPath: "/opt/nexus/bin/node_exporter",
					ListenPort:       9100,
					Collectors:       []string{"cpu"},
				},
			}),
		)

		vm := &domain.VM{
			ID: "vm-2", Name: "init-vm", State: domain.VMStateStopped,
			Init: true, TemplateID: "tpl-1",
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-2"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		// Only SyncShell runs (metrics skipped for init VMs).
		if !rt.waitForExecs(1, 5*time.Second) {
			t.Fatal("timed out waiting for SyncShell exec")
		}

		if rt.hasExecCmd("/usr/local/bin/node_exporter") {
			t.Error("init VM should not exec-start node_exporter (supervised by init)")
		}
	})

	t.Run("skips exec when metrics disabled", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		rt.execResult = &domain.ExecResult{ExitCode: 0, Stdout: "root:x:0:0:root:/root:/bin/sh\n"}
		rt.execSignal = make(chan struct{}, 10)

		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-3", Name: "no-metrics", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-3"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		// Only SyncShell runs (no metrics config).
		if !rt.waitForExecs(1, 5*time.Second) {
			t.Fatal("timed out waiting for SyncShell exec")
		}

		if rt.hasExecCmd("/usr/local/bin/node_exporter") {
			t.Error("exec should not start node_exporter when metrics disabled")
		}
	})
}

func TestInjectMetricsService(t *testing.T) {
	// This is an internal function test using the exported CreateVM path.
	// We verify the init script written contains the node_exporter service.
	store := newMockStore()
	rt := newMockRuntime()
	ts := newMockTemplateStore()
	ts.templates["tpl-alpine"] = &domain.Template{
		ID:     "tpl-alpine",
		Name:   "alpine-openrc",
		Distro: "alpine",
		Script: "#!/bin/sh\napk add --no-cache openrc\nexec /sbin/init",
	}

	svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
		app.WithConfig(app.VMServiceConfig{
			DefaultImage:   "alpine:latest",
			DefaultRuntime: "io.containerd.runc.v2",
			Metrics: app.MetricsConfig{
				NodeExporterPath: "/opt/nexus/bin/node_exporter",
				ListenPort:       9100,
				Collectors:       []string{"cpu", "meminfo"},
			},
		}),
		app.WithTemplateStore(ts),
	)

	_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
		Name:         "inject-test",
		Init:         true,
		TemplateName: "alpine-openrc",
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	// The init script path was captured by mockRuntime.
	if rt.initScript == "" {
		t.Fatal("expected init script to be set")
	}

	// Read the written script and verify it contains the service snippet.
	data, err := os.ReadFile(rt.initScript)
	if err != nil {
		t.Fatalf("read init script: %v", err)
	}
	script := string(data)
	if !strings.Contains(script, "/etc/init.d/node_exporter") {
		t.Error("expected OpenRC service file in init script")
	}
	if !strings.Contains(script, "rc-update add node_exporter") {
		t.Error("expected rc-update in init script")
	}
	if !strings.Contains(script, "--collector.cpu") {
		t.Error("expected collector flags in init script")
	}
}

func TestShutdown_StopsRunningVMs(t *testing.T) {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt, &cni.NoopNetwork{})
	ctx := context.Background()

	// Create two VMs: one running, one stopped.
	vm1, err := svc.CreateVM(ctx, domain.CreateVMParams{Name: "running-vm", Tags: []string{"agent"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.StartVM(ctx, vm1.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	if _, err := svc.CreateVM(ctx, domain.CreateVMParams{Name: "stopped-vm", Tags: []string{"agent"}}); err != nil {
		t.Fatalf("create: %v", err)
	}

	rt.stopCalls = nil // reset after StartVM's implicit stop

	svc.Shutdown(ctx)

	// Should have stopped the running VM only.
	if len(rt.stopCalls) != 1 {
		t.Fatalf("expected 1 stop call, got %d: %v", len(rt.stopCalls), rt.stopCalls)
	}
	if rt.stopCalls[0] != vm1.ID {
		t.Errorf("stopped wrong VM: got %s, want %s", rt.stopCalls[0], vm1.ID)
	}
}
