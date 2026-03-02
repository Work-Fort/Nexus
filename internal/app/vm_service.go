// SPDX-License-Identifier: Apache-2.0

// Package app contains application use-cases that orchestrate domain ports.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/google/uuid"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/bytesize"
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
	store       domain.VMStore
	runtime     domain.Runtime
	network     domain.Network
	driveStore  domain.DriveStore
	storage     domain.Storage
	deviceStore domain.DeviceStore
	config      VMServiceConfig
}

// NewVMService creates a VMService with the given ports and config.
func NewVMService(store domain.VMStore, runtime domain.Runtime, network domain.Network, opts ...func(*VMService)) *VMService {
	svc := &VMService{
		store:   store,
		runtime: runtime,
		network: network,
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

// WithStorage enables drive management with the given store and storage backend.
func WithStorage(driveStore domain.DriveStore, storage domain.Storage) func(*VMService) {
	return func(s *VMService) {
		s.driveStore = driveStore
		s.storage = storage
	}
}

// WithDeviceStore enables device management.
func WithDeviceStore(deviceStore domain.DeviceStore) func(*VMService) {
	return func(s *VMService) {
		s.deviceStore = deviceStore
	}
}

// CreateVM validates parameters, creates a container via the runtime, and
// persists the VM record.
func (s *VMService) CreateVM(ctx context.Context, params domain.CreateVMParams) (*domain.VM, error) {
	if !domain.ValidRole(params.Role) {
		return nil, fmt.Errorf("invalid role %q: %w", params.Role, domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
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

	netInfo, err := s.network.Setup(ctx, vm.ID)
	if err != nil {
		return nil, fmt.Errorf("network setup: %w", err)
	}
	vm.IP = netInfo.IP
	vm.Gateway = netInfo.Gateway
	vm.NetNSPath = netInfo.NetNSPath

	var createOpts []domain.CreateOpt
	if netInfo.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(netInfo.NetNSPath))
	}

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime, createOpts...); err != nil {
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck // best-effort rollback
		return nil, fmt.Errorf("runtime create: %w", err)
	}

	if err := s.store.Create(ctx, vm); err != nil {
		s.runtime.Delete(ctx, vm.ID)    //nolint:errcheck // best-effort rollback
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck // best-effort rollback
		return nil, fmt.Errorf("store create: %w", err)
	}

	log.Info("vm created", "id", vm.ID, "name", vm.Name, "role", vm.Role, "ip", vm.IP)
	return vm, nil
}

// GetVM retrieves a VM by ID.
func (s *VMService) GetVM(ctx context.Context, id string) (*domain.VM, error) {
	return s.store.Get(ctx, id)
}

// ListVMs returns VMs matching the filter.
func (s *VMService) ListVMs(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	return s.store.List(ctx, filter)
}

// StartVM starts a created or stopped VM.
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

// StopVM stops a running VM.
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

// DeleteVM stops the container if running, then removes it and its store record.
func (s *VMService) DeleteVM(ctx context.Context, id string) error {
	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		if err := s.runtime.Stop(ctx, id); err != nil {
			log.Warn("runtime stop before delete failed", "id", id, "err", err)
		}
	}
	if err := s.runtime.Delete(ctx, id); err != nil {
		log.Warn("runtime delete failed", "id", id, "err", err)
	}

	if err := s.network.Teardown(ctx, id); err != nil {
		log.Warn("network teardown failed", "id", id, "err", err)
	}

	if s.driveStore != nil {
		if err := s.driveStore.DetachAllDrives(ctx, id); err != nil {
			log.Warn("detach drives failed", "id", id, "err", err)
		}
	}

	if s.deviceStore != nil {
		if err := s.deviceStore.DetachAllDevices(ctx, id); err != nil {
			log.Warn("detach devices failed", "id", id, "err", err)
		}
	}

	if err := s.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("store delete: %w", err)
	}

	log.Info("vm deleted", "id", id)
	return nil
}

// ExecVM runs a command in a running VM.
func (s *VMService) ExecVM(ctx context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("cmd is required: %w", domain.ErrValidation)
	}

	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	return s.runtime.Exec(ctx, id, cmd)
}

// ResetNetwork deletes the bridge and clears CNI state. Refuses if any VMs exist.
func (s *VMService) ResetNetwork(ctx context.Context) error {
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		return fmt.Errorf("list vms: %w", err)
	}
	if len(vms) > 0 {
		return fmt.Errorf("%d VM(s) exist, delete them first: %w", len(vms), domain.ErrNetworkInUse)
	}
	return s.network.ResetNetwork(ctx)
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

// --- Drive operations ---

// CreateDrive creates a new persistent data volume.
func (s *VMService) CreateDrive(ctx context.Context, params domain.CreateDriveParams) (*domain.Drive, error) {
	if s.storage == nil {
		return nil, fmt.Errorf("drives not enabled: %w", domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if params.MountPath == "" {
		return nil, fmt.Errorf("mount_path is required: %w", domain.ErrValidation)
	}
	if params.Size == "" {
		return nil, fmt.Errorf("size is required: %w", domain.ErrValidation)
	}

	sizeBytes, err := bytesize.Parse(params.Size)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, domain.ErrValidation)
	}

	d := &domain.Drive{
		ID:        uuid.New().String(),
		Name:      params.Name,
		SizeBytes: sizeBytes,
		MountPath: params.MountPath,
		CreatedAt: time.Now().UTC(),
	}

	if _, err := s.storage.CreateVolume(ctx, d.Name, d.SizeBytes); err != nil {
		return nil, fmt.Errorf("create volume: %w", err)
	}

	if err := s.driveStore.CreateDrive(ctx, d); err != nil {
		s.storage.DeleteVolume(ctx, d.Name) //nolint:errcheck // best-effort rollback
		return nil, fmt.Errorf("store create drive: %w", err)
	}

	log.Info("drive created", "id", d.ID, "name", d.Name, "size", d.SizeBytes)
	return d, nil
}

// GetDrive retrieves a drive by ID.
func (s *VMService) GetDrive(ctx context.Context, id string) (*domain.Drive, error) {
	return s.driveStore.GetDrive(ctx, id)
}

// ListDrives returns all drives.
func (s *VMService) ListDrives(ctx context.Context) ([]*domain.Drive, error) {
	return s.driveStore.ListDrives(ctx)
}

// DeleteDrive removes a drive. Fails if the drive is attached to a VM.
func (s *VMService) DeleteDrive(ctx context.Context, id string) error {
	d, err := s.driveStore.GetDrive(ctx, id)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("drive %q attached to VM %s: %w", d.Name, d.VMID, domain.ErrDriveAttached)
	}

	if err := s.storage.DeleteVolume(ctx, d.Name); err != nil {
		return fmt.Errorf("delete volume: %w", err)
	}
	if err := s.driveStore.DeleteDrive(ctx, id); err != nil {
		return fmt.Errorf("store delete drive: %w", err)
	}

	log.Info("drive deleted", "id", id, "name", d.Name)
	return nil
}

// AttachDrive attaches a drive to a stopped VM, recreating the container
// with the new mount.
func (s *VMService) AttachDrive(ctx context.Context, driveID, vmID string) error {
	vm, err := s.store.Get(ctx, vmID)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to attach drives: %w", domain.ErrInvalidState)
	}

	d, err := s.driveStore.GetDrive(ctx, driveID)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("drive already attached to VM %s: %w", d.VMID, domain.ErrDriveAttached)
	}

	if err := s.driveStore.AttachDrive(ctx, driveID, vmID); err != nil {
		return fmt.Errorf("store attach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		s.driveStore.DetachDrive(ctx, driveID) //nolint:errcheck // best-effort rollback
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("drive attached", "drive", d.Name, "vm", vm.Name)
	return nil
}

// DetachDrive detaches a drive from its VM, recreating the container
// without the mount.
func (s *VMService) DetachDrive(ctx context.Context, driveID string) error {
	d, err := s.driveStore.GetDrive(ctx, driveID)
	if err != nil {
		return err
	}
	if d.VMID == "" {
		return nil // already detached, idempotent
	}

	vm, err := s.store.Get(ctx, d.VMID)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to detach drives: %w", domain.ErrInvalidState)
	}

	if err := s.driveStore.DetachDrive(ctx, driveID); err != nil {
		return fmt.Errorf("store detach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("drive detached", "drive", d.Name, "vm", vm.Name)
	return nil
}

// --- Device operations ---

// validatePermissions checks that s contains only 'r', 'w', 'm' with no duplicates.
func validatePermissions(s string) bool {
	if len(s) == 0 || len(s) > 3 {
		return false
	}
	seen := make(map[rune]bool, 3)
	for _, c := range s {
		if c != 'r' && c != 'w' && c != 'm' {
			return false
		}
		if seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

// CreateDevice registers a new host device mapping.
func (s *VMService) CreateDevice(ctx context.Context, params domain.CreateDeviceParams) (*domain.Device, error) {
	if s.deviceStore == nil {
		return nil, fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	if params.HostPath == "" {
		return nil, fmt.Errorf("host_path is required: %w", domain.ErrValidation)
	}
	if params.ContainerPath == "" {
		return nil, fmt.Errorf("container_path is required: %w", domain.ErrValidation)
	}
	if !strings.HasPrefix(params.ContainerPath, "/") {
		return nil, fmt.Errorf("container_path must be absolute: %w", domain.ErrValidation)
	}
	if !validatePermissions(params.Permissions) {
		return nil, fmt.Errorf("permissions must be a combination of r, w, m: %w", domain.ErrValidation)
	}

	fi, err := os.Stat(params.HostPath)
	if err != nil {
		return nil, fmt.Errorf("host_path %q: %v: %w", params.HostPath, err, domain.ErrValidation)
	}
	if fi.Mode()&os.ModeDevice == 0 {
		return nil, fmt.Errorf("host_path %q is not a device file: %w", params.HostPath, domain.ErrValidation)
	}

	d := &domain.Device{
		ID:            uuid.New().String(),
		HostPath:      params.HostPath,
		ContainerPath: params.ContainerPath,
		Permissions:   params.Permissions,
		GID:           params.GID,
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.deviceStore.CreateDevice(ctx, d); err != nil {
		return nil, fmt.Errorf("store create device: %w", err)
	}

	log.Info("device created", "id", d.ID, "host_path", d.HostPath)
	return d, nil
}

// GetDevice retrieves a device by ID.
func (s *VMService) GetDevice(ctx context.Context, id string) (*domain.Device, error) {
	if s.deviceStore == nil {
		return nil, fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	return s.deviceStore.GetDevice(ctx, id)
}

// ListDevices returns all devices.
func (s *VMService) ListDevices(ctx context.Context) ([]*domain.Device, error) {
	if s.deviceStore == nil {
		return nil, fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	return s.deviceStore.ListDevices(ctx)
}

// DeleteDevice removes a device. Fails if the device is attached to a VM.
func (s *VMService) DeleteDevice(ctx context.Context, id string) error {
	if s.deviceStore == nil {
		return fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	d, err := s.deviceStore.GetDevice(ctx, id)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("device %q attached to VM %s: %w", d.HostPath, d.VMID, domain.ErrDeviceAttached)
	}

	if err := s.deviceStore.DeleteDevice(ctx, id); err != nil {
		return fmt.Errorf("store delete device: %w", err)
	}

	log.Info("device deleted", "id", id, "host_path", d.HostPath)
	return nil
}

// AttachDevice attaches a device to a stopped VM, recreating the container
// with the new device mapping.
func (s *VMService) AttachDevice(ctx context.Context, deviceID, vmID string) error {
	if s.deviceStore == nil {
		return fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	vm, err := s.store.Get(ctx, vmID)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to attach devices: %w", domain.ErrInvalidState)
	}

	d, err := s.deviceStore.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("device already attached to VM %s: %w", d.VMID, domain.ErrDeviceAttached)
	}

	if err := s.deviceStore.AttachDevice(ctx, deviceID, vmID); err != nil {
		return fmt.Errorf("store attach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		s.deviceStore.DetachDevice(ctx, deviceID) //nolint:errcheck // best-effort rollback
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("device attached", "device", d.HostPath, "vm", vm.Name)
	return nil
}

// DetachDevice detaches a device from its VM, recreating the container
// without the device mapping.
func (s *VMService) DetachDevice(ctx context.Context, deviceID string) error {
	if s.deviceStore == nil {
		return fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	d, err := s.deviceStore.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if d.VMID == "" {
		return nil // already detached, idempotent
	}

	vm, err := s.store.Get(ctx, d.VMID)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to detach devices: %w", domain.ErrInvalidState)
	}

	if err := s.deviceStore.DetachDevice(ctx, deviceID); err != nil {
		return fmt.Errorf("store detach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("device detached", "device", d.HostPath, "vm", vm.Name)
	return nil
}

// recreateContainer deletes and recreates the containerd container for a VM,
// applying the current set of attached drives as mounts and devices.
func (s *VMService) recreateContainer(ctx context.Context, vm *domain.VM) error {
	var mounts []domain.Mount
	if s.driveStore != nil && s.storage != nil {
		drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			return fmt.Errorf("get drives: %w", err)
		}
		for _, d := range drives {
			mounts = append(mounts, domain.Mount{
				HostPath:      s.storage.VolumePath(d.Name),
				ContainerPath: d.MountPath,
			})
		}
	}

	var deviceInfos []domain.DeviceInfo
	if s.deviceStore != nil {
		devices, err := s.deviceStore.GetDevicesByVM(ctx, vm.ID)
		if err != nil {
			return fmt.Errorf("get devices: %w", err)
		}
		for _, dev := range devices {
			deviceInfos = append(deviceInfos, domain.DeviceInfo{
				HostPath:      dev.HostPath,
				ContainerPath: dev.ContainerPath,
				Permissions:   dev.Permissions,
				GID:           dev.GID,
			})
		}
	}

	if err := s.runtime.Delete(ctx, vm.ID); err != nil {
		log.Warn("runtime delete before recreate", "id", vm.ID, "err", err)
	}

	var createOpts []domain.CreateOpt
	if vm.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(vm.NetNSPath))
	}
	if len(mounts) > 0 {
		createOpts = append(createOpts, domain.WithMounts(mounts))
	}
	if len(deviceInfos) > 0 {
		createOpts = append(createOpts, domain.WithDevices(deviceInfos))
	}

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime, createOpts...); err != nil {
		return fmt.Errorf("runtime create: %w", err)
	}
	return nil
}
