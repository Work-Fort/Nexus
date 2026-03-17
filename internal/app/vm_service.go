// SPDX-License-Identifier: GPL-3.0-or-later

// Package app contains application use-cases that orchestrate domain ports.
package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/bytesize"
	"github.com/Work-Fort/Nexus/pkg/nxid"
)

// VMServiceConfig holds configurable defaults for the VM service.
type VMServiceConfig struct {
	DefaultImage       string
	DefaultRuntime     string
	NetworkAutoMigrate bool
	Metrics            MetricsConfig
}

// MetricsConfig controls in-VM node_exporter provisioning.
type MetricsConfig struct {
	NodeExporterPath string   // host path to node_exporter binary, empty = disabled
	ListenPort       int      // port node_exporter listens on inside VMs
	Collectors       []string // enabled collector names
}

// VMService orchestrates VM lifecycle operations.
type VMService struct {
	store         domain.VMStore
	runtime       domain.Runtime
	network       domain.Network
	driveStore    domain.DriveStore
	storage       domain.Storage
	deviceStore   domain.DeviceStore
	dns           domain.DNSManager
	templateStore domain.TemplateStore
	snapshotStore domain.SnapshotStore
	config        VMServiceConfig
	health        *HealthService
}

// NewVMService creates a VMService with the given ports and config.
func NewVMService(store domain.VMStore, runtime domain.Runtime, network domain.Network, opts ...func(*VMService)) *VMService {
	svc := &VMService{
		store:   store,
		runtime: runtime,
		network: network,
		dns:     domain.NoopDNSManager{},
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

// WithTemplateStore enables provisioning templates.
func WithTemplateStore(ts domain.TemplateStore) func(*VMService) {
	return func(s *VMService) {
		s.templateStore = ts
	}
}

// WithDNS enables internal DNS management.
func WithDNS(dns domain.DNSManager) func(*VMService) {
	return func(s *VMService) {
		s.dns = dns
	}
}

// WithSnapshotStore enables snapshot management.
func WithSnapshotStore(ss domain.SnapshotStore) func(*VMService) {
	return func(s *VMService) {
		s.snapshotStore = ss
	}
}

// WithHealth enables runtime health gating for VM creation.
func WithHealth(h *HealthService) func(*VMService) {
	return func(s *VMService) {
		s.health = h
	}
}

// MetricsPort returns the configured node_exporter listen port.
func (s *VMService) MetricsPort() int {
	if s.config.Metrics.ListenPort == 0 {
		return 9100
	}
	return s.config.Metrics.ListenPort
}

const minRootSize = 64 * 1_000_000 // 64M

// CreateVM validates parameters, creates a container via the runtime, and
// persists the VM record.
func (s *VMService) CreateVM(ctx context.Context, params domain.CreateVMParams) (*domain.VM, error) {
	for _, tag := range params.Tags {
		if err := nxid.ValidateName(tag); err != nil {
			return nil, fmt.Errorf("invalid tag %q: %v: %w", tag, err, domain.ErrValidation)
		}
	}
	if len(params.Tags) > 20 {
		return nil, fmt.Errorf("too many tags (max 20): %w", domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(params.Name); err != nil {
		return nil, fmt.Errorf("invalid name: %v: %w", err, domain.ErrValidation)
	}
	if params.Image == "" {
		params.Image = s.config.DefaultImage
	}
	if params.Runtime == "" {
		params.Runtime = s.config.DefaultRuntime
	}
	if s.health != nil {
		if err := s.health.RuntimeHealthy(params.Runtime); err != nil {
			return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
		}
	}
	if params.RootSize < 0 {
		return nil, fmt.Errorf("root_size must be positive: %w", domain.ErrValidation)
	}
	if params.RootSize > 0 && params.RootSize < minRootSize {
		return nil, fmt.Errorf("root_size minimum is 64M: %w", domain.ErrValidation)
	}
	if params.RestartPolicy == "" {
		params.RestartPolicy = domain.RestartPolicyNone
	}
	if !domain.ValidRestartPolicy(params.RestartPolicy) {
		return nil, fmt.Errorf("invalid restart_policy %q: %w", params.RestartPolicy, domain.ErrValidation)
	}
	if params.RestartStrategy == "" {
		params.RestartStrategy = domain.RestartStrategyBackoff
	}
	if !domain.ValidRestartStrategy(params.RestartStrategy) {
		return nil, fmt.Errorf("invalid restart_strategy %q: %w", params.RestartStrategy, domain.ErrValidation)
	}

	vm := &domain.VM{
		ID:        nxid.New(),
		Name:      params.Name,
		Tags:      params.Tags,
		State:     domain.VMStateCreated,
		Image:     params.Image,
		Runtime:   params.Runtime,
		RootSize:        params.RootSize,
		Shell:           params.Shell,
		RestartPolicy:   params.RestartPolicy,
		RestartStrategy: params.RestartStrategy,
		CreatedAt:       time.Now().UTC(),
	}

	netInfo, err := s.network.Setup(ctx, vm.ID)
	if err != nil {
		return nil, fmt.Errorf("network setup: %w", err)
	}
	vm.IP = netInfo.IP
	vm.Gateway = netInfo.Gateway
	vm.NetNSPath = netInfo.NetNSPath

	vm.DNSConfig = params.DNSConfig

	if err := s.dns.AddRecord(ctx, vm.Name, vm.IP); err != nil {
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck
		return nil, fmt.Errorf("dns add record: %w", err)
	}
	resolvConfPath, err := s.dns.GenerateResolvConf(vm.ID, vm.DNSConfig)
	if err != nil {
		s.dns.RemoveRecord(ctx, vm.Name) //nolint:errcheck
		s.network.Teardown(ctx, vm.ID)   //nolint:errcheck
		return nil, fmt.Errorf("dns resolv.conf: %w", err)
	}

	var createOpts []domain.CreateOpt
	if netInfo.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(netInfo.NetNSPath))
	}
	if resolvConfPath != "" {
		createOpts = append(createOpts, domain.WithResolvConf(resolvConfPath))
	}
	if params.RootSize > 0 {
		createOpts = append(createOpts, domain.WithRootSize(params.RootSize))
	}

	// Bind-mount node_exporter when metrics are configured.
	if s.config.Metrics.NodeExporterPath != "" {
		createOpts = append(createOpts, domain.WithMounts([]domain.Mount{
			{
				HostPath:      s.config.Metrics.NodeExporterPath,
				ContainerPath: "/usr/local/bin/node_exporter",
			},
		}))
	}

	// Init injection: detect distro, resolve template, write init script.
	if params.Init {
		if s.templateStore == nil {
			return nil, fmt.Errorf("templates not enabled: %w", domain.ErrValidation)
		}
		initPath, templateID, stopSignal, err := s.resolveInitScript(ctx, vm.ID, params.Image, params.TemplateName)
		if err != nil {
			s.dns.RemoveRecord(ctx, vm.Name)  //nolint:errcheck
			s.dns.CleanupResolvConf(vm.ID)    //nolint:errcheck
			s.network.Teardown(ctx, vm.ID) //nolint:errcheck
			return nil, fmt.Errorf("init script: %w", err)
		}
		vm.Init = true
		vm.TemplateID = templateID
		createOpts = append(createOpts, domain.WithInitScript(initPath))
		if stopSignal != 0 {
			createOpts = append(createOpts, domain.WithStopSignal(stopSignal))
		}
	}

	if len(params.Env) > 0 {
		var envSlice []string
		for k, v := range params.Env {
			envSlice = append(envSlice, k+"="+v)
		}
		createOpts = append(createOpts, domain.WithEnv(envSlice))
	}
	vm.Env = params.Env

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime, createOpts...); err != nil {
		s.dns.RemoveRecord(ctx, vm.Name)  //nolint:errcheck
		s.dns.CleanupResolvConf(vm.ID)    //nolint:errcheck
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck // best-effort rollback
		return nil, fmt.Errorf("runtime create: %w", err)
	}

	if err := s.store.Create(ctx, vm); err != nil {
		s.runtime.Delete(ctx, vm.ID)    //nolint:errcheck // best-effort rollback
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck // best-effort rollback
		return nil, fmt.Errorf("store create: %w", err)
	}

	log.Info("vm created", "id", vm.ID, "name", vm.Name, "tags", vm.Tags, "ip", vm.IP)
	return vm, nil
}

// GetVM retrieves a VM by ID or name.
func (s *VMService) GetVM(ctx context.Context, ref string) (*domain.VM, error) {
	return s.store.Resolve(ctx, ref)
}

// ListVMs returns VMs matching the filter.
func (s *VMService) ListVMs(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	return s.store.List(ctx, filter)
}

// StartVM starts a created or stopped VM.
func (s *VMService) StartVM(ctx context.Context, ref string) error {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return domain.ErrInvalidState
	}

	var startOpts []domain.CreateOpt
	if len(vm.Env) > 0 {
		var envSlice []string
		for k, v := range vm.Env {
			envSlice = append(envSlice, k+"="+v)
		}
		startOpts = append(startOpts, domain.WithEnv(envSlice))
	}
	if err := s.runtime.Start(ctx, vm.ID, startOpts...); err != nil {
		return fmt.Errorf("runtime start: %w", err)
	}

	if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateRunning, time.Now().UTC()); err != nil {
		return fmt.Errorf("store update: %w", err)
	}

	log.Info("vm started", "id", vm.ID)

	// Start node_exporter for VMs without init (init VMs use supervised service).
	if !vm.Init {
		s.execStartMetrics(vm.ID)
	}

	if vm.Shell == "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := s.SyncShell(ctx, vm.ID); err != nil {
				log.Warn("auto shell sync failed", "vm", vm.ID, "err", err)
			}
		}()
	}

	return nil
}

// StopVM stops a running VM. It is idempotent: stopping an already-stopped
// VM returns nil.
func (s *VMService) StopVM(ctx context.Context, ref string) error {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateStopped {
		return nil // already stopped, idempotent
	}
	if vm.State != domain.VMStateRunning {
		return domain.ErrInvalidState
	}

	if err := s.runtime.Stop(ctx, vm.ID); err != nil {
		return fmt.Errorf("runtime stop: %w", err)
	}

	if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateStopped, time.Now().UTC()); err != nil {
		return fmt.Errorf("store update: %w", err)
	}

	log.Info("vm stopped", "id", vm.ID)
	return nil
}

// DeleteVM stops the container if running, then removes it and its store record.
func (s *VMService) DeleteVM(ctx context.Context, ref string) error {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		if err := s.runtime.Stop(ctx, vm.ID); err != nil {
			log.Warn("runtime stop before delete failed", "id", vm.ID, "err", err)
		}
	}
	if err := s.runtime.Delete(ctx, vm.ID); err != nil {
		log.Warn("runtime delete failed", "id", vm.ID, "err", err)
	}

	if err := s.network.Teardown(ctx, vm.ID); err != nil {
		log.Warn("network teardown failed", "id", vm.ID, "err", err)
	}

	s.dns.RemoveRecord(ctx, vm.Name)  //nolint:errcheck
	s.dns.CleanupResolvConf(vm.ID)    //nolint:errcheck

	if s.driveStore != nil {
		if err := s.driveStore.DetachAllDrives(ctx, vm.ID); err != nil {
			log.Warn("detach drives failed", "id", vm.ID, "err", err)
		}
	}

	if s.deviceStore != nil {
		if err := s.deviceStore.DetachAllDevices(ctx, vm.ID); err != nil {
			log.Warn("detach devices failed", "id", vm.ID, "err", err)
		}
	}

	// Clean up all snapshots (on-disk data; DB records cascade via ON DELETE CASCADE).
	if s.snapshotStore != nil {
		snaps, err := s.snapshotStore.ListSnapshots(ctx, vm.ID)
		if err == nil {
			for _, snap := range snaps {
				rootfsSnapName := vm.ID + "@" + snap.Name
				s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
				s.cleanupAllSnapshots(ctx, vm.ID, snap.Name)
			}
		}
	}

	if err := s.store.Delete(ctx, vm.ID); err != nil {
		return fmt.Errorf("store delete: %w", err)
	}

	log.Info("vm deleted", "id", vm.ID)
	return nil
}

// ExecVM runs a command in a running VM.
func (s *VMService) ExecVM(ctx context.Context, ref string, cmd []string) (*domain.ExecResult, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("cmd is required: %w", domain.ErrValidation)
	}

	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	return s.runtime.Exec(ctx, vm.ID, cmd)
}

// ExecStreamVM runs a command in the VM and streams output to the provided writers.
// Returns the exit code when the process exits.
func (s *VMService) ExecStreamVM(ctx context.Context, ref string, cmd []string, stdout, stderr io.Writer) (int, error) {
	if len(cmd) == 0 {
		return -1, fmt.Errorf("cmd is required: %w", domain.ErrValidation)
	}

	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return -1, err
	}
	if vm.State != domain.VMStateRunning {
		return -1, domain.ErrInvalidState
	}

	return s.runtime.ExecStream(ctx, vm.ID, cmd, stdout, stderr)
}

// ExecConsoleVM opens an interactive TTY console in the VM.
func (s *VMService) ExecConsoleVM(ctx context.Context, ref string, cmd []string, cols, rows uint16) (*domain.ConsoleSession, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	// Shell resolution: explicit cmd > VM shell field > /bin/sh
	if len(cmd) == 0 {
		shell := vm.Shell
		if shell == "" {
			shell = "/bin/sh"
		}
		cmd = []string{shell}
	}

	return s.runtime.ExecConsole(ctx, vm.ID, cmd, cols, rows)
}

// ExpandRootSize increases the root size quota for a VM.
func (s *VMService) ExpandRootSize(ctx context.Context, ref string, newSize int64) error {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	if vm.RootSize == 0 {
		return fmt.Errorf("VM has no root size limit set: %w", domain.ErrValidation)
	}
	if newSize <= vm.RootSize {
		return fmt.Errorf("new size must be larger than current (%d): %w", vm.RootSize, domain.ErrValidation)
	}

	if err := s.runtime.SetSnapshotQuota(ctx, vm.ID+"-snap", newSize); err != nil {
		return fmt.Errorf("set quota: %w", err)
	}

	if err := s.store.UpdateRootSize(ctx, vm.ID, newSize); err != nil {
		return fmt.Errorf("store update root_size: %w", err)
	}

	log.Info("root size expanded", "id", vm.ID, "old", vm.RootSize, "new", newSize)
	return nil
}

// UpdateShell sets the default shell for console sessions.
func (s *VMService) UpdateShell(ctx context.Context, ref, shell string) (*domain.VM, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateShell(ctx, vm.ID, shell); err != nil {
		return nil, fmt.Errorf("update shell: %w", err)
	}
	return s.store.Get(ctx, vm.ID)
}

// UpdateRestartPolicy changes the restart policy and strategy for a VM.
func (s *VMService) UpdateRestartPolicy(ctx context.Context, ref string, policy domain.RestartPolicy, strategy domain.RestartStrategy) (*domain.VM, error) {
	if !domain.ValidRestartPolicy(policy) {
		return nil, fmt.Errorf("invalid restart_policy %q: %w", policy, domain.ErrValidation)
	}
	if !domain.ValidRestartStrategy(strategy) {
		return nil, fmt.Errorf("invalid restart_strategy %q: %w", strategy, domain.ErrValidation)
	}

	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	if err := s.store.UpdateRestartPolicy(ctx, vm.ID, policy, strategy); err != nil {
		return nil, fmt.Errorf("store update restart policy: %w", err)
	}

	vm.RestartPolicy = policy
	vm.RestartStrategy = strategy
	log.Info("restart policy updated", "id", vm.ID, "policy", policy, "strategy", strategy)
	return vm, nil
}

// UpdateEnv replaces the environment variables for a VM. The new env takes
// effect on the next Start (container recreation applies the updated spec).
func (s *VMService) UpdateEnv(ctx context.Context, ref string, env map[string]string) (*domain.VM, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateEnv(ctx, vm.ID, env); err != nil {
		return nil, fmt.Errorf("store update env: %w", err)
	}
	vm.Env = env
	log.Info("env updated", "id", vm.ID, "count", len(env))
	return vm, nil
}

// SetTags replaces all tags on a VM.
func (s *VMService) SetTags(ctx context.Context, ref string, tags []string) (*domain.VM, error) {
	for _, tag := range tags {
		if err := nxid.ValidateName(tag); err != nil {
			return nil, fmt.Errorf("invalid tag %q: %v: %w", tag, err, domain.ErrValidation)
		}
	}
	if len(tags) > 20 {
		return nil, fmt.Errorf("too many tags (max 20): %w", domain.ErrValidation)
	}

	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	if err := s.store.SetTags(ctx, vm.ID, tags); err != nil {
		return nil, fmt.Errorf("set tags: %w", err)
	}

	vm.Tags = tags
	log.Info("tags updated", "id", vm.ID, "tags", tags)
	return vm, nil
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

// --- Drive operations ---

// CreateDrive creates a new persistent data volume.
func (s *VMService) CreateDrive(ctx context.Context, params domain.CreateDriveParams) (*domain.Drive, error) {
	if s.storage == nil {
		return nil, fmt.Errorf("drives not enabled: %w", domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(params.Name); err != nil {
		return nil, fmt.Errorf("invalid name: %v: %w", err, domain.ErrValidation)
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
		ID:        nxid.New(),
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

// GetDrive retrieves a drive by ID or name.
func (s *VMService) GetDrive(ctx context.Context, ref string) (*domain.Drive, error) {
	return s.driveStore.ResolveDrive(ctx, ref)
}

// ListDrives returns all drives.
func (s *VMService) ListDrives(ctx context.Context) ([]*domain.Drive, error) {
	return s.driveStore.ListDrives(ctx)
}

// DeleteDrive removes a drive. Fails if the drive is attached to a VM.
func (s *VMService) DeleteDrive(ctx context.Context, ref string) error {
	d, err := s.driveStore.ResolveDrive(ctx, ref)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("drive %q attached to VM %s: %w", d.Name, d.VMID, domain.ErrDriveAttached)
	}

	if err := s.storage.DeleteVolume(ctx, d.Name); err != nil {
		return fmt.Errorf("delete volume: %w", err)
	}
	if err := s.driveStore.DeleteDrive(ctx, d.ID); err != nil {
		return fmt.Errorf("store delete drive: %w", err)
	}

	log.Info("drive deleted", "id", d.ID, "name", d.Name)
	return nil
}

// AttachDrive attaches a drive to a stopped VM, recreating the container
// with the new mount.
func (s *VMService) AttachDrive(ctx context.Context, driveRef, vmRef string) error {
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to attach drives: %w", domain.ErrInvalidState)
	}

	d, err := s.driveStore.ResolveDrive(ctx, driveRef)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("drive already attached to VM %s: %w", d.VMID, domain.ErrDriveAttached)
	}

	if err := s.driveStore.AttachDrive(ctx, d.ID, vm.ID); err != nil {
		return fmt.Errorf("store attach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		s.driveStore.DetachDrive(ctx, d.ID) //nolint:errcheck // best-effort rollback
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("drive attached", "drive", d.Name, "vm", vm.Name)
	return nil
}

// DetachDrive detaches a drive from its VM, recreating the container
// without the mount.
func (s *VMService) DetachDrive(ctx context.Context, driveRef string) error {
	d, err := s.driveStore.ResolveDrive(ctx, driveRef)
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

	if err := s.driveStore.DetachDrive(ctx, d.ID); err != nil {
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
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(params.Name); err != nil {
		return nil, fmt.Errorf("invalid name: %v: %w", err, domain.ErrValidation)
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
		ID:            nxid.New(),
		Name:          params.Name,
		HostPath:      params.HostPath,
		ContainerPath: params.ContainerPath,
		Permissions:   params.Permissions,
		GID:           params.GID,
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.deviceStore.CreateDevice(ctx, d); err != nil {
		return nil, fmt.Errorf("store create device: %w", err)
	}

	log.Info("device created", "id", d.ID, "name", d.Name, "host_path", d.HostPath)
	return d, nil
}

// GetDevice retrieves a device by ID or name.
func (s *VMService) GetDevice(ctx context.Context, ref string) (*domain.Device, error) {
	if s.deviceStore == nil {
		return nil, fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	return s.deviceStore.ResolveDevice(ctx, ref)
}

// ListDevices returns all devices.
func (s *VMService) ListDevices(ctx context.Context) ([]*domain.Device, error) {
	if s.deviceStore == nil {
		return nil, fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	return s.deviceStore.ListDevices(ctx)
}

// DeleteDevice removes a device. Fails if the device is attached to a VM.
func (s *VMService) DeleteDevice(ctx context.Context, ref string) error {
	if s.deviceStore == nil {
		return fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	d, err := s.deviceStore.ResolveDevice(ctx, ref)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("device %q attached to VM %s: %w", d.HostPath, d.VMID, domain.ErrDeviceAttached)
	}

	if err := s.deviceStore.DeleteDevice(ctx, d.ID); err != nil {
		return fmt.Errorf("store delete device: %w", err)
	}

	log.Info("device deleted", "id", d.ID, "host_path", d.HostPath)
	return nil
}

// AttachDevice attaches a device to a stopped VM, recreating the container
// with the new device mapping.
func (s *VMService) AttachDevice(ctx context.Context, deviceRef, vmRef string) error {
	if s.deviceStore == nil {
		return fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM must be stopped to attach devices: %w", domain.ErrInvalidState)
	}

	d, err := s.deviceStore.ResolveDevice(ctx, deviceRef)
	if err != nil {
		return err
	}
	if d.VMID != "" {
		return fmt.Errorf("device already attached to VM %s: %w", d.VMID, domain.ErrDeviceAttached)
	}

	if err := s.deviceStore.AttachDevice(ctx, d.ID, vm.ID); err != nil {
		return fmt.Errorf("store attach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		s.deviceStore.DetachDevice(ctx, d.ID) //nolint:errcheck // best-effort rollback
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("device attached", "device", d.HostPath, "vm", vm.Name)
	return nil
}

// DetachDevice detaches a device from its VM, recreating the container
// without the device mapping.
func (s *VMService) DetachDevice(ctx context.Context, deviceRef string) error {
	if s.deviceStore == nil {
		return fmt.Errorf("devices not enabled: %w", domain.ErrValidation)
	}
	d, err := s.deviceStore.ResolveDevice(ctx, deviceRef)
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

	if err := s.deviceStore.DetachDevice(ctx, d.ID); err != nil {
		return fmt.Errorf("store detach: %w", err)
	}

	if err := s.recreateContainer(ctx, vm); err != nil {
		return fmt.Errorf("recreate container: %w", err)
	}

	log.Info("device detached", "device", d.HostPath, "vm", vm.Name)
	return nil
}

// SyncDNS loads all existing VM records into the DNS manager.
// Called once at startup to populate the hosts file.
func (s *VMService) SyncDNS(ctx context.Context) error {
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		return fmt.Errorf("list vms for dns sync: %w", err)
	}
	var count int
	for _, vm := range vms {
		if vm.IP != "" {
			if err := s.dns.AddRecord(ctx, vm.Name, vm.IP); err != nil {
				return fmt.Errorf("dns sync %s: %w", vm.Name, err)
			}
			count++
		}
	}
	log.Info("dns synced", "records", count)
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

	if s.config.Metrics.NodeExporterPath != "" {
		mounts = append(mounts, domain.Mount{
			HostPath:      s.config.Metrics.NodeExporterPath,
			ContainerPath: "/usr/local/bin/node_exporter",
		})
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

	resolvConfPath, err := s.dns.GenerateResolvConf(vm.ID, vm.DNSConfig)
	if err != nil {
		return fmt.Errorf("dns resolv.conf: %w", err)
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
	if resolvConfPath != "" {
		createOpts = append(createOpts, domain.WithResolvConf(resolvConfPath))
	}
	if vm.RootSize > 0 {
		createOpts = append(createOpts, domain.WithRootSize(vm.RootSize))
	}
	if vm.Init {
		script := vm.ScriptOverride
		distro := ""
		if script == "" && s.templateStore != nil && vm.TemplateID != "" {
			tmpl, err := s.templateStore.GetTemplate(ctx, vm.TemplateID)
			if err != nil {
				return fmt.Errorf("get template for init: %w", err)
			}
			script = tmpl.Script
			distro = tmpl.Distro
		}
		if script != "" {
			if distro != "" && s.config.Metrics.NodeExporterPath != "" {
				script = injectMetricsService(script, distro, s.config.Metrics)
			}
			path, err := s.writeInitScript(vm.ID, script)
			if err != nil {
				return fmt.Errorf("write init script: %w", err)
			}
			createOpts = append(createOpts, domain.WithInitScript(path))
			if sig := initStopSignal(script); sig != 0 {
				createOpts = append(createOpts, domain.WithStopSignal(sig))
			}
		}
	}

	if len(vm.Env) > 0 {
		var envSlice []string
		for k, v := range vm.Env {
			envSlice = append(envSlice, k+"="+v)
		}
		createOpts = append(createOpts, domain.WithEnv(envSlice))
	}

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime, createOpts...); err != nil {
		return fmt.Errorf("runtime create: %w", err)
	}
	return nil
}

// SyncShell detects the root user's default shell from inside a running VM
// and persists it to the shell field. Returns the updated VM.
func (s *VMService) SyncShell(ctx context.Context, ref string) (*domain.VM, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	result, err := s.runtime.Exec(ctx, vm.ID, []string{"getent", "passwd", "root"})
	if err != nil {
		return nil, fmt.Errorf("exec getent: %w", err)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("getent exited %d: %s", result.ExitCode, result.Stderr)
	}

	shell, err := parseShellFromPasswd(result.Stdout)
	if err != nil {
		return nil, err
	}

	if shell != vm.Shell {
		if err := s.store.UpdateShell(ctx, vm.ID, shell); err != nil {
			return nil, fmt.Errorf("update shell: %w", err)
		}
	}

	return s.store.Get(ctx, vm.ID)
}

// parseShellFromPasswd extracts the shell (field 7) from a passwd-format line.
func parseShellFromPasswd(output string) (string, error) {
	line := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	if line == "" {
		return "", fmt.Errorf("empty passwd output: %w", domain.ErrValidation)
	}
	fields := strings.Split(line, ":")
	if len(fields) < 7 {
		return "", fmt.Errorf("malformed passwd line (%d fields): %w", len(fields), domain.ErrValidation)
	}
	shell := fields[6]
	if shell == "" {
		return "", fmt.Errorf("empty shell in passwd: %w", domain.ErrValidation)
	}
	if !strings.HasPrefix(shell, "/") {
		return "", fmt.Errorf("shell %q is not an absolute path: %w", shell, domain.ErrValidation)
	}
	return shell, nil
}

// --- Template operations ---

// CreateTemplate creates a new provisioning template.
func (s *VMService) CreateTemplate(ctx context.Context, params domain.CreateTemplateParams) (*domain.Template, error) {
	if s.templateStore == nil {
		return nil, fmt.Errorf("templates not enabled: %w", domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if params.Distro == "" {
		return nil, fmt.Errorf("distro is required: %w", domain.ErrValidation)
	}
	if params.Script == "" {
		return nil, fmt.Errorf("script is required: %w", domain.ErrValidation)
	}

	now := time.Now().UTC()
	t := &domain.Template{
		ID:        nxid.New(),
		Name:      params.Name,
		Distro:    params.Distro,
		Script:    params.Script,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.templateStore.CreateTemplate(ctx, t); err != nil {
		return nil, fmt.Errorf("store create template: %w", err)
	}
	log.Info("template created", "id", t.ID, "name", t.Name, "distro", t.Distro)
	return t, nil
}

// GetTemplate retrieves a template by ID or name.
func (s *VMService) GetTemplate(ctx context.Context, ref string) (*domain.Template, error) {
	if s.templateStore == nil {
		return nil, fmt.Errorf("templates not enabled: %w", domain.ErrValidation)
	}
	return s.templateStore.ResolveTemplate(ctx, ref)
}

// ListTemplates returns all templates.
func (s *VMService) ListTemplates(ctx context.Context) ([]*domain.Template, error) {
	if s.templateStore == nil {
		return nil, fmt.Errorf("templates not enabled: %w", domain.ErrValidation)
	}
	return s.templateStore.ListTemplates(ctx)
}

// UpdateTemplate updates a template's name, distro, and script.
func (s *VMService) UpdateTemplate(ctx context.Context, ref string, params domain.CreateTemplateParams) (*domain.Template, error) {
	if s.templateStore == nil {
		return nil, fmt.Errorf("templates not enabled: %w", domain.ErrValidation)
	}
	t, err := s.templateStore.ResolveTemplate(ctx, ref)
	if err != nil {
		return nil, err
	}
	name := params.Name
	if name == "" {
		name = t.Name
	}
	distro := params.Distro
	if distro == "" {
		distro = t.Distro
	}
	script := params.Script
	if script == "" {
		script = t.Script
	}
	if err := s.templateStore.UpdateTemplate(ctx, t.ID, name, distro, script); err != nil {
		return nil, fmt.Errorf("update template: %w", err)
	}
	log.Info("template updated", "id", t.ID, "name", name)
	return s.templateStore.GetTemplate(ctx, t.ID)
}

// DeleteTemplate deletes a template if no VMs reference it.
func (s *VMService) DeleteTemplate(ctx context.Context, ref string) error {
	if s.templateStore == nil {
		return fmt.Errorf("templates not enabled: %w", domain.ErrValidation)
	}
	t, err := s.templateStore.ResolveTemplate(ctx, ref)
	if err != nil {
		return err
	}
	n, err := s.templateStore.CountTemplateRefs(ctx, t.ID)
	if err != nil {
		return fmt.Errorf("count template refs: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("template %q referenced by %d VM(s): %w", t.Name, n, domain.ErrTemplateInUse)
	}
	if err := s.templateStore.DeleteTemplate(ctx, t.ID); err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	log.Info("template deleted", "id", t.ID, "name", t.Name)
	return nil
}

// UpdateScriptOverride sets or clears a per-VM init script override.
func (s *VMService) UpdateScriptOverride(ctx context.Context, ref, script string) (*domain.VM, error) {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if !vm.Init {
		return nil, fmt.Errorf("VM does not have init enabled: %w", domain.ErrValidation)
	}
	vm.ScriptOverride = script
	// Persist via the init update query (keeps init=true, template_id unchanged).
	// We reuse the store's UpdateInit if available, or just update fields directly.
	// For now, we re-create the init script.
	return vm, nil
}

// resolveInitScript determines the effective init script for a VM, writes it
// to a temp file, and returns the file path and template ID.
func (s *VMService) resolveInitScript(ctx context.Context, vmID, image, templateName string) (path, templateID string, stopSignal int, err error) {
	var tmpl *domain.Template

	if templateName != "" {
		tmpl, err = s.templateStore.ResolveTemplate(ctx, templateName)
		if err != nil {
			return "", "", 0, fmt.Errorf("resolve template %q: %w", templateName, err)
		}
	} else {
		distro, err := s.runtime.DetectDistro(ctx, image)
		if err != nil {
			return "", "", 0, fmt.Errorf("detect distro: %w", err)
		}
		tmpl, err = s.templateStore.GetTemplateByDistro(ctx, distro)
		if err != nil {
			return "", "", 0, fmt.Errorf("no template for distro %q: %w", distro, err)
		}
	}

	script := tmpl.Script
	if s.config.Metrics.NodeExporterPath != "" {
		script = injectMetricsService(script, tmpl.Distro, s.config.Metrics)
	}

	scriptPath, err := s.writeInitScript(vmID, script)
	if err != nil {
		return "", "", 0, err
	}
	return scriptPath, tmpl.ID, initStopSignal(script), nil
}

// writeInitScript writes a shell script to a temp file for bind-mounting.
func (s *VMService) writeInitScript(vmID, script string) (string, error) {
	dir := os.TempDir()
	initDir := dir + "/nexus-init"
	if err := os.MkdirAll(initDir, 0755); err != nil {
		return "", fmt.Errorf("create init dir: %w", err)
	}
	path := initDir + "/" + vmID + ".sh"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		return "", fmt.Errorf("write init script: %w", err)
	}
	return path, nil
}

// initStopSignal returns the signal number to send when stopping a container
// running the given init script. systemd requires SIGRTMIN+3 (37); busybox
// init (Alpine/OpenRC) accepts SIGUSR2 (12) for poweroff. Returns 0 if the
// init system is unknown (falls back to SIGTERM).
func initStopSignal(script string) int {
	if strings.Contains(script, "systemd") {
		return 37 // SIGRTMIN+3
	}
	if strings.Contains(script, "/sbin/init") {
		return 12 // SIGUSR2 — busybox init poweroff
	}
	return 0
}

// injectMetricsService inserts a node_exporter service definition into an
// init script, before the final `exec /sbin/init` line. The service is
// managed by the VM's init system (OpenRC or systemd) so it gets supervised.
func injectMetricsService(script, distro string, mc MetricsConfig) string {
	snippet := metricsServiceSnippet(distro, mc)
	if snippet == "" {
		return script
	}

	// Insert before the last `exec` line (typically `exec /sbin/init`).
	lines := strings.Split(script, "\n")
	var result []string
	inserted := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inserted && strings.HasPrefix(trimmed, "exec ") {
			result = append(result, "", snippet, "")
			inserted = true
		}
		result = append(result, line)
	}
	if !inserted {
		// No exec line found — append at end.
		result = append(result, "", snippet)
	}
	return strings.Join(result, "\n")
}

// metricsServiceSnippet returns distro-specific shell commands to install a
// node_exporter service that the init system will start and supervise.
func metricsServiceSnippet(distro string, mc MetricsConfig) string {
	args := fmt.Sprintf("--web.listen-address=:%d --collector.disable-defaults", mc.ListenPort)
	for _, c := range mc.Collectors {
		args += " --collector." + c
	}

	switch distro {
	case "alpine":
		return fmt.Sprintf(`# node_exporter service (injected by nexus)
cat > /etc/init.d/node_exporter << 'NEXUS_NE_EOF'
#!/sbin/openrc-run
command="/usr/local/bin/node_exporter"
command_args="%s"
command_background=true
pidfile="/run/node_exporter.pid"
NEXUS_NE_EOF
chmod +x /etc/init.d/node_exporter
rc-update add node_exporter default`, args)

	case "ubuntu", "debian", "arch":
		return fmt.Sprintf(`# node_exporter service (injected by nexus)
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/node_exporter.service << 'NEXUS_NE_EOF'
[Unit]
Description=Node Exporter
[Service]
ExecStart=/usr/local/bin/node_exporter %s
[Install]
WantedBy=multi-user.target
NEXUS_NE_EOF
systemctl enable node_exporter`, args)

	default:
		return ""
	}
}

// execStartMetrics fires node_exporter via exec inside a running VM.
// Used as a fallback for VMs that don't have init enabled.
func (s *VMService) execStartMetrics(vmID string) {
	if s.config.Metrics.NodeExporterPath == "" {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := []string{
			"/usr/local/bin/node_exporter",
			fmt.Sprintf("--web.listen-address=:%d", s.config.Metrics.ListenPort),
			"--collector.disable-defaults",
		}
		for _, c := range s.config.Metrics.Collectors {
			cmd = append(cmd, "--collector."+c)
		}

		if _, err := s.runtime.Exec(ctx, vmID, cmd); err != nil {
			log.Warn("metrics exec failed", "vm", vmID, "err", err)
		}
	}()
}
