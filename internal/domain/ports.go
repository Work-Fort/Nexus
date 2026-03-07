// SPDX-License-Identifier: Apache-2.0
package domain

import (
	"context"
	"errors"
	"io"
	"time"
)

// VMStore persists VM metadata. Implementations live in internal/infra/.
type VMStore interface {
	Create(ctx context.Context, vm *VM) error
	Get(ctx context.Context, id string) (*VM, error)
	List(ctx context.Context, filter VMFilter) ([]*VM, error)
	GetByName(ctx context.Context, name string) (*VM, error)
	Resolve(ctx context.Context, ref string) (*VM, error)
	UpdateState(ctx context.Context, id string, state VMState, now time.Time) error
	UpdateRootSize(ctx context.Context, id string, rootSize int64) error
	UpdateRestartPolicy(ctx context.Context, id string, policy RestartPolicy, strategy RestartStrategy) error
	UpdateShell(ctx context.Context, id, shell string) error
	SetTags(ctx context.Context, vmID string, tags []string) error
	Delete(ctx context.Context, id string) error
}

// Runtime manages the container/VM lifecycle. Implementations live in
// internal/infra/.
type Runtime interface {
	Create(ctx context.Context, id, image, runtimeHandler string, opts ...CreateOpt) error
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	Exec(ctx context.Context, id string, cmd []string) (*ExecResult, error)
	ExecStream(ctx context.Context, id string, cmd []string, stdout, stderr io.Writer) (int, error)
	ExecConsole(ctx context.Context, id string, cmd []string, cols, rows uint16) (*ConsoleSession, error)
	SetSnapshotQuota(ctx context.Context, snapName string, sizeBytes int64) error
	ExportImage(ctx context.Context, imageRef string, w io.Writer) error
	ImportImage(ctx context.Context, reader io.Reader) (string, error)
	WatchExits(ctx context.Context, onExit func(containerID string, exitCode uint32)) error
}

// CreateConfig holds optional configuration for Runtime.Create.
type CreateConfig struct {
	NetNSPath      string
	Mounts         []Mount
	Devices        []DeviceInfo
	ResolvConfPath string
	RootSize       int64 // bytes, 0 = no quota
}

// CreateOpt is a functional option for Runtime.Create.
type CreateOpt func(*CreateConfig)

// WithNetNS sets the network namespace path for the container.
func WithNetNS(path string) CreateOpt {
	return func(c *CreateConfig) {
		c.NetNSPath = path
	}
}

// NetworkInfo holds the network configuration assigned to a VM.
type NetworkInfo struct {
	IP        string
	Gateway   string
	NetNSPath string
}

// Network manages network namespaces and CNI for VMs.
type Network interface {
	Setup(ctx context.Context, id string) (*NetworkInfo, error)
	Teardown(ctx context.Context, id string) error
	ResetNetwork(ctx context.Context) error
}

// ErrNetworkInUse is returned when a network reset is attempted while VMs exist.
var ErrNetworkInUse = errors.New("network in use")

// ErrDriveAttached is returned when deleting a drive that is attached to a VM.
var ErrDriveAttached = errors.New("drive is attached to a VM")

// ErrDeviceAttached is returned when deleting a device that is attached to a VM.
var ErrDeviceAttached = errors.New("device is attached to a VM")

// Mount describes a bind mount from host into the container.
type Mount struct {
	HostPath      string
	ContainerPath string
}

// WithMounts adds bind mounts to the container spec.
func WithMounts(mounts []Mount) CreateOpt {
	return func(c *CreateConfig) {
		c.Mounts = mounts
	}
}

// DeviceInfo describes a device to include in the OCI spec.
type DeviceInfo struct {
	HostPath      string
	ContainerPath string
	Permissions   string // "rwm", "rw", "r"
	GID           uint32
}

// WithDevices adds device mappings to the container spec.
func WithDevices(devices []DeviceInfo) CreateOpt {
	return func(c *CreateConfig) {
		c.Devices = devices
	}
}

// WithResolvConf bind-mounts a resolv.conf into the container.
func WithResolvConf(path string) CreateOpt {
	return func(c *CreateConfig) {
		c.ResolvConfPath = path
	}
}

// WithRootSize sets a btrfs quota limit on the container snapshot.
func WithRootSize(size int64) CreateOpt {
	return func(c *CreateConfig) {
		c.RootSize = size
	}
}

// DriveStore persists drive metadata.
type DriveStore interface {
	CreateDrive(ctx context.Context, d *Drive) error
	GetDrive(ctx context.Context, id string) (*Drive, error)
	GetDriveByName(ctx context.Context, name string) (*Drive, error)
	ResolveDrive(ctx context.Context, ref string) (*Drive, error)
	ListDrives(ctx context.Context) ([]*Drive, error)
	AttachDrive(ctx context.Context, driveID, vmID string) error
	DetachDrive(ctx context.Context, driveID string) error
	DetachAllDrives(ctx context.Context, vmID string) error
	GetDrivesByVM(ctx context.Context, vmID string) ([]*Drive, error)
	DeleteDrive(ctx context.Context, id string) error
}

// DeviceStore persists device metadata.
type DeviceStore interface {
	CreateDevice(ctx context.Context, d *Device) error
	GetDevice(ctx context.Context, id string) (*Device, error)
	GetDeviceByName(ctx context.Context, name string) (*Device, error)
	ResolveDevice(ctx context.Context, ref string) (*Device, error)
	ListDevices(ctx context.Context) ([]*Device, error)
	AttachDevice(ctx context.Context, deviceID, vmID string) error
	DetachDevice(ctx context.Context, deviceID string) error
	DetachAllDevices(ctx context.Context, vmID string) error
	GetDevicesByVM(ctx context.Context, vmID string) ([]*Device, error)
	DeleteDevice(ctx context.Context, id string) error
}

// Storage manages the underlying volume backend (e.g. btrfs subvolumes).
type Storage interface {
	CreateVolume(ctx context.Context, name string, sizeBytes uint64) (path string, err error)
	DeleteVolume(ctx context.Context, name string) error
	VolumePath(name string) string
	SendVolume(ctx context.Context, name string, w io.Writer) error
	ReceiveVolume(ctx context.Context, name string, r io.Reader) error
}

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
