// SPDX-License-Identifier: Apache-2.0
package domain

import (
	"context"
	"errors"
	"time"
)

// VMStore persists VM metadata. Implementations live in internal/infra/.
type VMStore interface {
	Create(ctx context.Context, vm *VM) error
	Get(ctx context.Context, id string) (*VM, error)
	List(ctx context.Context, filter VMFilter) ([]*VM, error)
	GetByName(ctx context.Context, name string) (*VM, error)
	UpdateState(ctx context.Context, id string, state VMState, now time.Time) error
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
}

// CreateConfig holds optional configuration for Runtime.Create.
type CreateConfig struct {
	NetNSPath string
	Mounts    []Mount
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

// DriveStore persists drive metadata.
type DriveStore interface {
	CreateDrive(ctx context.Context, d *Drive) error
	GetDrive(ctx context.Context, id string) (*Drive, error)
	GetDriveByName(ctx context.Context, name string) (*Drive, error)
	ListDrives(ctx context.Context) ([]*Drive, error)
	AttachDrive(ctx context.Context, driveID, vmID string) error
	DetachDrive(ctx context.Context, driveID string) error
	DetachAllDrives(ctx context.Context, vmID string) error
	GetDrivesByVM(ctx context.Context, vmID string) ([]*Drive, error)
	DeleteDrive(ctx context.Context, id string) error
}

// Storage manages the underlying volume backend (e.g. btrfs subvolumes).
type Storage interface {
	CreateVolume(ctx context.Context, name string, sizeBytes uint64) (path string, err error)
	DeleteVolume(ctx context.Context, name string) error
	VolumePath(name string) string
}
