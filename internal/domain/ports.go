// SPDX-License-Identifier: Apache-2.0
package domain

import (
	"context"
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
}
