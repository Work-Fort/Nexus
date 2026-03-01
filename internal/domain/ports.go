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
	Create(ctx context.Context, id, image, runtimeHandler string) error
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
	Exec(ctx context.Context, id string, cmd []string) (*ExecResult, error)
}
