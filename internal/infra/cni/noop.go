// SPDX-License-Identifier: GPL-3.0-or-later

// Package cni implements domain.Network using CNI plugins.
package cni

import (
	"context"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// NoopNetwork implements domain.Network as a no-op. Used when networking
// is disabled or during testing.
type NoopNetwork struct{}

func (n *NoopNetwork) Setup(_ context.Context, _ string, _ ...domain.SetupOpt) (*domain.NetworkInfo, error) {
	return &domain.NetworkInfo{}, nil
}

func (n *NoopNetwork) Teardown(_ context.Context, _ string) error {
	return nil
}

func (n *NoopNetwork) ResetNetwork(_ context.Context) error {
	return nil
}

func (n *NoopNetwork) ConfigChanged() bool {
	return false
}

func (n *NoopNetwork) SaveConfigHash() error {
	return nil
}
