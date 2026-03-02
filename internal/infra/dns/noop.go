// SPDX-License-Identifier: GPL-2.0-or-later
package dns

import (
	"context"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// NoopManager is a DNS manager that does nothing. Used when DNS is disabled.
type NoopManager struct{}

func (n *NoopManager) Start(context.Context) error                                  { return nil }
func (n *NoopManager) Stop() error                                                  { return nil }
func (n *NoopManager) AddRecord(context.Context, string, string) error              { return nil }
func (n *NoopManager) RemoveRecord(context.Context, string) error                   { return nil }
func (n *NoopManager) GenerateResolvConf(string, *domain.DNSConfig) (string, error) { return "", nil }
func (n *NoopManager) CleanupResolvConf(string) error                               { return nil }
