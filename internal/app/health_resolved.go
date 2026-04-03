// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"time"
)

// ResolvedOps abstracts the check and re-register operations for
// systemd-resolved DNS routing. This allows the health check to
// be tested without D-Bus.
type ResolvedOps interface {
	IsRegistered() (bool, error)
	Register() error
}

// ResolvedDNSCheck monitors whether split DNS routing is registered
// with systemd-resolved. If the registration is missing (e.g. after
// a resolved restart or Wi-Fi reconnect), it self-heals by
// re-registering.
type ResolvedDNSCheck struct {
	ops      ResolvedOps
	interval time.Duration
}

// NewResolvedDNSCheck creates a health check that verifies and
// self-heals systemd-resolved DNS routing registration.
func NewResolvedDNSCheck(ops ResolvedOps, interval time.Duration) *ResolvedDNSCheck {
	return &ResolvedDNSCheck{ops: ops, interval: interval}
}

func (c *ResolvedDNSCheck) Name() string            { return "resolved-dns" }
func (c *ResolvedDNSCheck) Interval() time.Duration { return c.interval }

func (c *ResolvedDNSCheck) Check(_ context.Context) CheckResult {
	registered, err := c.ops.IsRegistered()
	if err != nil {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("check failed: %v", err),
		}
	}

	if registered {
		return CheckResult{
			Status:  StatusHealthy,
			Message: "registered",
		}
	}

	// Self-heal: re-register with resolved.
	if err := c.ops.Register(); err != nil {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("re-register failed: %v", err),
		}
	}

	return CheckResult{
		Status:  StatusDegraded,
		Message: "re-registered after resolved restart",
	}
}
