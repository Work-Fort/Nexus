// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"time"
)

// Pinger verifies connectivity to a container runtime.
type Pinger interface {
	Ping(ctx context.Context) error
}

// ContainerdCheck monitors containerd reachability.
type ContainerdCheck struct {
	pinger   Pinger
	interval time.Duration
}

// NewContainerdCheck returns a health check that pings containerd on the given
// interval.
func NewContainerdCheck(pinger Pinger, interval time.Duration) *ContainerdCheck {
	return &ContainerdCheck{
		pinger:   pinger,
		interval: interval,
	}
}

// Name returns the health check identifier.
func (c *ContainerdCheck) Name() string { return "containerd" }

// Interval returns how often the check should run.
func (c *ContainerdCheck) Interval() time.Duration { return c.interval }

// Check pings containerd and returns the result.
func (c *ContainerdCheck) Check(ctx context.Context) CheckResult {
	if err := c.pinger.Ping(ctx); err != nil {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("containerd unreachable: %v", err),
		}
	}
	return CheckResult{
		Status:  StatusHealthy,
		Message: "connected",
	}
}
