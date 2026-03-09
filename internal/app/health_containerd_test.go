// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubPinger struct {
	err error
}

func (s *stubPinger) Ping(_ context.Context) error {
	return s.err
}

func TestContainerdCheckHealthy(t *testing.T) {
	chk := NewContainerdCheck(&stubPinger{err: nil}, 10*time.Second)
	result := chk.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
	if result.Message != "connected" {
		t.Fatalf("expected message %q, got %q", "connected", result.Message)
	}
}

func TestContainerdCheckUnhealthy(t *testing.T) {
	chk := NewContainerdCheck(&stubPinger{err: errors.New("connection refused")}, 10*time.Second)
	result := chk.Check(context.Background())

	if result.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy, got %s: %s", result.Status, result.Message)
	}
	if result.Message != "containerd unreachable: connection refused" {
		t.Fatalf("expected message %q, got %q", "containerd unreachable: connection refused", result.Message)
	}
}
