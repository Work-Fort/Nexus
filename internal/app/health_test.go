// SPDX-License-Identifier: GPL-3.0-or-later

package app_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/app"
)

// stubCheck is a configurable HealthCheck for testing.
type stubCheck struct {
	name     string
	interval time.Duration

	mu     sync.Mutex
	result app.CheckResult
}

func newStubCheck(name string, interval time.Duration, status app.HealthStatus, msg string) *stubCheck {
	return &stubCheck{
		name:     name,
		interval: interval,
		result:   app.CheckResult{Status: status, Message: msg},
	}
}

func (s *stubCheck) Name() string            { return s.name }
func (s *stubCheck) Interval() time.Duration  { return s.interval }
func (s *stubCheck) Check(_ context.Context) app.CheckResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result
}

func (s *stubCheck) setResult(status app.HealthStatus, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = app.CheckResult{Status: status, Message: msg}
}

func TestHealthReportIncludesVersion(t *testing.T) {
	check := newStubCheck("test", 50*time.Millisecond, app.StatusHealthy, "ok")
	svc := app.NewHealthService(check)
	svc.SetVersion("1.2.3")
	svc.Start(context.Background())
	defer svc.Stop()

	report := svc.Status()
	if report.Version != "1.2.3" {
		t.Fatalf("expected version 1.2.3, got %q", report.Version)
	}
}

func TestHealthServiceStatus(t *testing.T) {
	check := newStubCheck("test", 50*time.Millisecond, app.StatusHealthy, "all good")

	svc := app.NewHealthService(check)
	svc.Start(context.Background())
	defer svc.Stop()

	report := svc.Status()
	if report.Status != app.StatusHealthy {
		t.Fatalf("expected healthy, got %s", report.Status)
	}
	if r, ok := report.Checks["test"]; !ok {
		t.Fatal("missing check result for 'test'")
	} else if r.Status != app.StatusHealthy {
		t.Fatalf("expected check healthy, got %s", r.Status)
	}
}

func TestHealthServiceDegraded(t *testing.T) {
	healthy := newStubCheck("ok", 50*time.Millisecond, app.StatusHealthy, "fine")
	degraded := newStubCheck("slow", 50*time.Millisecond, app.StatusDegraded, "slow response")

	svc := app.NewHealthService(healthy, degraded)
	svc.Start(context.Background())
	defer svc.Stop()

	report := svc.Status()
	if report.Status != app.StatusDegraded {
		t.Fatalf("expected degraded, got %s", report.Status)
	}
}

func TestHealthServiceUnhealthy(t *testing.T) {
	degraded := newStubCheck("slow", 50*time.Millisecond, app.StatusDegraded, "slow")
	unhealthy := newStubCheck("down", 50*time.Millisecond, app.StatusUnhealthy, "connection refused")

	svc := app.NewHealthService(degraded, unhealthy)
	svc.Start(context.Background())
	defer svc.Stop()

	report := svc.Status()
	if report.Status != app.StatusUnhealthy {
		t.Fatalf("expected unhealthy, got %s", report.Status)
	}
}

func TestHealthServicePeriodicUpdate(t *testing.T) {
	check := newStubCheck("flip", 50*time.Millisecond, app.StatusHealthy, "ok")

	svc := app.NewHealthService(check)
	svc.Start(context.Background())
	defer svc.Stop()

	// Initially healthy (Start runs checks synchronously first).
	report := svc.Status()
	if report.Status != app.StatusHealthy {
		t.Fatalf("expected initially healthy, got %s", report.Status)
	}

	// Change the stub result to degraded.
	check.setResult(app.StatusDegraded, "warming up")

	// Wait for periodic tick to pick up the change.
	time.Sleep(100 * time.Millisecond)

	report = svc.Status()
	if report.Status != app.StatusDegraded {
		t.Fatalf("expected degraded after update, got %s", report.Status)
	}
}

func TestRuntimeHealthyKataDegraded(t *testing.T) {
	containerd := newStubCheck("containerd", 50*time.Millisecond, app.StatusHealthy, "ok")
	kataKernel := newStubCheck("kata-kernel", 50*time.Millisecond, app.StatusDegraded, "kernel missing")

	svc := app.NewHealthService(containerd, kataKernel)
	svc.Start(context.Background())
	defer svc.Stop()

	// runc should work even when kata-kernel is degraded.
	if err := svc.RuntimeHealthy("io.containerd.runc.v2"); err != nil {
		t.Fatalf("runc should be healthy, got: %v", err)
	}

	// kata should fail because kata-kernel is degraded.
	if err := svc.RuntimeHealthy("io.containerd.kata.v2"); err == nil {
		t.Fatal("kata should be unhealthy when kata-kernel is degraded")
	}
}

func TestRuntimeHealthyContainerdUnhealthy(t *testing.T) {
	containerd := newStubCheck("containerd", 50*time.Millisecond, app.StatusUnhealthy, "connection refused")
	kataKernel := newStubCheck("kata-kernel", 50*time.Millisecond, app.StatusHealthy, "ok")

	svc := app.NewHealthService(containerd, kataKernel)
	svc.Start(context.Background())
	defer svc.Stop()

	// ALL runtimes should fail when containerd is unhealthy.
	if err := svc.RuntimeHealthy("io.containerd.runc.v2"); err == nil {
		t.Fatal("runc should fail when containerd is unhealthy")
	}
	if err := svc.RuntimeHealthy("io.containerd.kata.v2"); err == nil {
		t.Fatal("kata should fail when containerd is unhealthy")
	}
}

func TestRuntimeHealthyAllHealthy(t *testing.T) {
	containerd := newStubCheck("containerd", 50*time.Millisecond, app.StatusHealthy, "ok")
	kataKernel := newStubCheck("kata-kernel", 50*time.Millisecond, app.StatusHealthy, "ok")

	svc := app.NewHealthService(containerd, kataKernel)
	svc.Start(context.Background())
	defer svc.Stop()

	// kata should work when everything is healthy.
	if err := svc.RuntimeHealthy("io.containerd.kata.v2"); err != nil {
		t.Fatalf("kata should be healthy, got: %v", err)
	}
}
