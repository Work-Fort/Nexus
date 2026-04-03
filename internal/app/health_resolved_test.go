// SPDX-License-Identifier: GPL-3.0-or-later

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/app"
)

type stubResolvedOps struct {
	registered bool
	checkErr   error
	registerErr error
	registerCalled bool
}

func (s *stubResolvedOps) IsRegistered() (bool, error) {
	return s.registered, s.checkErr
}

func (s *stubResolvedOps) Register() error {
	s.registerCalled = true
	return s.registerErr
}

func TestResolvedDNSCheck_Healthy(t *testing.T) {
	ops := &stubResolvedOps{registered: true}
	check := app.NewResolvedDNSCheck(ops, 30*time.Second)

	result := check.Check(context.Background())
	if result.Status != app.StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
	if ops.registerCalled {
		t.Fatal("should not re-register when already registered")
	}
}

func TestResolvedDNSCheck_SelfHeals(t *testing.T) {
	ops := &stubResolvedOps{registered: false}
	check := app.NewResolvedDNSCheck(ops, 30*time.Second)

	result := check.Check(context.Background())
	if result.Status != app.StatusDegraded {
		t.Fatalf("expected degraded after self-heal, got %s: %s", result.Status, result.Message)
	}
	if !ops.registerCalled {
		t.Fatal("should have called Register to self-heal")
	}
}

func TestResolvedDNSCheck_RegisterFails(t *testing.T) {
	ops := &stubResolvedOps{registered: false, registerErr: errors.New("dbus error")}
	check := app.NewResolvedDNSCheck(ops, 30*time.Second)

	result := check.Check(context.Background())
	if result.Status != app.StatusUnhealthy {
		t.Fatalf("expected unhealthy when register fails, got %s: %s", result.Status, result.Message)
	}
}

func TestResolvedDNSCheck_CheckFails(t *testing.T) {
	ops := &stubResolvedOps{checkErr: errors.New("no such interface")}
	check := app.NewResolvedDNSCheck(ops, 30*time.Second)

	result := check.Check(context.Background())
	if result.Status != app.StatusUnhealthy {
		t.Fatalf("expected unhealthy when check fails, got %s: %s", result.Status, result.Message)
	}
}

func TestResolvedDNSCheck_Name(t *testing.T) {
	ops := &stubResolvedOps{}
	check := app.NewResolvedDNSCheck(ops, 30*time.Second)
	if check.Name() != "resolved-dns" {
		t.Fatalf("name = %q, want %q", check.Name(), "resolved-dns")
	}
}
