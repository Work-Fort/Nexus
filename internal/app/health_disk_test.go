// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"testing"
	"time"
)

func TestDiskCheckHealthy(t *testing.T) {
	dir := t.TempDir()

	chk := NewDiskSpaceCheck(
		[]string{dir},
		30*time.Second,
		1024,      // 1 KB warn threshold — any real disk has more
		512,       // 512 B critical threshold
	)

	result := chk.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestDiskCheckDegraded(t *testing.T) {
	dir := t.TempDir()

	chk := NewDiskSpaceCheck(
		[]string{dir},
		30*time.Second,
		999*1024*1024*1024*1024, // 999 TB warn — more than any real disk
		1,                       // 1 B critical — won't trigger
	)

	result := chk.Check(context.Background())

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestDiskCheckUnhealthy(t *testing.T) {
	dir := t.TempDir()

	chk := NewDiskSpaceCheck(
		[]string{dir},
		30*time.Second,
		999*1024*1024*1024*1024, // 999 TB warn
		999*1024*1024*1024*1024, // 999 TB critical — more than any real disk
	)

	result := chk.Check(context.Background())

	if result.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestDiskCheckNonexistentPath(t *testing.T) {
	chk := NewDiskSpaceCheck(
		[]string{"/nonexistent/path/that/does/not/exist"},
		30*time.Second,
		1024,
		512,
	)

	result := chk.Check(context.Background())

	if result.Status == StatusHealthy {
		t.Fatalf("expected non-healthy status for nonexistent path, got healthy: %s", result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}
