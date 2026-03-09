// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKataKernelCheckHealthy(t *testing.T) {
	dir := t.TempDir()

	kernelPath := filepath.Join(dir, "vmlinux-6.19.5-anvil")
	if err := os.WriteFile(kernelPath, []byte("fake-kernel"), 0o644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "configuration.toml")
	config := `[hypervisor.qemu]
kernel = "` + kernelPath + `"
`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	chk := NewKataKernelCheck("6.19.5", 30*time.Second, configPath)
	result := chk.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestKataKernelCheckDegradedWrongVersion(t *testing.T) {
	dir := t.TempDir()

	kernelPath := filepath.Join(dir, "vmlinux.container")
	if err := os.WriteFile(kernelPath, []byte("fake-kernel"), 0o644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "configuration.toml")
	config := `[hypervisor.qemu]
kernel = "` + kernelPath + `"
`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	chk := NewKataKernelCheck("6.19.5", 30*time.Second, configPath)
	result := chk.Check(context.Background())

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestKataKernelCheckDegradedMissingFile(t *testing.T) {
	dir := t.TempDir()

	kernelPath := filepath.Join(dir, "vmlinux-6.19.5-anvil")

	configPath := filepath.Join(dir, "configuration.toml")
	config := `[hypervisor.qemu]
kernel = "` + kernelPath + `"
`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	chk := NewKataKernelCheck("6.19.5", 30*time.Second, configPath)
	result := chk.Check(context.Background())

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestKataKernelCheckDegradedNoConfig(t *testing.T) {
	chk := NewKataKernelCheck("6.19.5", 30*time.Second, "/nonexistent/path/configuration.toml")
	result := chk.Check(context.Background())

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}

func TestKataKernelCheckFirecrackerHypervisor(t *testing.T) {
	dir := t.TempDir()

	kernelPath := filepath.Join(dir, "vmlinux-6.19.5-anvil")
	if err := os.WriteFile(kernelPath, []byte("fake-kernel"), 0o644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "configuration.toml")
	config := `[hypervisor.firecracker]
kernel = "` + kernelPath + `"
`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	chk := NewKataKernelCheck("6.19.5", 30*time.Second, configPath)
	result := chk.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
	if result.Message == "" {
		t.Fatal("expected non-empty message")
	}
}
