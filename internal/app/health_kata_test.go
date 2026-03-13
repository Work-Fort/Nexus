// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeKernel returns bytes that mimic a real kernel's embedded version string.
func fakeKernel(version string) []byte {
	return []byte(fmt.Sprintf("\x00Linux version %s (builder@host) #1 SMP\x00", version))
}

func TestKataKernelCheckHealthy(t *testing.T) {
	dir := t.TempDir()

	kernelPath := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(kernelPath, fakeKernel("6.19.5"), 0o644); err != nil {
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

	kernelPath := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(kernelPath, fakeKernel("6.18.0"), 0o644); err != nil {
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

	kernelPath := filepath.Join(dir, "vmlinux")

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

	kernelPath := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(kernelPath, fakeKernel("6.19.5"), 0o644); err != nil {
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

func TestKataKernelCheckNewerVersionHealthy(t *testing.T) {
	dir := t.TempDir()

	kernelPath := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(kernelPath, fakeKernel("6.20.0"), 0o644); err != nil {
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
		t.Fatalf("expected healthy for newer kernel, got %s: %s", result.Status, result.Message)
	}
}

func TestKataKernelCheckNoVersionInBinary(t *testing.T) {
	dir := t.TempDir()

	kernelPath := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(kernelPath, []byte("not-a-real-kernel"), 0o644); err != nil {
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
}
