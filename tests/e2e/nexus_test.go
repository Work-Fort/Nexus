// SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Work-Fort/nexus-e2e/harness"
)

var (
	nexusBin string // path to compiled nexus binary
	binDir   string // directory containing all helper binaries
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "nexus-e2e-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}
	projectRoot := filepath.Join(wd, "..", "..")

	// Build targets: main binary + helpers.
	targets := []struct {
		name string
		path string
	}{
		{"nexus", "."},
		{"nexus-netns", "./cmd/nexus-netns/"},
		{"nexus-cni-exec", "./cmd/nexus-cni-exec/"},
		{"nexus-quota", "./cmd/nexus-quota/"},
		{"nexus-dns", "./cmd/nexus-dns/"},
	}

	for _, t := range targets {
		binPath := filepath.Join(tmpDir, t.name)
		cmd := exec.Command("go", "build", "-race", "-o", binPath, t.path)
		cmd.Dir = projectRoot
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n", t.name, err)
			os.Exit(1)
		}
	}

	nexusBin = filepath.Join(tmpDir, "nexus")
	binDir = tmpDir
	os.Exit(m.Run())
}

// startDaemon is a test helper that starts a daemon and registers cleanup.
func startDaemon(t *testing.T, opts ...harness.DaemonOption) (*harness.Daemon, *harness.Client) {
	t.Helper()

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d, err := harness.StartDaemon(nexusBin, binDir, addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.StopFatal(t) })

	return d, harness.NewClient(addr)
}

func TestSmoke(t *testing.T) {
	_, c := startDaemon(t)
	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 0 {
		t.Errorf("expected 0 VMs, got %d", len(vms))
	}
}

func TestCreateVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-create", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if vm.ID == "" {
		t.Fatal("expected non-empty VM ID")
	}
	if vm.Name != "test-create" {
		t.Errorf("name = %q, want %q", vm.Name, "test-create")
	}
	if vm.State != "created" {
		t.Errorf("state = %q, want %q", vm.State, "created")
	}

	// Verify it appears in list.
	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(vms))
	}
	if vms[0].ID != vm.ID {
		t.Errorf("list VM ID = %q, want %q", vms[0].ID, vm.ID)
	}
}

func TestStartStopVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-startstop", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	got, err := c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.State != "running" {
		t.Errorf("state after start = %q, want %q", got.State, "running")
	}

	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop VM: %v", err)
	}

	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.State != "stopped" {
		t.Errorf("state after stop = %q, want %q", got.State, "stopped")
	}
}

func TestExecVM(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine because its master process stays alive, unlike
	// plain alpine whose /bin/sh exits immediately with NullIO.
	vm, err := c.CreateVMWithImage("test-exec", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// The container task may need a moment to initialize.
	var result *harness.ExecResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"uname", "-r"})
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", result.ExitCode, result.Stderr)
	}
	if result.Stdout == "" {
		t.Error("expected non-empty stdout from uname -r")
	}
	t.Logf("guest kernel: %s", result.Stdout)
}

func TestDeleteVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-delete", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete VM: %v", err)
	}

	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 0 {
		t.Errorf("expected 0 VMs after delete, got %d", len(vms))
	}
}

func TestDeleteRunningVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-delrunning", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// The API auto-stops running VMs before deleting them.
	if err := c.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete running VM: %v", err)
	}

	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 0 {
		t.Errorf("expected 0 VMs after delete, got %d", len(vms))
	}
}

func TestCreateDuplicateName(t *testing.T) {
	_, c := startDaemon(t)

	_, err := c.CreateVM("test-dup", "agent")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err = c.CreateVM("test-dup", "agent")
	if err == nil {
		t.Fatal("expected error creating duplicate name, got nil")
	}
}
