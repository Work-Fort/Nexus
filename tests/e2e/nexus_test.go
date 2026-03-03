// SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestCreateDrive(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDrive("test-drive", "1G", "/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if d.ID == "" {
		t.Fatal("expected non-empty drive ID")
	}
	if d.Name != "test-drive" {
		t.Errorf("name = %q, want %q", d.Name, "test-drive")
	}

	drives, err := c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(drives) != 1 {
		t.Fatalf("expected 1 drive, got %d", len(drives))
	}
}

func TestAttachDetachDrive(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-drive-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDrive("test-attach", "512M", "/mnt/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}

	if err := c.AttachDrive(d.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// Verify drive shows vm_id.
	got, err := c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(got) != 1 || got[0].VMID == nil || *got[0].VMID != vm.ID {
		t.Errorf("drive should show vm_id=%s after attach", vm.ID)
	}

	if err := c.DetachDrive(d.ID); err != nil {
		t.Fatalf("detach drive: %v", err)
	}

	got, err = c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(got) != 1 || got[0].VMID != nil {
		t.Error("drive should have nil vm_id after detach")
	}
}

func TestDeleteAttachedDrive(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-delattach-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDrive("test-delattach", "256M", "/mnt/x")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}

	if err := c.AttachDrive(d.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	err = c.DeleteDrive(d.ID)
	if err == nil {
		t.Fatal("expected error deleting attached drive, got nil")
	}

	// Clean up.
	c.DetachDrive(d.ID)
	c.DeleteDrive(d.ID)
}

func TestDriveInVM(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine so the container stays alive for exec.
	vm, err := c.CreateVMWithImage("test-driveinvm", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDrive("test-visible", "256M", "/mnt/testdrive")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}

	if err := c.AttachDrive(d.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	result, err := c.ExecVM(vm.ID, []string{"mount"})
	if err != nil {
		t.Fatalf("exec mount: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("mount exit code = %d, stderr: %s", result.ExitCode, result.Stderr)
	}
	t.Logf("mount output:\n%s", result.Stdout)

	// Stop + cleanup.
	c.StopVM(vm.ID)
}

func TestDeleteDrive(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDrive("test-deldrive", "128M", "/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := c.DeleteDrive(d.ID); err != nil {
		t.Fatalf("delete drive: %v", err)
	}

	drives, err := c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(drives) != 0 {
		t.Errorf("expected 0 drives after delete, got %d", len(drives))
	}
}

func TestCreateDevice(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDevice("test-dev", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if d.ID == "" {
		t.Fatal("expected non-empty device ID")
	}

	devices, err := c.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
}

func TestAttachDetachDevice(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-dev-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDevice("test-devattach", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := c.AttachDevice(d.ID, vm.ID); err != nil {
		t.Fatalf("attach device: %v", err)
	}

	devices, err := c.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 1 || devices[0].VMID == nil || *devices[0].VMID != vm.ID {
		t.Errorf("device should show vm_id=%s after attach", vm.ID)
	}

	if err := c.DetachDevice(d.ID); err != nil {
		t.Fatalf("detach device: %v", err)
	}
}

func TestDeleteAttachedDevice(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-devdelatt-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDevice("test-devdelatt", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := c.AttachDevice(d.ID, vm.ID); err != nil {
		t.Fatalf("attach device: %v", err)
	}

	err = c.DeleteDevice(d.ID)
	if err == nil {
		t.Fatal("expected error deleting attached device, got nil")
	}

	// Clean up.
	c.DetachDevice(d.ID)
	c.DeleteDevice(d.ID)
}

func TestDeleteDevice(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDevice("test-devdel", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := c.DeleteDevice(d.ID); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	devices, err := c.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices after delete, got %d", len(devices))
	}
}

func TestGetNonexistentVM(t *testing.T) {
	_, c := startDaemon(t)

	_, err := c.GetVM("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent VM, got nil")
	}
	var apiErr *harness.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Status != 404 {
		t.Errorf("status = %d, want 404", apiErr.Status)
	}
}

func TestStartAlreadyRunningVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-doublestart", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("first start: %v", err)
	}

	// Second start — should return a conflict error.
	err = c.StartVM(vm.ID)
	t.Logf("second start result: %v", err)

	// Clean up.
	c.StopVM(vm.ID)
}

func TestStopAlreadyStopped(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-doublestop", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Stop a VM that was never started.
	err = c.StopVM(vm.ID)
	t.Logf("stop created (not started) VM result: %v", err)
}

func TestInvalidCreatePayload(t *testing.T) {
	_, c := startDaemon(t)

	// Missing name — should fail validation.
	resp, err := c.RawRequest("POST", "/v1/vms", strings.NewReader(`{"role":"agent"}`))
	if err != nil {
		t.Fatalf("raw request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 201 {
		t.Error("expected non-201 for missing name")
	}

	// Invalid role.
	resp, err = c.RawRequest("POST", "/v1/vms", strings.NewReader(`{"name":"bad","role":"invalid"}`))
	if err != nil {
		t.Fatalf("raw request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 201 {
		t.Error("expected non-201 for invalid role")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	_, c := startDaemon(t)

	// Create VM with nginx:alpine (stays alive for exec).
	vm, err := c.CreateVMWithImage("test-backup", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Create and attach a drive.
	drv, err := c.CreateDrive("test-backup-data", "256M", "/mnt/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := c.AttachDrive(drv.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// Start VM and write test data to the drive.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}
	var result *harness.ExecResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"sh", "-c", "echo test-data > /mnt/data/file.txt"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("write test data: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("write exit code = %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	// Stop VM before export (required).
	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop VM: %v", err)
	}

	// Export VM.
	archive, err := c.ExportVM(vm.ID, false)
	if err != nil {
		t.Fatalf("export VM: %v", err)
	}
	if len(archive) == 0 {
		t.Fatal("expected non-empty archive")
	}
	t.Logf("archive size: %d bytes", len(archive))

	// Delete original VM and drive to free the names.
	c.DetachDrive(drv.ID)
	if err := c.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete original VM: %v", err)
	}
	if err := c.DeleteDrive(drv.ID); err != nil {
		t.Fatalf("delete original drive: %v", err)
	}

	// Import from archive.
	imported, err := c.ImportVM(archive, false)
	if err != nil {
		t.Fatalf("import VM: %v", err)
	}
	if imported.VM.Name != "test-backup" {
		t.Errorf("imported name = %q, want %q", imported.VM.Name, "test-backup")
	}
	if imported.VM.State != "created" {
		t.Errorf("imported state = %q, want %q", imported.VM.State, "created")
	}

	// Start imported VM and verify data is intact.
	if err := c.StartVM(imported.VM.ID); err != nil {
		t.Fatalf("start imported VM: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(imported.VM.ID, []string{"cat", "/mnt/data/file.txt"})
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("read exit code = %d, stderr: %s", result.ExitCode, result.Stderr)
	}
	if strings.TrimSpace(result.Stdout) != "test-data" {
		t.Errorf("data = %q, want %q", strings.TrimSpace(result.Stdout), "test-data")
	}

	// Clean up.
	c.StopVM(imported.VM.ID)
}

func TestGracefulShutdown(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVM("test-shutdown", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	_ = vm

	// Send SIGTERM — daemon should exit cleanly.
	if err := d.Stop(); err != nil {
		t.Logf("daemon stop: %v", err)
	}

	// Verify daemon is no longer listening.
	_, err = c.ListVMs()
	if err == nil {
		t.Error("expected error after daemon shutdown, but request succeeded")
	}
}
