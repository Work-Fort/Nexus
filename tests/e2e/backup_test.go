// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Work-Fort/nexus-e2e/harness"
)

const testImage = "docker.io/library/alpine:latest"

func TestExportImportWithDrive(t *testing.T) {
	requireBtrfs(t)
	// Use default containerd snapshotter (not btrfs) — only drive storage needs btrfs.
	bd := startBtrfsDaemon(t, harness.WithSnapshotter(""))

	vm, err := bd.client.CreateVMWithImage("export-drv", "agent", testImage)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	drv, err := bd.client.CreateDrive("exp-data", "256M", "/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := bd.client.AttachDrive(drv.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// Write a marker file directly to the drive btrfs subvolume.
	drivePath := filepath.Join(bd.drivesDir, "exp-data")
	if err := os.WriteFile(filepath.Join(drivePath, "marker.txt"), []byte("hello-export"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	// Export the VM with drives.
	archive, err := bd.client.ExportVM(vm.ID, false)
	if err != nil {
		logPath := filepath.Join(filepath.Dir(bd.drivesDir), "debug.log")
		if logData, e := os.ReadFile(logPath); e == nil {
			t.Logf("daemon log:\n%s", string(logData))
		}
		t.Fatalf("export VM: %v", err)
	}
	t.Logf("archive size: %d bytes", len(archive))

	// Delete original VM (detaches drive) and then the drive.
	if err := bd.client.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete VM: %v", err)
	}
	if err := bd.client.DeleteDrive(drv.ID); err != nil {
		t.Fatalf("delete drive: %v", err)
	}

	// Import from archive.
	imported, err := bd.client.ImportVM(archive, false)
	if err != nil {
		logPath := filepath.Join(filepath.Dir(bd.drivesDir), "debug.log")
		if logData, e := os.ReadFile(logPath); e == nil {
			t.Logf("daemon log:\n%s", string(logData))
		}
		t.Fatalf("import VM: %v", err)
	}
	if imported.VM.Name != "export-drv" {
		t.Errorf("imported name = %q, want %q", imported.VM.Name, "export-drv")
	}
	if imported.VM.State != "created" {
		t.Errorf("imported state = %q, want %q", imported.VM.State, "created")
	}

	// Verify drive was recreated.
	drives, err := bd.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	var found bool
	for _, d := range drives {
		if d.Name == "exp-data" {
			found = true
			if d.MountPath != "/data" {
				t.Errorf("drive mount_path = %q, want %q", d.MountPath, "/data")
			}
		}
	}
	if !found {
		t.Fatal("imported drive 'exp-data' not found in drive list")
	}

	// Verify marker file survived the btrfs send/receive round-trip.
	data, err := os.ReadFile(filepath.Join(bd.drivesDir, "exp-data", "marker.txt"))
	if err != nil {
		t.Fatalf("read marker after import: %v", err)
	}
	if string(data) != "hello-export" {
		t.Errorf("marker data = %q, want %q", string(data), "hello-export")
	}
}

func TestExportImportMultipleDrives(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t, harness.WithSnapshotter(""))

	vm, err := bd.client.CreateVMWithImage("export-multi", "agent", testImage)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Create and attach two drives.
	for _, spec := range []struct{ name, mount string }{
		{"multi-data", "/data"},
		{"multi-logs", "/logs"},
	} {
		drv, err := bd.client.CreateDrive(spec.name, "256M", spec.mount)
		if err != nil {
			t.Fatalf("create drive %s: %v", spec.name, err)
		}
		if err := bd.client.AttachDrive(drv.ID, vm.ID); err != nil {
			t.Fatalf("attach drive %s: %v", spec.name, err)
		}
		// Write a unique marker to each drive subvolume.
		drivePath := filepath.Join(bd.drivesDir, spec.name)
		if err := os.WriteFile(filepath.Join(drivePath, "id.txt"), []byte(spec.name), 0644); err != nil {
			t.Fatalf("write marker for %s: %v", spec.name, err)
		}
	}

	archive, err := bd.client.ExportVM(vm.ID, false)
	if err != nil {
		t.Fatalf("export VM: %v", err)
	}

	// Delete original VM and drives.
	if err := bd.client.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete VM: %v", err)
	}
	drives, err := bd.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	for _, d := range drives {
		if err := bd.client.DeleteDrive(d.ID); err != nil {
			t.Fatalf("delete drive %s: %v", d.Name, err)
		}
	}

	// Import and verify both drives came back with their data.
	imported, err := bd.client.ImportVM(archive, false)
	if err != nil {
		t.Fatalf("import VM: %v", err)
	}
	if imported.VM.Name != "export-multi" {
		t.Errorf("imported name = %q, want %q", imported.VM.Name, "export-multi")
	}

	for _, spec := range []struct{ name, mount string }{
		{"multi-data", "/data"},
		{"multi-logs", "/logs"},
	} {
		data, err := os.ReadFile(filepath.Join(bd.drivesDir, spec.name, "id.txt"))
		if err != nil {
			t.Fatalf("read marker for %s: %v", spec.name, err)
		}
		if string(data) != spec.name {
			t.Errorf("drive %s data = %q, want %q", spec.name, string(data), spec.name)
		}
	}
}

func TestExportImportCrossDaemon(t *testing.T) {
	requireBtrfs(t)

	// Daemon A: source — create VM with drive and marker data, then export.
	srcDaemon := startBtrfsDaemon(t, harness.WithSnapshotter(""))

	vm, err := srcDaemon.client.CreateVMWithImage("cross-vm", "agent", testImage)
	if err != nil {
		t.Fatalf("create VM on source: %v", err)
	}

	drv, err := srcDaemon.client.CreateDrive("cross-drv", "256M", "/data")
	if err != nil {
		t.Fatalf("create drive on source: %v", err)
	}
	if err := srcDaemon.client.AttachDrive(drv.ID, vm.ID); err != nil {
		t.Fatalf("attach drive on source: %v", err)
	}

	// Write marker files directly to the drive btrfs subvolume.
	drivePath := filepath.Join(srcDaemon.drivesDir, "cross-drv")
	if err := os.WriteFile(filepath.Join(drivePath, "marker.txt"), []byte("cross-daemon-data"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(drivePath, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(drivePath, "subdir", "nested.txt"), []byte("nested-content"), 0644); err != nil {
		t.Fatalf("write nested marker: %v", err)
	}

	archive, err := srcDaemon.client.ExportVM(vm.ID, false)
	if err != nil {
		t.Fatalf("export VM from source: %v", err)
	}
	t.Logf("archive size: %d bytes", len(archive))

	// Daemon B: destination — completely separate instance.
	dstDaemon := startBtrfsDaemon(t, harness.WithSnapshotter(""))

	// Verify destination is empty before import.
	vms, err := dstDaemon.client.ListVMs()
	if err != nil {
		t.Fatalf("list VMs on dest: %v", err)
	}
	if len(vms) != 0 {
		t.Fatalf("expected 0 VMs on fresh dest daemon, got %d", len(vms))
	}

	// Import the archive into the destination daemon.
	imported, err := dstDaemon.client.ImportVM(archive, false)
	if err != nil {
		t.Fatalf("import VM into dest: %v", err)
	}

	// Verify VM metadata.
	if imported.VM.Name != "cross-vm" {
		t.Errorf("imported name = %q, want %q", imported.VM.Name, "cross-vm")
	}
	if imported.VM.State != "created" {
		t.Errorf("imported state = %q, want %q", imported.VM.State, "created")
	}
	if imported.VM.Image != testImage {
		t.Errorf("imported image = %q, want %q", imported.VM.Image, testImage)
	}

	// Verify drive was recreated on the destination.
	drives, err := dstDaemon.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives on dest: %v", err)
	}
	var foundDrive bool
	for _, d := range drives {
		if d.Name == "cross-drv" {
			foundDrive = true
			if d.MountPath != "/data" {
				t.Errorf("drive mount_path = %q, want %q", d.MountPath, "/data")
			}
		}
	}
	if !foundDrive {
		t.Fatal("imported drive 'cross-drv' not found on destination daemon")
	}

	// Verify marker file survived the cross-daemon btrfs send/receive.
	data, err := os.ReadFile(filepath.Join(dstDaemon.drivesDir, "cross-drv", "marker.txt"))
	if err != nil {
		t.Fatalf("read marker on dest: %v", err)
	}
	if string(data) != "cross-daemon-data" {
		t.Errorf("marker data = %q, want %q", string(data), "cross-daemon-data")
	}

	// Verify nested file survived too.
	nested, err := os.ReadFile(filepath.Join(dstDaemon.drivesDir, "cross-drv", "subdir", "nested.txt"))
	if err != nil {
		t.Fatalf("read nested marker on dest: %v", err)
	}
	if string(nested) != "nested-content" {
		t.Errorf("nested data = %q, want %q", string(nested), "nested-content")
	}

	// Verify the source daemon still has its original VM (export is non-destructive).
	srcVMs, err := srcDaemon.client.ListVMs()
	if err != nil {
		t.Fatalf("list VMs on source after export: %v", err)
	}
	if len(srcVMs) != 1 {
		t.Errorf("source should still have 1 VM, got %d", len(srcVMs))
	}
}

func TestExportImportNameConflict(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t, harness.WithSnapshotter(""))

	vm, err := bd.client.CreateVMWithImage("conflict-vm", "agent", testImage)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	drv, err := bd.client.CreateDrive("conflict-drv", "256M", "/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := bd.client.AttachDrive(drv.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	archive, err := bd.client.ExportVM(vm.ID, false)
	if err != nil {
		t.Fatalf("export VM: %v", err)
	}

	// Import without deleting originals — should fail with name conflict.
	_, err = bd.client.ImportVM(archive, false)
	if err == nil {
		t.Fatal("expected error importing duplicate VM name, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}
