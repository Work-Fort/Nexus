// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Work-Fort/nexus-e2e/harness"
)

const btrfsSuperMagic = 0x9123683e

// requireBtrfs skips the test if the working directory is not on btrfs
// or the btrfs CLI is not available.
func requireBtrfs(t *testing.T) {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(".", &st); err != nil {
		t.Skipf("statfs: %v", err)
	}
	if st.Type != btrfsSuperMagic {
		t.Skip("working directory is not on btrfs")
	}
	if _, err := exec.LookPath("btrfs"); err != nil {
		t.Skip("btrfs CLI not in PATH")
	}
}

// requireBtrfsSend skips the test if the build/nexus-btrfs helper is
// missing CAP_SYS_ADMIN. The btrfs send/receive path used by drive
// export/import shells out to this helper, which silently returns
// "CAP 21 not in permitted set" when uncapabilitated. Run
// `sudo ./scripts/dev-setcap-loop.sh` (or `sudo mise run install:local`)
// to set caps; this helper polls up to 5s in case the loop is mid-cycle.
func requireBtrfsSend(t *testing.T) {
	t.Helper()
	requireBtrfs(t)

	helper, err := filepath.Abs("../../build/nexus-btrfs")
	if err != nil {
		t.Skipf("cannot resolve build/nexus-btrfs: %v", err)
	}
	if _, err := os.Stat(helper); err != nil {
		t.Skipf("build/nexus-btrfs not found (run `mise run build`): %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("getcap", helper).Output()
		if err == nil && strings.Contains(string(out), "cap_sys_admin") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Skipf("build/nexus-btrfs lacks cap_sys_admin — run: sudo ./scripts/dev-setcap-loop.sh")
}

// btrfsPropertyGet runs "btrfs property get <path> ro" and returns the output.
// Returns error if the path is not a valid btrfs subvolume.
func btrfsPropertyGet(path string) (string, error) {
	out, err := exec.Command("btrfs", "property", "get", path, "ro").CombinedOutput()
	return string(out), err
}

// btrfsDaemon holds references needed for btrfs verification.
type btrfsDaemon struct {
	client    *harness.Client
	drivesDir string // absolute path to the drives directory
}

// startBtrfsDaemon starts a daemon with btrfs-compatible configuration.
// WithBaseDir places the XDG temp dir on the current (btrfs) filesystem,
// so the default drives dir ($XDG_STATE_HOME/nexus/drives) is also on btrfs.
func startBtrfsDaemon(t *testing.T, extraOpts ...harness.DaemonOption) *btrfsDaemon {
	t.Helper()

	absBase, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	// Use the build/ copy of nexus-btrfs which has CAP_SYS_ADMIN from
	// the dev-setcap-loop. The temp E2E copies don't have capabilities.
	btrfsHelper, err := filepath.Abs("../../build/nexus-btrfs")
	if err != nil {
		t.Fatal(err)
	}

	opts := []harness.DaemonOption{
		harness.WithSnapshotter("btrfs"),
		harness.WithBaseDir(absBase),
		harness.WithLogLevel("debug"),
		harness.WithQuotaHelper(""),
		harness.WithBtrfsHelper(btrfsHelper),
	}
	opts = append(opts, extraOpts...)

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d, err := harness.StartDaemon(nexusBin, binDir, addr, opts...)
	if err != nil {
		t.Fatal(err)
	}

	drivesDir := filepath.Join(d.XDGDir(), "state", "nexus", "drives")
	t.Cleanup(func() {
		d.StopFatal(t)
		cleanupBtrfsDir(filepath.Join(drivesDir, ".snapshots"))
		cleanupBtrfsDir(drivesDir)
	})

	return &btrfsDaemon{
		client:    harness.NewClient(addr),
		drivesDir: drivesDir,
	}
}

// cleanupBtrfsDir recursively deletes btrfs subvolumes in a directory.
func cleanupBtrfsDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		// Try to delete as subvolume; ignore errors for regular dirs.
		exec.Command("btrfs", "subvolume", "delete", path).Run() //nolint:errcheck
	}
}

func TestSnapshotCreateAndList(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-create", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Create a snapshot.
	snap, err := bd.client.CreateSnapshot(vm.ID, "s1")
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	if snap.Name != "s1" {
		t.Errorf("snapshot name = %q, want %q", snap.Name, "s1")
	}
	if snap.VMID != vm.ID {
		t.Errorf("snapshot vm_id = %q, want %q", snap.VMID, vm.ID)
	}

	// Verify it appears in list.
	snaps, err := bd.client.ListSnapshots(vm.ID)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snaps))
	}
	if snaps[0].Name != "s1" {
		t.Errorf("listed snapshot name = %q, want %q", snaps[0].Name, "s1")
	}
}

func TestSnapshotDelete(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-delete", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	snap, err := bd.client.CreateSnapshot(vm.ID, "to-delete")
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Delete snapshot.
	if err := bd.client.DeleteSnapshot(vm.ID, snap.ID); err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}

	// Verify it's gone from the API.
	snaps, err := bd.client.ListSnapshots(vm.ID)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("expected 0 snapshots after delete, got %d", len(snaps))
	}
}

func TestSnapshotDeleteByName(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-delname", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	if _, err := bd.client.CreateSnapshot(vm.ID, "by-name"); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Delete by name instead of ID.
	if err := bd.client.DeleteSnapshot(vm.ID, "by-name"); err != nil {
		t.Fatalf("delete snapshot by name: %v", err)
	}

	snaps, err := bd.client.ListSnapshots(vm.ID)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 0 {
		t.Errorf("expected 0 snapshots after delete by name, got %d", len(snaps))
	}
}

func TestSnapshotMultiple(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-multi", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Create multiple snapshots.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if _, err := bd.client.CreateSnapshot(vm.ID, name); err != nil {
			t.Fatalf("create snapshot %q: %v", name, err)
		}
	}

	snaps, err := bd.client.ListSnapshots(vm.ID)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(snaps))
	}

	// Delete one and verify the others remain.
	if err := bd.client.DeleteSnapshot(vm.ID, "beta"); err != nil {
		t.Fatalf("delete beta: %v", err)
	}

	snaps, err = bd.client.ListSnapshots(vm.ID)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected 2 snapshots after delete, got %d", len(snaps))
	}

	// Verify remaining snapshot names.
	names := map[string]bool{}
	for _, s := range snaps {
		names[s.Name] = true
	}
	if !names["alpha"] || !names["gamma"] {
		t.Errorf("expected alpha and gamma to remain, got %v", names)
	}
}

func TestSnapshotDuplicateName(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-dup", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	if _, err := bd.client.CreateSnapshot(vm.ID, "same-name"); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Second snapshot with the same name should fail.
	_, err = bd.client.CreateSnapshot(vm.ID, "same-name")
	if err == nil {
		t.Fatal("expected error creating duplicate snapshot name, got nil")
	}
}

func TestSnapshotCascadeDeleteVM(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-cascade", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	if _, err := bd.client.CreateSnapshot(vm.ID, "c1"); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	if _, err := bd.client.CreateSnapshot(vm.ID, "c2"); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Verify snapshots exist via API.
	snaps, err := bd.client.ListSnapshots(vm.ID)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snaps))
	}

	// Delete the VM — snapshots should be cascade-deleted.
	if err := bd.client.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete VM: %v", err)
	}
}

func TestSnapshotWithDrive(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-drive", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	drv, err := bd.client.CreateDrive("snap-drv", "256M", "/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := bd.client.AttachDrive(drv.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// Create snapshot — should snapshot both rootfs and drive.
	snap, err := bd.client.CreateSnapshot(vm.ID, "with-drive")
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Verify drive snapshot subvolume at <drivesDir>/.snapshots/<driveName>@<snapName>.
	driveSnap := filepath.Join(bd.drivesDir, ".snapshots", "snap-drv@with-drive")
	out, err := btrfsPropertyGet(driveSnap)
	if err != nil {
		t.Fatalf("drive snapshot subvolume: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=true") {
		t.Errorf("drive snapshot should be read-only, got: %s", out)
	}

	// Delete snapshot and verify drive snapshot is cleaned up.
	if err := bd.client.DeleteSnapshot(vm.ID, snap.ID); err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}

	if _, err := os.Stat(driveSnap); !os.IsNotExist(err) {
		t.Errorf("drive snapshot should be deleted")
	}
}

func TestSnapshotClone(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVMWithImage("snap-clone-src", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	snap, err := bd.client.CreateSnapshot(vm.ID, "for-clone")
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Clone the snapshot into a new VM.
	cloned, err := bd.client.CloneSnapshot(vm.ID, snap.ID, "snap-clone-dst")
	if err != nil {
		t.Fatalf("clone snapshot: %v", err)
	}
	if cloned.Name != "snap-clone-dst" {
		t.Errorf("cloned VM name = %q, want %q", cloned.Name, "snap-clone-dst")
	}
	if cloned.ID == vm.ID {
		t.Error("cloned VM should have a different ID")
	}
	if cloned.State != "created" {
		t.Errorf("cloned VM state = %q, want %q", cloned.State, "created")
	}

	// Both VMs should appear in the list.
	vms, err := bd.client.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(vms))
	}
}

func TestSnapshotRestore(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	vm, err := bd.client.CreateVM("snap-restore", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Create snapshot of the initial state.
	if _, err := bd.client.CreateSnapshot(vm.ID, "initial"); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Restore from snapshot (VM is stopped/created, so this should work).
	if err := bd.client.RestoreSnapshot(vm.ID, "initial"); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}

	// VM should still be in a valid state after restore.
	got, err := bd.client.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after restore: %v", err)
	}
	if got.State != "created" && got.State != "stopped" {
		t.Errorf("state after restore = %q, want created or stopped", got.State)
	}
}
