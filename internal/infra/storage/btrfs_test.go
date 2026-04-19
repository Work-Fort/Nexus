package storage

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

const btrfsSuperMagic = 0x9123683e

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

// btrfsTestDir returns a temp directory on btrfs. We cannot use t.TempDir()
// because it defaults to /tmp which is typically tmpfs.
func btrfsTestDir(t *testing.T) string {
	t.Helper()
	ok, _ := btrfs.IsBtrfs(".")
	if !ok {
		t.Skip("not on btrfs")
	}
	dir, err := os.MkdirTemp(".", ".storage-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(abs) })
	return abs
}

func TestBtrfsStorageQuotaHelperCalled(t *testing.T) {
	dir := filepath.Join(btrfsTestDir(t), "drives")

	// Fake helper that records its args.
	helperDir := t.TempDir()
	argsFile := filepath.Join(helperDir, "args.txt")
	helper := filepath.Join(helperDir, "nexus-quota")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho \"$@\" > "+argsFile+"\n"), 0755); err != nil {
		t.Fatal(err)
	}

	bs, err := NewBtrfsWithQuota(dir, helper)
	if err != nil {
		t.Fatalf("NewBtrfsWithQuota: %v", err)
	}

	_, err = bs.CreateVolume(context.Background(), "test-vol", 1073741824)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { btrfs.DeleteSubvolume(filepath.Join(dir, "test-vol")) })

	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("helper was not called: %v", err)
	}
	want := "set-limit " + filepath.Join(dir, "test-vol") + " 1073741824\n"
	if string(data) != want {
		t.Errorf("helper args = %q, want %q", data, want)
	}
}

func TestBtrfsStorageQuotaHelperFailureRollback(t *testing.T) {
	dir := filepath.Join(btrfsTestDir(t), "drives")

	// Helper that always fails.
	helperDir := t.TempDir()
	helper := filepath.Join(helperDir, "nexus-quota")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho 'error' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	bs, err := NewBtrfsWithQuota(dir, helper)
	if err != nil {
		t.Fatalf("NewBtrfsWithQuota: %v", err)
	}

	_, err = bs.CreateVolume(context.Background(), "fail-vol", 1073741824)
	if err == nil {
		t.Fatal("expected error when helper fails")
	}

	// Subvolume should be rolled back.
	volPath := filepath.Join(dir, "fail-vol")
	if _, err := os.Stat(volPath); !os.IsNotExist(err) {
		t.Errorf("subvolume %s still exists after rollback", volPath)
		btrfs.DeleteSubvolume(volPath)
	}
}

func TestBtrfsStorageNoQuotaHelper(t *testing.T) {
	dir := filepath.Join(btrfsTestDir(t), "drives")

	bs, err := NewBtrfs(dir)
	if err != nil {
		t.Fatalf("NewBtrfs: %v", err)
	}

	_, err = bs.CreateVolume(context.Background(), "no-quota", 1073741824)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { btrfs.DeleteSubvolume(filepath.Join(dir, "no-quota")) })
}

func TestBtrfsStorageQuotaSkippedForZeroSize(t *testing.T) {
	dir := filepath.Join(btrfsTestDir(t), "drives")

	// Helper that would fail if called — proves it's not called.
	helperDir := t.TempDir()
	helper := filepath.Join(helperDir, "nexus-quota")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	bs, err := NewBtrfsWithQuota(dir, helper)
	if err != nil {
		t.Fatalf("NewBtrfsWithQuota: %v", err)
	}

	// sizeBytes=0 should skip the helper call entirely.
	_, err = bs.CreateVolume(context.Background(), "zero-size", 0)
	if err != nil {
		t.Fatalf("CreateVolume with zero size: %v", err)
	}
	t.Cleanup(func() { btrfs.DeleteSubvolume(filepath.Join(dir, "zero-size")) })
}

func TestBtrfsStorage_CloneVolume(t *testing.T) {
	requireBtrfs(t)

	dir := btrfsTestDir(t)
	store, err := NewBtrfs(dir)
	if err != nil {
		t.Fatalf("NewBtrfs: %v", err)
	}

	if _, err := store.CreateVolume(context.Background(), "src", 0); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	// Drop a marker file so we can verify CoW semantics.
	if err := os.WriteFile(filepath.Join(dir, "src", "marker"), []byte("hi"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	if err := store.SnapshotVolume(context.Background(), "src", "src@snap-1"); err != nil {
		t.Fatalf("SnapshotVolume: %v", err)
	}

	// CloneVolume materialises src@snap-1 into a brand-new path "clone"
	// without requiring "clone" to exist beforehand.
	if err := store.CloneVolume(context.Background(), "src@snap-1", "clone"); err != nil {
		t.Fatalf("CloneVolume: %v", err)
	}

	// The clone must be a writable subvolume containing the marker.
	clonePath := filepath.Join(dir, "clone")
	got, err := os.ReadFile(filepath.Join(clonePath, "marker"))
	if err != nil {
		t.Fatalf("read clone marker: %v", err)
	}
	if string(got) != "hi" {
		t.Errorf("clone content = %q, want %q", got, "hi")
	}
	ro, err := btrfs.GetReadOnly(clonePath)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if ro {
		t.Errorf("clone must be writable, got read-only")
	}

	t.Cleanup(func() {
		// Reverse order: clone first (a clone of a snapshot), then snapshot, then src.
		_ = btrfs.DeleteSubvolume(clonePath)
		_ = store.DeleteVolumeSnapshot(context.Background(), "src@snap-1")
		_ = store.DeleteVolume(context.Background(), "src")
	})
}
