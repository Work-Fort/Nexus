// SPDX-License-Identifier: GPL-2.0-only
package btrfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// requireBtrfs skips the test if the working directory is not on btrfs.
func requireBtrfs(t *testing.T) {
	t.Helper()
	ok, err := IsBtrfs(".")
	if err != nil {
		t.Skipf("cannot check filesystem type: %v", err)
	}
	if !ok {
		t.Skip("not a btrfs filesystem")
	}
}

// testDir returns a temp directory on the current btrfs filesystem and
// registers cleanup. All subvolumes created inside must be deleted before
// the test ends.  We cannot use t.TempDir() because it defaults to /tmp
// which is typically tmpfs.
func testDir(t *testing.T) string {
	t.Helper()
	requireBtrfs(t)
	dir, err := os.MkdirTemp(".", ".btrfs-test-*")
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

func TestIsBtrfs(t *testing.T) {
	requireBtrfs(t)
	ok, err := IsBtrfs(".")
	if err != nil {
		t.Fatalf("IsBtrfs: %v", err)
	}
	if !ok {
		t.Fatal("expected true on btrfs filesystem")
	}
}

func TestIsBtrfsNonExistent(t *testing.T) {
	_, err := IsBtrfs("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestIsSubvolumeRegularDir(t *testing.T) {
	dir := testDir(t)
	ok, err := IsSubvolume(dir)
	if err != nil {
		t.Fatalf("IsSubvolume: %v", err)
	}
	if ok {
		t.Fatal("expected false for regular directory")
	}
}

func TestIsSubvolumeNonExistent(t *testing.T) {
	_, err := IsSubvolume("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestCreateSubvolume(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "@test-subvol")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	ok, err := IsSubvolume(path)
	if err != nil {
		t.Fatalf("IsSubvolume: %v", err)
	}
	if !ok {
		t.Fatal("expected path to be a subvolume after creation")
	}
}

func TestCreateSubvolumeAlreadyExists(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "@test-exists")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	err := CreateSubvolume(path)
	if err == nil {
		t.Fatal("expected error for duplicate subvolume")
	}
	if !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got: %v", err)
	}
}

func TestCreateSubvolumeNotBtrfs(t *testing.T) {
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Skip("/dev/shm not available")
	}
	ok, _ := IsBtrfs("/dev/shm")
	if ok {
		t.Skip("/dev/shm is on btrfs")
	}

	err := CreateSubvolume("/dev/shm/btrfs-test-subvol")
	if err == nil {
		t.Fatal("expected error on non-btrfs filesystem")
	}
	if !errors.Is(err, ErrNotBtrfs) {
		t.Fatalf("expected ErrNotBtrfs, got: %v", err)
	}
}

func TestGetReadOnlyDefault(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "@test-ro-default")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	ro, err := GetReadOnly(path)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if ro {
		t.Fatal("expected new subvolume to be writable by default")
	}
}

func TestSetReadOnly(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "@test-set-ro")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := SetReadOnly(path, true); err != nil {
		t.Fatalf("SetReadOnly(true): %v", err)
	}
	ro, err := GetReadOnly(path)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if !ro {
		t.Fatal("expected subvolume to be read-only after SetReadOnly(true)")
	}

	if err := SetReadOnly(path, false); err != nil {
		t.Fatalf("SetReadOnly(false): %v", err)
	}
	ro, err = GetReadOnly(path)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if ro {
		t.Fatal("expected subvolume to be writable after SetReadOnly(false)")
	}
}
