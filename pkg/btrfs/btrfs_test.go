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

// testDir returns a temp directory on the current filesystem and registers
// cleanup. All subvolumes created inside must be deleted before the test ends.
func testDir(t *testing.T) string {
	t.Helper()
	requireBtrfs(t)
	return t.TempDir()
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

// Silence "unused" errors for variables used in later tasks.
var _ = errors.Is
var _ = os.Lstat
var _ = filepath.Join
