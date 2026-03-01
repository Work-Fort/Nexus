// SPDX-License-Identifier: MIT
package btrfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireBtrfsCLI skips the test if the btrfs binary is not in PATH.
func requireBtrfsCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("btrfs"); err != nil {
		t.Skip("btrfs CLI not in PATH")
	}
}

// btrfsCmd runs a btrfs CLI command and returns its combined output.
func btrfsCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("btrfs", args...).CombinedOutput()
	return string(out), err
}

func TestE2ECreateSubvolume(t *testing.T) {
	requireBtrfsCLI(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@e2e-create")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	// "btrfs subvolume show" requires CAP_SYS_ADMIN; use "btrfs property get"
	// which works unprivileged and implicitly validates the path is a subvolume
	// (it fails with "not compatible with property" on regular directories).
	out, err := btrfsCmd(t, "property", "get", path, "ro")
	if err != nil {
		t.Fatalf("btrfs property get failed (not a valid subvolume?): %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=") {
		t.Fatalf("expected ro property in output, got:\n%s", out)
	}
}

func TestE2ESetReadOnly(t *testing.T) {
	requireBtrfsCLI(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@e2e-readonly")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := SetReadOnly(path, true); err != nil {
		t.Fatalf("SetReadOnly(true): %v", err)
	}

	out, err := btrfsCmd(t, "property", "get", path, "ro")
	if err != nil {
		t.Fatalf("btrfs property get failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=true") {
		t.Fatalf("expected ro=true, got:\n%s", out)
	}

	if err := SetReadOnly(path, false); err != nil {
		t.Fatalf("SetReadOnly(false): %v", err)
	}

	out, err = btrfsCmd(t, "property", "get", path, "ro")
	if err != nil {
		t.Fatalf("btrfs property get failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=false") {
		t.Fatalf("expected ro=false, got:\n%s", out)
	}
}

func TestE2ECreateSnapshot(t *testing.T) {
	requireBtrfsCLI(t)
	dir := testDir(t)
	src := filepath.Join(dir, "@e2e-snap-src")
	dst := filepath.Join(dir, "@e2e-snap-dst")

	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	if err := CreateSnapshot(src, dst, false); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(dst) })

	// Verify the snapshot is a valid subvolume via CLI.
	// "btrfs property get" works without CAP_SYS_ADMIN and implicitly
	// validates the target is a btrfs subvolume.
	outDst, err := btrfsCmd(t, "property", "get", dst, "ro")
	if err != nil {
		t.Fatalf("btrfs property get (snapshot) failed: %v\n%s", err, outDst)
	}
	if !strings.Contains(outDst, "ro=false") {
		t.Fatalf("expected writable snapshot (ro=false), got:\n%s", outDst)
	}

	// If we have permission to run "btrfs subvolume show", verify the
	// parent UUID relationship between source and snapshot.
	outSrc, errSrc := btrfsCmd(t, "subvolume", "show", src)
	outSnap, errSnap := btrfsCmd(t, "subvolume", "show", dst)
	if errSrc == nil && errSnap == nil {
		srcUUID := extractField(outSrc, "UUID:")
		dstParentUUID := extractField(outSnap, "Parent UUID:")

		if srcUUID == "" {
			t.Fatal("could not extract source UUID")
		}
		if dstParentUUID == "" {
			t.Fatal("could not extract snapshot Parent UUID")
		}
		if srcUUID != dstParentUUID {
			t.Fatalf("snapshot Parent UUID %q does not match source UUID %q", dstParentUUID, srcUUID)
		}
	} else {
		t.Log("btrfs subvolume show requires CAP_SYS_ADMIN; skipping UUID verification")
	}
}

func TestE2EDeleteSubvolume(t *testing.T) {
	requireBtrfsCLI(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@e2e-delete")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}

	// Verify the subvolume exists via CLI before deletion.
	out, err := btrfsCmd(t, "property", "get", path, "ro")
	if err != nil {
		t.Fatalf("btrfs property get failed before delete: %v\n%s", err, out)
	}

	if err := DeleteSubvolume(path); err != nil {
		t.Fatalf("DeleteSubvolume: %v", err)
	}

	// After deletion, both btrfs CLI and stat should fail.
	_, err = btrfsCmd(t, "property", "get", path, "ro")
	if err == nil {
		t.Fatal("expected btrfs property get to fail after deletion")
	}
}

func TestE2ESnapshotPreservesContent(t *testing.T) {
	requireBtrfsCLI(t)
	dir := testDir(t)
	src := filepath.Join(dir, "@e2e-content-src")
	dst := filepath.Join(dir, "@e2e-content-dst")

	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	if err := os.WriteFile(filepath.Join(src, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("write file1: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(src, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "subdir", "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("write file2: %v", err)
	}

	if err := CreateSnapshot(src, dst, false); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(dst) })

	data1, err := os.ReadFile(filepath.Join(dst, "file1.txt"))
	if err != nil {
		t.Fatalf("read file1 in snapshot: %v", err)
	}
	if string(data1) != "content1" {
		t.Fatalf("expected 'content1', got %q", string(data1))
	}

	data2, err := os.ReadFile(filepath.Join(dst, "subdir", "file2.txt"))
	if err != nil {
		t.Fatalf("read file2 in snapshot: %v", err)
	}
	if string(data2) != "content2" {
		t.Fatalf("expected 'content2', got %q", string(data2))
	}

	if err := os.WriteFile(filepath.Join(dst, "file3.txt"), []byte("new"), 0644); err != nil {
		t.Fatalf("write to snapshot: %v", err)
	}

	if _, err := os.Stat(filepath.Join(src, "file3.txt")); !os.IsNotExist(err) {
		t.Fatal("CoW violation: file written to snapshot appeared in source")
	}
}

// extractField extracts the value for a field like "UUID:" from btrfs subvolume show output.
func extractField(output, field string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, field) {
			return strings.TrimSpace(strings.TrimPrefix(line, field))
		}
	}
	return ""
}
