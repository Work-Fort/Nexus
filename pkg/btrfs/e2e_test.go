// SPDX-License-Identifier: MIT
package btrfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

func TestE2EEnableQuota(t *testing.T) {
	requireBtrfsCLI(t)
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@e2e-quota-enable")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}

	// Verify via CLI: "btrfs qgroup show" should work (it fails if quotas not enabled).
	// The btrfs CLI itself needs CAP_SYS_ADMIN for qgroup show; skip if unavailable.
	out, err := btrfsCmd(t, "qgroup", "show", path)
	if err != nil {
		if strings.Contains(out, "Operation not permitted") {
			t.Skip("btrfs CLI lacks CAP_SYS_ADMIN for qgroup show")
		}
		t.Fatalf("btrfs qgroup show failed (quotas not enabled?): %v\n%s", err, out)
	}
}

func TestE2ESetQuota(t *testing.T) {
	requireBtrfsCLI(t)
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@e2e-quota-set")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}

	limit := uint64(100 * 1024 * 1024) // 100 MiB
	if err := SetQuota(path, limit); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}

	// Verify via CLI.
	// The btrfs CLI itself needs CAP_SYS_ADMIN for qgroup show; skip if unavailable.
	out, err := btrfsCmd(t, "qgroup", "show", "--raw", path)
	if err != nil {
		if strings.Contains(out, "Operation not permitted") {
			t.Skip("btrfs CLI lacks CAP_SYS_ADMIN for qgroup show")
		}
		t.Fatalf("btrfs qgroup show failed: %v\n%s", err, out)
	}
	// The output should contain "104857600" (100 MiB in bytes).
	if !strings.Contains(out, "104857600") {
		t.Fatalf("expected 104857600 in qgroup output, got:\n%s", out)
	}
}

func TestE2EGetQuotaUsageAfterWrite(t *testing.T) {
	requireBtrfsCLI(t)
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@e2e-quota-usage")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}

	// Write data.
	data := make([]byte, 128*1024) // 128 KiB
	if err := os.WriteFile(filepath.Join(path, "payload.bin"), data, 0644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	// Sync to flush accounting.
	syncFd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("open for sync: %v", err)
	}
	unix.Syncfs(syncFd)
	unix.Close(syncFd)

	usage, err := GetQuotaUsage(path)
	if err != nil {
		t.Fatalf("GetQuotaUsage: %v", err)
	}

	// Verify Referenced > 0. The exact size depends on btrfs compression
	// and allocation strategy — zero-filled data may be stored compactly.
	if usage.Referenced == 0 {
		t.Fatal("expected Referenced > 0 after writing data")
	}
}
