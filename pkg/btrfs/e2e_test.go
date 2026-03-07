// SPDX-License-Identifier: MIT
package btrfs

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// requireSendReceiveCap skips the test if CAP_SYS_ADMIN and CAP_FOWNER are
// not available. When the test binary has file caps (via setcap), this raises
// them as ambient on the current OS thread so spawned subprocesses
// (btrfs send/receive) inherit them. Each test must call this because
// ambient caps are per-thread and Go may schedule goroutines on different threads.
func requireSendReceiveCap(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	for _, cap := range []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_FOWNER} {
		if err := raiseAmbientCap(cap); err != nil {
			t.Skipf("btrfs send/receive caps not available: %v", err)
		}
	}
}

func raiseAmbientCap(cap uintptr) error {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	word := cap / 32
	bit := uint32(1 << (cap % 32))

	if data[word].Permitted&bit == 0 {
		return fmt.Errorf("CAP %d not in permitted set", cap)
	}

	data[word].Inheritable |= bit
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	return unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, cap, 0, 0)
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

func TestE2ESendReceive(t *testing.T) {
	requireBtrfsCLI(t)
	requireSendReceiveCap(t)
	dir := testDir(t)

	// Create source subvolume with test data.
	src := filepath.Join(dir, "@e2e-send-src")
	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	if err := os.WriteFile(filepath.Join(src, "marker.txt"), []byte("e2e-send-receive"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(src, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "subdir", "nested.txt"), []byte("nested-data"), 0644); err != nil {
		t.Fatalf("write nested: %v", err)
	}

	// Create read-only snapshot (required for btrfs send).
	snap := filepath.Join(dir, "@e2e-send-snap")
	if err := CreateSnapshot(src, snap, true); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(snap) })

	// Send snapshot to buffer.
	var buf bytes.Buffer
	if err := Send(snap, &buf); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty send stream")
	}
	t.Logf("send stream size: %d bytes", buf.Len())

	// Receive into a new directory.
	recvDir := filepath.Join(dir, "recv")
	if err := os.MkdirAll(recvDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := Receive(recvDir, &buf); err != nil {
		t.Fatalf("Receive: %v", err)
	}

	// The received subvolume has the same name as the snapshot.
	received := filepath.Join(recvDir, "@e2e-send-snap")
	t.Cleanup(func() { DeleteSubvolume(received) })

	// Cross-verify via CLI: received subvolume should be read-only.
	out, err := btrfsCmd(t, "property", "get", received, "ro")
	if err != nil {
		t.Fatalf("btrfs property get on received: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=true") {
		t.Fatalf("expected received subvolume to be ro=true, got:\n%s", out)
	}

	// Verify data survived the round-trip.
	data, err := os.ReadFile(filepath.Join(received, "marker.txt"))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(data) != "e2e-send-receive" {
		t.Fatalf("marker = %q, want %q", string(data), "e2e-send-receive")
	}

	nested, err := os.ReadFile(filepath.Join(received, "subdir", "nested.txt"))
	if err != nil {
		t.Fatalf("read nested: %v", err)
	}
	if string(nested) != "nested-data" {
		t.Fatalf("nested = %q, want %q", string(nested), "nested-data")
	}
}

// TestE2ESendReceiveSetReadOnly verifies that SetReadOnly(false) works on
// received subvolumes via ioctl. The btrfs CLI rejects clearing read-only
// on received subvolumes (those with received_uuid set) without -f, but the
// BTRFS_IOC_SUBVOL_SETFLAGS ioctl does not have this restriction.
func TestE2ESendReceiveSetReadOnly(t *testing.T) {
	requireBtrfsCLI(t)
	requireSendReceiveCap(t)
	dir := testDir(t)

	src := filepath.Join(dir, "@e2e-rw-src")
	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	if err := os.WriteFile(filepath.Join(src, "data.txt"), []byte("rw-test"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	snap := filepath.Join(dir, "@e2e-rw-snap")
	if err := CreateSnapshot(src, snap, true); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(snap) })

	var buf bytes.Buffer
	if err := Send(snap, &buf); err != nil {
		t.Fatalf("Send: %v", err)
	}

	recvDir := filepath.Join(dir, "recv-rw")
	if err := os.MkdirAll(recvDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := Receive(recvDir, &buf); err != nil {
		t.Fatalf("Receive: %v", err)
	}

	received := filepath.Join(recvDir, "@e2e-rw-snap")
	t.Cleanup(func() { DeleteSubvolume(received) })

	// Cross-verify: received subvolume is read-only.
	out, err := btrfsCmd(t, "property", "get", received, "ro")
	if err != nil {
		t.Fatalf("btrfs property get: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=true") {
		t.Fatalf("expected ro=true, got:\n%s", out)
	}

	// Clear read-only via ioctl — must work on received subvolumes.
	if err := SetReadOnly(received, false); err != nil {
		t.Fatalf("SetReadOnly(false) on received subvolume: %v", err)
	}

	// Cross-verify via CLI: read-only should now be false.
	out, err = btrfsCmd(t, "property", "get", received, "ro")
	if err != nil {
		t.Fatalf("btrfs property get after clear: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=false") {
		t.Fatalf("expected ro=false after SetReadOnly(false), got:\n%s", out)
	}

	// Verify we can write to it.
	if err := os.WriteFile(filepath.Join(received, "new.txt"), []byte("writable"), 0644); err != nil {
		t.Fatalf("write to received subvolume: %v", err)
	}
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
