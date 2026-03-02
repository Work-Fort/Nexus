// SPDX-License-Identifier: MIT
package btrfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
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

// requireQuotaCap skips the test if the process lacks CAP_SYS_ADMIN,
// which is required for all btrfs quota operations.
func requireQuotaCap(t *testing.T) {
	t.Helper()
	requireBtrfs(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@quota-cap-check")
	if err := CreateSubvolume(path); err != nil {
		t.Skipf("cannot create subvolume for cap check: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })
	if err := EnableQuota(path); err != nil {
		t.Skipf("CAP_SYS_ADMIN not available (quota ops will skip): %v", err)
	}
}

func TestGetFSID(t *testing.T) {
	dir := testDir(t)

	fsid, err := GetFSID(dir)
	if err != nil {
		t.Fatalf("GetFSID: %v", err)
	}
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
	if len(fsid) != 36 {
		t.Fatalf("expected 36-char UUID, got %d: %q", len(fsid), fsid)
	}
	if fsid[8] != '-' || fsid[13] != '-' || fsid[18] != '-' || fsid[23] != '-' {
		t.Fatalf("bad UUID format: %q", fsid)
	}
	t.Logf("FSID: %s", fsid)
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

func TestDeleteSubvolume(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "@test-delete")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}

	if err := DeleteSubvolume(path); err != nil {
		t.Fatalf("DeleteSubvolume: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected subvolume to be gone, got err: %v", err)
	}
}

func TestDeleteReadOnlySubvolume(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "@test-delete-ro")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}

	if err := os.WriteFile(filepath.Join(path, "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := SetReadOnly(path, true); err != nil {
		t.Fatalf("SetReadOnly: %v", err)
	}

	if err := DeleteSubvolume(path); err != nil {
		t.Fatalf("DeleteSubvolume: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected subvolume to be gone, got err: %v", err)
	}
}

func TestCreateSnapshot(t *testing.T) {
	dir := testDir(t)
	src := filepath.Join(dir, "@test-snap-src")
	dst := filepath.Join(dir, "@test-snap-dst")

	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := CreateSnapshot(src, dst, false); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(dst) })

	ok, err := IsSubvolume(dst)
	if err != nil {
		t.Fatalf("IsSubvolume: %v", err)
	}
	if !ok {
		t.Fatal("expected snapshot to be a subvolume")
	}

	ro, err := GetReadOnly(dst)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if ro {
		t.Fatal("expected writable snapshot")
	}

	data, err := os.ReadFile(filepath.Join(dst, "hello.txt"))
	if err != nil {
		t.Fatalf("read snapshot file: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(data))
	}
}

func TestCreateSnapshotReadOnly(t *testing.T) {
	dir := testDir(t)
	src := filepath.Join(dir, "@test-snap-ro-src")
	dst := filepath.Join(dir, "@test-snap-ro-dst")

	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	if err := CreateSnapshot(src, dst, true); err != nil {
		t.Fatalf("CreateSnapshot(readOnly=true): %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(dst) })

	ro, err := GetReadOnly(dst)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if !ro {
		t.Fatal("expected read-only snapshot")
	}
}

func TestCreateSnapshotAlreadyExists(t *testing.T) {
	dir := testDir(t)
	src := filepath.Join(dir, "@test-snap-exists-src")
	dst := filepath.Join(dir, "@test-snap-exists-dst")

	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	if err := CreateSubvolume(dst); err != nil {
		t.Fatalf("CreateSubvolume dst: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(dst) })

	err := CreateSnapshot(src, dst, false)
	if err == nil {
		t.Fatal("expected error for existing destination")
	}
	if !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got: %v", err)
	}
}

func TestGetQuotaUsageUnprivileged(t *testing.T) {
	dir := testDir(t)
	sub := filepath.Join(dir, "sysfs-test")
	if err := CreateSubvolume(sub); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(sub) })

	usage, err := GetQuotaUsage(sub)
	if err != nil {
		if errors.Is(err, ErrQuotaNotEnabled) {
			t.Skip("quotas not enabled on test filesystem")
		}
		t.Fatalf("GetQuotaUsage: %v", err)
	}

	// No limit set yet.
	if usage.MaxReferenced != 0 {
		t.Errorf("expected MaxReferenced=0 (unlimited), got %d", usage.MaxReferenced)
	}
	t.Logf("usage: referenced=%d exclusive=%d max_ref=%d max_excl=%d",
		usage.Referenced, usage.Exclusive, usage.MaxReferenced, usage.MaxExclusive)
}

func TestEnableQuota(t *testing.T) {
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@test-quota-enable")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}
}

func TestEnableQuotaIdempotent(t *testing.T) {
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@test-quota-idempotent")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota first call: %v", err)
	}
	// Second call should succeed (idempotent).
	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota second call (should be idempotent): %v", err)
	}
}

func TestSetQuota(t *testing.T) {
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@test-set-quota")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}

	// Set a 10 MiB limit.
	if err := SetQuota(path, 10*1024*1024); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
}

func TestSetQuotaClear(t *testing.T) {
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@test-clear-quota")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}

	// Set then clear.
	if err := SetQuota(path, 10*1024*1024); err != nil {
		t.Fatalf("SetQuota(10M): %v", err)
	}
	if err := SetQuota(path, 0); err != nil {
		t.Fatalf("SetQuota(0) to clear: %v", err)
	}
}

func TestGetQuotaUsage(t *testing.T) {
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@test-get-usage")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}

	// Write some data so Referenced > 0.
	data := make([]byte, 64*1024) // 64 KiB
	if err := os.WriteFile(filepath.Join(path, "data.bin"), data, 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	// Force a sync so quota accounting picks up the write.
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

	if usage.Referenced == 0 {
		t.Fatal("expected Referenced > 0 after writing data")
	}
	if usage.MaxReferenced != 0 {
		t.Fatalf("expected MaxReferenced=0 (unlimited), got %d", usage.MaxReferenced)
	}
}

func TestGetQuotaUsageWithLimit(t *testing.T) {
	requireQuotaCap(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@test-usage-limit")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(path) })

	if err := EnableQuota(path); err != nil {
		t.Fatalf("EnableQuota: %v", err)
	}

	limit := uint64(50 * 1024 * 1024) // 50 MiB
	if err := SetQuota(path, limit); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}

	usage, err := GetQuotaUsage(path)
	if err != nil {
		t.Fatalf("GetQuotaUsage: %v", err)
	}

	if usage.MaxReferenced != limit {
		t.Fatalf("expected MaxReferenced=%d, got %d", limit, usage.MaxReferenced)
	}
}
