# pkg/btrfs Quota Extension Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend `pkg/btrfs` with btrfs qgroup quota support (EnableQuota, SetQuota, GetQuotaUsage) for per-agent disk limits.

**Architecture:** Pure Go ioctl wrappers using `unix.Syscall`, same pattern as existing subvolume ops. All quota ioctls require `CAP_SYS_ADMIN`. GetQuotaUsage uses `BTRFS_IOC_INO_LOOKUP` to resolve subvolume ID, then `BTRFS_IOC_TREE_SEARCH` to read quota info and limit items from the quota tree.

**Tech Stack:** Go, `golang.org/x/sys/unix`, `encoding/binary` (for LE struct parsing), `unsafe` (ioctl structs)

**Design doc:** `docs/plans/2026-03-01-btrfs-quota-design.md`

---

### Task 1: Add quota ioctl constants and structs

**Files:**
- Modify: `pkg/btrfs/ioctl.go`

**Step 1: Add the new ioctl constants**

Add after the existing ioctl constant block (line 16):

```go
// Quota ioctl numbers. All require CAP_SYS_ADMIN.
const (
	iocQuotaCtl   = 0xC0109428 // _IOWR(0x94, 40, btrfs_ioctl_quota_ctl_args)
	iocQgroupLimit = 0x8030942B // _IOR(0x94, 43, btrfs_ioctl_qgroup_limit_args)
	iocTreeSearch  = 0xC1009411 // _IOWR(0x94, 17, btrfs_ioctl_search_args)
	iocInoLookup   = 0xD0009412 // _IOWR(0x94, 18, btrfs_ioctl_ino_lookup_args)
)
```

**Step 2: Add quota-related flag constants**

Add after the existing flags block (line 23):

```go
// Quota constants.
const (
	quotaCtlEnable     = uint64(1)       // BTRFS_QUOTA_CTL_ENABLE
	qgroupLimitMaxRfer = uint64(1 << 0)  // BTRFS_QGROUP_LIMIT_MAX_RFER
	quotaTreeObjectid  = uint64(8)       // BTRFS_QUOTA_TREE_OBJECTID
	qgroupInfoKey      = uint32(242)     // BTRFS_QGROUP_INFO_KEY
	qgroupLimitKey     = uint32(244)     // BTRFS_QGROUP_LIMIT_KEY
)
```

**Step 3: Add ioctl structs**

Add after `ioctlVolArgsV2` (after line 33):

```go
// ioctlQuotaCtlArgs maps to struct btrfs_ioctl_quota_ctl_args (16 bytes).
type ioctlQuotaCtlArgs struct {
	Cmd    uint64
	Status uint64
}

// qgroupLimit maps to struct btrfs_qgroup_limit (40 bytes).
type qgroupLimit struct {
	Flags   uint64
	MaxRfer uint64
	MaxExcl uint64
	RsvRfer uint64
	RsvExcl uint64
}

// ioctlQgroupLimitArgs maps to struct btrfs_ioctl_qgroup_limit_args (48 bytes).
type ioctlQgroupLimitArgs struct {
	Qgroupid uint64
	Lim      qgroupLimit
}

// searchKey maps to struct btrfs_ioctl_search_key (104 bytes).
type searchKey struct {
	TreeID      uint64
	MinObjectid uint64
	MaxObjectid uint64
	MinOffset   uint64
	MaxOffset   uint64
	MinTransid  uint64
	MaxTransid  uint64
	MinType     uint32
	MaxType     uint32
	NrItems     uint32
	Unused      uint32
	Unused1     uint64
	Unused2     uint64
	Unused3     uint64
	Unused4     uint64
}

// ioctlSearchArgs maps to struct btrfs_ioctl_search_args (4096 bytes).
type ioctlSearchArgs struct {
	Key searchKey
	Buf [3992]byte
}

// searchHeader maps to struct btrfs_ioctl_search_header (32 bytes).
type searchHeader struct {
	Transid  uint64
	Objectid uint64
	Offset   uint64
	Type     uint32
	Len      uint32
}

// ioctlInoLookupArgs maps to struct btrfs_ioctl_ino_lookup_args (4096 bytes).
type ioctlInoLookupArgs struct {
	Treeid   uint64
	Objectid uint64
	Name     [4080]byte
}
```

**Step 4: Add compile-time size assertions**

Add after the existing assertion (after line 36):

```go
var _ [16]byte = [unsafe.Sizeof(ioctlQuotaCtlArgs{})]byte{}
var _ [48]byte = [unsafe.Sizeof(ioctlQgroupLimitArgs{})]byte{}
var _ [4096]byte = [unsafe.Sizeof(ioctlSearchArgs{})]byte{}
var _ [4096]byte = [unsafe.Sizeof(ioctlInoLookupArgs{})]byte{}
```

**Step 5: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go build ./pkg/btrfs/`
Expected: No errors.

**Step 6: Commit**

```bash
git add pkg/btrfs/ioctl.go
git commit -m "feat(btrfs): add quota ioctl constants and structs"
```

---

### Task 2: Add QuotaUsage type, ErrQuotaNotEnabled, and test helpers

**Files:**
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Add ErrQuotaNotEnabled and QuotaUsage to btrfs.go**

Add `ErrQuotaNotEnabled` to the existing var block (after line 28, after `ErrNameTooLong`):

```go
	// ErrQuotaNotEnabled is returned when quotas are not enabled on the filesystem.
	ErrQuotaNotEnabled = errors.New("btrfs: quotas not enabled")
```

Add the `QuotaUsage` type after the `subvolNameMax` constant (after line 32):

```go
// QuotaUsage contains disk usage and quota limits for a btrfs subvolume.
type QuotaUsage struct {
	Referenced    uint64 // total bytes referenced by this subvolume
	Exclusive     uint64 // bytes exclusive to this subvolume (not shared via CoW)
	MaxReferenced uint64 // quota limit (0 = unlimited)
	MaxExclusive  uint64 // exclusive limit (0 = unlimited)
}
```

**Step 2: Add requireQuotaCap helper to btrfs_test.go**

Add after the `testDir` function (after line 40):

```go
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
```

Note: This won't compile yet because `EnableQuota` doesn't exist. That's fine — it compiles when Task 3 is done.

**Step 3: Verify btrfs.go compiles (QuotaUsage + error only)**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go build ./pkg/btrfs/`
Expected: No errors (the test file with `requireQuotaCap` won't be checked by `go build`).

**Step 4: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): add QuotaUsage type and ErrQuotaNotEnabled"
```

---

### Task 3: Implement EnableQuota with tests

**Files:**
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Write the failing tests**

Add to `btrfs_test.go`:

```go
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
```

**Step 2: Implement EnableQuota**

Add to `btrfs.go`, after `CreateSnapshot`:

```go
// EnableQuota enables btrfs qgroup quotas on the filesystem containing path.
// This is idempotent — calling it on a filesystem that already has quotas
// enabled returns nil.
// Requires CAP_SYS_ADMIN.
func EnableQuota(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("btrfs: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	var args ioctlQuotaCtlArgs
	args.Cmd = quotaCtlEnable

	if err := ioctl(uintptr(fd), iocQuotaCtl, uintptr(unsafe.Pointer(&args))); err != nil {
		// EEXIST means quotas are already enabled — idempotent.
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return fmt.Errorf("btrfs: enable quota %s: %w", path, err)
	}
	return nil
}
```

Add `"errors"` is already imported. Add `"golang.org/x/sys/unix"` is already imported. Good.

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go build ./pkg/btrfs/`
Expected: No errors.

**Step 4: Run tests (they will skip without CAP_SYS_ADMIN)**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go test ./pkg/btrfs/ -run TestEnableQuota -v`
Expected: Tests skip with "CAP_SYS_ADMIN not available".

**Step 5: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): implement EnableQuota with idempotent EEXIST handling"
```

---

### Task 4: Implement SetQuota with tests

**Files:**
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Write the failing tests**

Add to `btrfs_test.go`:

```go
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
```

**Step 2: Implement SetQuota**

Add to `btrfs.go`, after `EnableQuota`:

```go
// SetQuota sets the maximum referenced bytes (disk quota) for the subvolume at path.
// Pass maxBytes=0 to clear the limit (unlimited).
// Quotas must be enabled first with EnableQuota.
// Uses qgroupid=0 which auto-detects the subvolume's qgroup from the fd.
// Requires CAP_SYS_ADMIN.
func SetQuota(path string, maxBytes uint64) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("btrfs: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	var args ioctlQgroupLimitArgs
	// Qgroupid=0 means auto-detect from fd.
	args.Qgroupid = 0
	args.Lim.Flags = qgroupLimitMaxRfer

	if maxBytes == 0 {
		// Clear limit: set to max uint64.
		args.Lim.MaxRfer = ^uint64(0)
	} else {
		args.Lim.MaxRfer = maxBytes
	}

	if err := ioctl(uintptr(fd), iocQgroupLimit, uintptr(unsafe.Pointer(&args))); err != nil {
		return fmt.Errorf("btrfs: set quota %s: %w", path, err)
	}
	return nil
}
```

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go build ./pkg/btrfs/`
Expected: No errors.

**Step 4: Run tests (will skip without CAP_SYS_ADMIN)**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go test ./pkg/btrfs/ -run TestSetQuota -v`
Expected: Tests skip.

**Step 5: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): implement SetQuota with auto-detect qgroupid"
```

---

### Task 5: Implement GetQuotaUsage with tests

This is the most complex task. It uses two ioctls:
1. `BTRFS_IOC_INO_LOOKUP` to get the subvolume ID from a path
2. `BTRFS_IOC_TREE_SEARCH` to search the quota tree for info (type 242) and limit (type 244) items

**Files:**
- Modify: `pkg/btrfs/btrfs.go` — add `"encoding/binary"` import
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Write the failing tests**

Add to `btrfs_test.go`:

```go
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
```

**Step 2: Add `"encoding/binary"` and `"golang.org/x/sys/unix"` imports**

`btrfs.go` already imports `"golang.org/x/sys/unix"`. Add `"encoding/binary"` and `"bytes"` to the import block:

```go
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)
```

Also add `"golang.org/x/sys/unix"` to `btrfs_test.go` imports (for `unix.Syncfs`/`unix.Open`/`unix.Close`):

```go
import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)
```

**Step 3: Implement getSubvolumeID helper**

Add to `btrfs.go`, before `GetQuotaUsage`:

```go
// getSubvolumeID returns the btrfs subvolume ID for the given path
// using BTRFS_IOC_INO_LOOKUP.
func getSubvolumeID(path string) (uint64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return 0, fmt.Errorf("btrfs: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	var args ioctlInoLookupArgs
	args.Objectid = firstFreeObjID

	if err := ioctl(uintptr(fd), iocInoLookup, uintptr(unsafe.Pointer(&args))); err != nil {
		return 0, fmt.Errorf("btrfs: ino lookup %s: %w", path, err)
	}
	return args.Treeid, nil
}
```

**Step 4: Implement GetQuotaUsage**

Add to `btrfs.go`, after `getSubvolumeID`:

```go
// GetQuotaUsage returns disk usage and quota limits for the subvolume at path.
// Quotas must be enabled first with EnableQuota.
// Returns ErrQuotaNotEnabled if quotas are not enabled on the filesystem.
// Requires CAP_SYS_ADMIN.
func GetQuotaUsage(path string) (QuotaUsage, error) {
	subvolID, err := getSubvolumeID(path)
	if err != nil {
		return QuotaUsage{}, err
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	var usage QuotaUsage
	var foundInfo bool

	// Search for qgroup info item (type 242) and limit item (type 244).
	var args ioctlSearchArgs
	args.Key.TreeID = quotaTreeObjectid
	args.Key.MinObjectid = 0
	args.Key.MaxObjectid = subvolID
	args.Key.MinOffset = subvolID
	args.Key.MaxOffset = subvolID
	args.Key.MinType = qgroupInfoKey
	args.Key.MaxType = qgroupLimitKey
	args.Key.MaxTransid = ^uint64(0)
	args.Key.NrItems = 16

	if err := ioctl(uintptr(fd), iocTreeSearch, uintptr(unsafe.Pointer(&args))); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return QuotaUsage{}, fmt.Errorf("btrfs: get quota usage %s: %w", path, ErrQuotaNotEnabled)
		}
		return QuotaUsage{}, fmt.Errorf("btrfs: tree search %s: %w", path, err)
	}

	if args.Key.NrItems == 0 {
		return QuotaUsage{}, fmt.Errorf("btrfs: get quota usage %s: %w", path, ErrQuotaNotEnabled)
	}

	buf := args.Buf[:]
	for i := uint32(0); i < args.Key.NrItems; i++ {
		if len(buf) < 32 {
			break
		}

		var hdr searchHeader
		hdr.Transid = binary.LittleEndian.Uint64(buf[0:8])
		hdr.Objectid = binary.LittleEndian.Uint64(buf[8:16])
		hdr.Offset = binary.LittleEndian.Uint64(buf[16:24])
		hdr.Type = binary.LittleEndian.Uint32(buf[24:28])
		hdr.Len = binary.LittleEndian.Uint32(buf[28:32])

		itemData := buf[32 : 32+hdr.Len]

		switch hdr.Type {
		case qgroupInfoKey:
			if hdr.Len >= 40 {
				r := bytes.NewReader(itemData)
				var info struct {
					Generation uint64
					Rfer       uint64
					RferCmpr   uint64
					Excl       uint64
					ExclCmpr   uint64
				}
				if err := binary.Read(r, binary.LittleEndian, &info); err == nil {
					usage.Referenced = info.Rfer
					usage.Exclusive = info.Excl
					foundInfo = true
				}
			}
		case qgroupLimitKey:
			if hdr.Len >= 40 {
				r := bytes.NewReader(itemData)
				var lim struct {
					Flags   uint64
					MaxRfer uint64
					MaxExcl uint64
					RsvRfer uint64
					RsvExcl uint64
				}
				if err := binary.Read(r, binary.LittleEndian, &lim); err == nil {
					// MaxRfer of ^uint64(0) means "no limit".
					if lim.MaxRfer != ^uint64(0) {
						usage.MaxReferenced = lim.MaxRfer
					}
					if lim.MaxExcl != ^uint64(0) {
						usage.MaxExclusive = lim.MaxExcl
					}
				}
			}
		}

		buf = buf[32+hdr.Len:]
	}

	if !foundInfo {
		return QuotaUsage{}, fmt.Errorf("btrfs: get quota usage %s: %w", path, ErrQuotaNotEnabled)
	}

	return usage, nil
}
```

**Step 5: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go build ./pkg/btrfs/`
Expected: No errors.

**Step 6: Run tests (will skip without CAP_SYS_ADMIN)**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go test ./pkg/btrfs/ -run TestGetQuotaUsage -v`
Expected: Tests skip.

**Step 7: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): implement GetQuotaUsage with tree search"
```

---

### Task 6: Add E2E quota tests

**Files:**
- Modify: `pkg/btrfs/e2e_test.go`

**Step 1: Write E2E tests**

Add to `e2e_test.go`:

```go
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
	out, err := btrfsCmd(t, "qgroup", "show", path)
	if err != nil {
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
	out, err := btrfsCmd(t, "qgroup", "show", "--raw", path)
	if err != nil {
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

	// Verify Referenced is at least 128 KiB (metadata adds some overhead).
	if usage.Referenced < 128*1024 {
		t.Fatalf("expected Referenced >= %d, got %d", 128*1024, usage.Referenced)
	}
}
```

**Step 2: Add missing imports to e2e_test.go**

Add `"golang.org/x/sys/unix"` to the import block in `e2e_test.go`:

```go
import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)
```

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go test -c -o /dev/null ./pkg/btrfs/`
Expected: No errors.

**Step 4: Commit**

```bash
git add pkg/btrfs/e2e_test.go
git commit -m "test(btrfs): add e2e quota tests using btrfs CLI as oracle"
```

---

### Task 7: PAUSE — Set CAP_SYS_ADMIN on test binary

**This task requires user action.**

All quota operations require `CAP_SYS_ADMIN`. The test binary must have this capability set before quota tests can run.

**Step 1: Build the test binary**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go test -c -o pkg/btrfs/btrfs.test ./pkg/btrfs/`
Expected: Binary created at `pkg/btrfs/btrfs.test`.

**Step 2: PAUSE — Ask the user to set the capability**

Tell the user:

> The test binary is built at `pkg/btrfs/btrfs.test`. Please run:
>
> ```bash
> sudo setcap cap_sys_admin=+eip pkg/btrfs/btrfs.test
> ```
>
> Then confirm so I can continue.

**Wait for user confirmation before proceeding.**

---

### Task 8: Run full test suite and verify

**Step 1: Run quota unit tests**

Run: `cd /home/kazw/Work/WorkFort/nexus-go/pkg/btrfs && ./btrfs.test -test.v -test.run 'TestEnableQuota|TestSetQuota|TestGetQuotaUsage'`
Expected: All 5 quota tests PASS (no skips).

**Step 2: Run quota E2E tests**

Run: `cd /home/kazw/Work/WorkFort/nexus-go/pkg/btrfs && ./btrfs.test -test.v -test.run 'TestE2E.*Quota'`
Expected: All 3 E2E quota tests PASS.

**Step 3: Run full test suite (existing + new)**

Run: `cd /home/kazw/Work/WorkFort/nexus-go/pkg/btrfs && ./btrfs.test -test.v`
Expected: All tests PASS (existing 19 + new 8 = 27 total, or existing skip gracefully).

**Step 4: Clean up test binary**

Run: `rm pkg/btrfs/btrfs.test`

**Step 5: Commit if any fixes were needed**

If tests revealed bugs that required fixes, commit those fixes:

```bash
git add pkg/btrfs/
git commit -m "fix(btrfs): fix issues found during quota test run"
```

---

### Task 9: Final commit and verify

**Step 1: Run go vet**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && go vet ./pkg/btrfs/`
Expected: No issues.

**Step 2: Verify clean working tree**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && git status`
Expected: Clean working tree (nothing to commit).

**Step 3: Review commit log**

Run: `cd /home/kazw/Work/WorkFort/nexus-go && git log --oneline -10`
Expected: See the new quota commits on top of the previous btrfs work.
