# Btrfs Quota Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enforce btrfs quota limits on drive volumes so each drive's disk usage is capped at its configured size, while keeping the main daemon fully unprivileged.

**Architecture:** Three-layer approach: (1) unprivileged sysfs-based quota reading in `pkg/btrfs` via `/sys/fs/btrfs/<fsid>/qgroups/`, (2) a `nexus-quota` privileged helper binary with CAP_SYS_ADMIN for writing quota limits (follows nexus-netns pattern), (3) `BtrfsStorage.CreateVolume` calls the helper to enforce the size limit. No separate setup step — the helper calls `EnableQuota` (idempotent) before `SetQuota`, so quotas are auto-enabled on first drive creation.

**Tech Stack:** Go, btrfs ioctls (`BTRFS_IOC_FS_INFO`), Linux sysfs, `setcap` capabilities, `os/exec`

---

### Task 1: Add BTRFS_IOC_FS_INFO ioctl support

Adds `GetFSID()` — returns the btrfs filesystem UUID for a path. This is needed to construct sysfs paths for unprivileged quota reading. Does not require CAP_SYS_ADMIN.

**Files:**
- Modify: `pkg/btrfs/ioctl.go`
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Add ioctl struct and constant to `pkg/btrfs/ioctl.go`**

Add to the non-quota ioctl constants block (after `iocSubvolSetflags`):

```go
iocFsInfo = 0x8110941F // _IOR(0x94, 31, btrfs_ioctl_fs_info_args)
```

Add struct after `ioctlVolArgsV2`:

```go
// ioctlFsInfoArgs maps to struct btrfs_ioctl_fs_info_args (272 bytes).
// Only the FSID field is used; the rest is included for correct sizing.
type ioctlFsInfoArgs struct {
	MaxID          uint64
	NumDevices     uint64
	FSID           [16]byte
	NodeSize       uint32
	SectorSize     uint32
	CloneAlignment uint32
	CsumType       uint16
	CsumSize       uint16
	Flags          uint64
	Generation     uint64
	MetadataUUID   [16]byte
	Reserved       [192]byte
}
```

Add compile-time size assertion alongside the existing ones:

```go
var _ [272]byte = [unsafe.Sizeof(ioctlFsInfoArgs{})]byte{}
```

**Step 2: Add `GetFSID` function and `formatFSID` helper to `pkg/btrfs/btrfs.go`**

Add `"encoding/hex"` to imports.

```go
// GetFSID returns the filesystem UUID for the btrfs filesystem containing path.
// Does not require CAP_SYS_ADMIN.
func GetFSID(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return "", fmt.Errorf("btrfs: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	var args ioctlFsInfoArgs
	if err := ioctl(uintptr(fd), iocFsInfo, uintptr(unsafe.Pointer(&args))); err != nil {
		return "", fmt.Errorf("btrfs: fs info %s: %w", path, err)
	}

	return formatFSID(args.FSID), nil
}

// formatFSID formats a 16-byte btrfs FSID as a standard UUID string.
func formatFSID(fsid [16]byte) string {
	h := hex.EncodeToString(fsid[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
```

**Step 3: Add test in `pkg/btrfs/btrfs_test.go`**

```go
func TestGetFSID(t *testing.T) {
	requireBtrfs(t)

	fsid, err := btrfs.GetFSID(t.TempDir())
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
```

**Step 4: Run test**

Run: `go test -v -run TestGetFSID ./pkg/btrfs/`
Expected: PASS (on btrfs), SKIP (on non-btrfs)

**Step 5: Commit**

```bash
git add pkg/btrfs/ioctl.go pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): add GetFSID via BTRFS_IOC_FS_INFO (no CAP_SYS_ADMIN)"
```

---

### Task 2: Rewrite GetQuotaUsage to use sysfs

Replace the CAP_SYS_ADMIN-requiring tree search ioctl implementation with sysfs reads from `/sys/fs/btrfs/<fsid>/qgroups/0_<subvolid>/`. The public API (`GetQuotaUsage(path) → QuotaUsage`) stays identical. Old tree search code becomes unused — remove it.

**Files:**
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/ioctl.go` (cleanup dead code)
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Add sysfs helpers to `pkg/btrfs/btrfs.go`**

Add `"strconv"` and `"strings"` to imports.

```go
const sysfsBase = "/sys/fs/btrfs"

// readSysfsUint64 reads a uint64 value from a sysfs file.
func readSysfsUint64(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}
```

**Step 2: Replace `GetQuotaUsage` body**

```go
// GetQuotaUsage returns disk usage and quota limits for the subvolume at path.
// Reads from sysfs (/sys/fs/btrfs/<fsid>/qgroups/) which is world-readable
// and does not require CAP_SYS_ADMIN.
// Returns ErrQuotaNotEnabled if quotas are not enabled or the qgroup doesn't exist.
func GetQuotaUsage(path string) (QuotaUsage, error) {
	fsid, err := GetFSID(path)
	if err != nil {
		return QuotaUsage{}, err
	}

	subvolID, err := getSubvolumeID(path)
	if err != nil {
		return QuotaUsage{}, err
	}

	qgroupDir := filepath.Join(sysfsBase, fsid, "qgroups", fmt.Sprintf("0_%d", subvolID))

	if _, err := os.Stat(qgroupDir); err != nil {
		if os.IsNotExist(err) {
			return QuotaUsage{}, ErrQuotaNotEnabled
		}
		return QuotaUsage{}, fmt.Errorf("btrfs: stat qgroup dir: %w", err)
	}

	var usage QuotaUsage

	usage.Referenced, err = readSysfsUint64(filepath.Join(qgroupDir, "referenced"))
	if err != nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: read referenced: %w", err)
	}

	usage.Exclusive, err = readSysfsUint64(filepath.Join(qgroupDir, "exclusive"))
	if err != nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: read exclusive: %w", err)
	}

	usage.MaxReferenced, err = readSysfsUint64(filepath.Join(qgroupDir, "max_referenced"))
	if err != nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: read max_referenced: %w", err)
	}

	usage.MaxExclusive, err = readSysfsUint64(filepath.Join(qgroupDir, "max_exclusive"))
	if err != nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: read max_exclusive: %w", err)
	}

	return usage, nil
}
```

**Step 3: Update package doc comment**

Change line 5 of `btrfs.go` from:
```
// Quota operations (EnableQuota, SetQuota, GetQuotaUsage) require CAP_SYS_ADMIN.
```
To:
```
// Quota write operations (EnableQuota, SetQuota) require CAP_SYS_ADMIN.
// GetQuotaUsage reads from sysfs and works without capabilities.
```

**Step 4: Remove dead tree search code from `btrfs.go`**

Remove these functions (no longer called by anything):
- `treeSearchOne` function (entire function)

Remove the unused `"bytes"` and `"encoding/binary"` imports if they become unused. (`encoding/binary` may still be needed — check.)

**Step 5: Remove dead tree search types from `ioctl.go`**

Remove these (only used by the deleted `treeSearchOne`):
- `iocTreeSearch` constant
- `quotaTreeObjectid`, `qgroupInfoKey`, `qgroupLimitKey` constants
- `searchKey` struct
- `ioctlSearchArgs` struct
- `searchHeader` struct
- Compile-time assertion: `var _ [4096]byte = [unsafe.Sizeof(ioctlSearchArgs{})]byte{}`

Keep `iocInoLookup` and `ioctlInoLookupArgs` (still used by `getSubvolumeID`).

**Step 6: Add unprivileged sysfs test to `btrfs_test.go`**

This test verifies `GetQuotaUsage` works without CAP_SYS_ADMIN. It only requires quotas to be enabled on the test filesystem (they are on this system's /home).

```go
func TestGetQuotaUsageUnprivileged(t *testing.T) {
	requireBtrfs(t)

	dir := t.TempDir()
	sub := filepath.Join(dir, "sysfs-test")
	if err := btrfs.CreateSubvolume(sub); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { btrfs.DeleteSubvolume(sub) })

	usage, err := btrfs.GetQuotaUsage(sub)
	if err != nil {
		if errors.Is(err, btrfs.ErrQuotaNotEnabled) {
			t.Skip("quotas not enabled on test filesystem")
		}
		t.Fatalf("GetQuotaUsage: %v", err)
	}

	// New subvolumes have small non-zero Referenced (inode metadata).
	if usage.Referenced == 0 {
		t.Error("expected non-zero Referenced for new subvolume")
	}
	// No limit set yet.
	if usage.MaxReferenced != 0 {
		t.Errorf("expected MaxReferenced=0 (unlimited), got %d", usage.MaxReferenced)
	}
	t.Logf("usage: referenced=%d exclusive=%d max_ref=%d max_excl=%d",
		usage.Referenced, usage.Exclusive, usage.MaxReferenced, usage.MaxExclusive)
}
```

**Step 7: Run all btrfs tests**

Run: `go test -v ./pkg/btrfs/`
Expected: All tests pass. `TestGetQuotaUsageUnprivileged` passes without CAP_SYS_ADMIN. Existing quota tests that call `EnableQuota`/`SetQuota` still require `requireQuotaCap` and skip without caps.

**Step 8: Verify the whole project builds**

Run: `go build ./...`
Expected: Clean build, no unused import errors.

**Step 9: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/ioctl.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): rewrite GetQuotaUsage to use sysfs (no CAP_SYS_ADMIN needed)

Replaces BTRFS_IOC_TREE_SEARCH with reads from
/sys/fs/btrfs/<fsid>/qgroups/0_<subvolid>/ which is world-readable.
Removes unused tree search ioctl infrastructure."
```

---

### Task 3: Create nexus-quota helper binary

Minimal privileged binary following the `nexus-netns` pattern. Gets `cap_sys_admin+ep` via setcap. Two commands: `set-limit` (auto-enables quotas idempotently before setting the limit) and `clear-limit`.

**Files:**
- Create: `cmd/nexus-quota/main.go`
- Modify: `mise.toml`
- Modify: `scripts/dev-setcap-loop.sh`
- Modify: `internal/config/config.go`

**Step 1: Create `cmd/nexus-quota/main.go`**

```go
// SPDX-License-Identifier: Apache-2.0

// nexus-quota is a minimal helper that sets btrfs quota limits on subvolumes.
// It requires CAP_SYS_ADMIN (via setcap) so that the main nexusd daemon can
// remain unprivileged.
//
// Usage:
//
//	nexus-quota set-limit <path> <bytes>   — set max referenced bytes
//	nexus-quota clear-limit <path>         — remove quota limit
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: nexus-quota <set-limit|clear-limit> <path> [bytes]\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "set-limit":
		setLimit()
	case "clear-limit":
		clearLimit()
	default:
		fmt.Fprintf(os.Stderr, "nexus-quota: unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}

func setLimit() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: nexus-quota set-limit <path> <bytes>\n")
		os.Exit(1)
	}
	path := os.Args[2]

	maxBytes, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: invalid bytes %q: %v\n", os.Args[3], err)
		os.Exit(1)
	}
	if maxBytes == 0 {
		fmt.Fprintf(os.Stderr, "nexus-quota: bytes must be > 0 (use clear-limit to remove)\n")
		os.Exit(1)
	}

	ok, err := btrfs.IsSubvolume(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "nexus-quota: %s is not a btrfs subvolume\n", path)
		os.Exit(1)
	}

	// Enable quotas idempotently — on first call this turns on qgroup
	// accounting for the filesystem; subsequent calls are a no-op (EEXIST).
	// This eliminates the need for a separate "sudo nexusd setup btrfs-quotas" step.
	if err := btrfs.EnableQuota(path); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: enable quota: %v\n", err)
		os.Exit(1)
	}

	if err := btrfs.SetQuota(path, maxBytes); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: %v\n", err)
		os.Exit(1)
	}
}

func clearLimit() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: nexus-quota clear-limit <path>\n")
		os.Exit(1)
	}
	path := os.Args[2]

	if err := btrfs.SetQuota(path, 0); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: %v\n", err)
		os.Exit(1)
	}
}
```

**Step 2: Add build task to `mise.toml`**

Add to `[tasks.build]` run array:
```
"go build -o build/nexus-quota ./cmd/nexus-quota/",
```

Add to `[tasks."build:release"]` run array:
```
"CGO_ENABLED=0 go build -ldflags='-s -w' -o build/nexus-quota ./cmd/nexus-quota/",
```

Update `[tasks.clean]`:
```
run = "rm -f build/nexusd build/nexus-netns build/nexus-cni-exec build/nexus-quota"
```

**Step 3: Add setcap entry to `scripts/dev-setcap-loop.sh`**

Add variable after `CNI_EXEC`:
```bash
QUOTA_HELPER="$BUILD_DIR/nexus-quota"
```

Add to the echo section:
```bash
echo "  $QUOTA_HELPER   → CAP_SYS_ADMIN"
```

Add to the while loop body (after the CNI_EXEC block):
```bash
    if [ -f "$QUOTA_HELPER" ]; then
        setcap cap_sys_admin+ep "$QUOTA_HELPER" 2>/dev/null || true
    fi
```

**Step 4: Add config default to `internal/config/config.go`**

Add constant:
```go
DefaultQuotaHelper = "nexus-quota"
```

Add to `InitViper()`:
```go
viper.SetDefault("quota-helper", DefaultQuotaHelper)
```

**Step 5: Build and verify**

Run: `mise run build`
Expected: Four binaries in `build/`: `nexusd`, `nexus-netns`, `nexus-cni-exec`, `nexus-quota`.

Run: `./build/nexus-quota`
Expected: prints usage and exits 1.

Run: `./build/nexus-quota set-limit /tmp 100`
Expected: `nexus-quota: /tmp is not a btrfs subvolume` (validates the subvolume check)

**Step 6: Commit**

```bash
git add cmd/nexus-quota/main.go mise.toml scripts/dev-setcap-loop.sh internal/config/config.go
git commit -m "feat: add nexus-quota helper binary for privileged quota operations"
```

---

### Task 4: Wire quota helper into BtrfsStorage

BtrfsStorage currently ignores the `sizeBytes` parameter in `CreateVolume`. Add a `quotaHelper` field — when set, `CreateVolume` calls the helper to enforce the quota after creating the subvolume. If the helper fails, the subvolume is rolled back (deleted).

**Files:**
- Modify: `internal/infra/storage/btrfs.go`
- Create: `internal/infra/storage/btrfs_test.go`
- Modify: `cmd/daemon.go`

**Step 1: Write failing tests in `internal/infra/storage/btrfs_test.go`**

```go
package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

func requireBtrfs(t *testing.T) {
	t.Helper()
	ok, _ := btrfs.IsBtrfs(t.TempDir())
	if !ok {
		t.Skip("not on btrfs")
	}
}

func TestBtrfsStorageQuotaHelperCalled(t *testing.T) {
	requireBtrfs(t)

	dir := filepath.Join(t.TempDir(), "drives")

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
	requireBtrfs(t)

	dir := filepath.Join(t.TempDir(), "drives")

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
	requireBtrfs(t)

	dir := filepath.Join(t.TempDir(), "drives")

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
	requireBtrfs(t)

	dir := filepath.Join(t.TempDir(), "drives")

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
```

**Step 2: Run tests to verify they fail**

Run: `go test -v -run TestBtrfsStorage ./internal/infra/storage/`
Expected: FAIL — `NewBtrfsWithQuota` undefined.

**Step 3: Implement quota support in `internal/infra/storage/btrfs.go`**

Replace the entire file:

```go
// SPDX-License-Identifier: Apache-2.0

// Package storage implements domain.Storage for persistent data volumes.
package storage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

// BtrfsStorage implements domain.Storage using btrfs subvolumes.
type BtrfsStorage struct {
	basePath    string
	quotaHelper string // path to nexus-quota binary; empty = no enforcement
}

// NewBtrfs creates a BtrfsStorage without quota enforcement.
func NewBtrfs(basePath string) (*BtrfsStorage, error) {
	return NewBtrfsWithQuota(basePath, "")
}

// NewBtrfsWithQuota creates a BtrfsStorage with optional quota enforcement.
// If quotaHelper is non-empty, CreateVolume calls it to set quota limits.
func NewBtrfsWithQuota(basePath, quotaHelper string) (*BtrfsStorage, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("create drives dir %s: %w", basePath, err)
	}
	ok, err := btrfs.IsBtrfs(basePath)
	if err != nil {
		return nil, fmt.Errorf("check btrfs %s: %w", basePath, err)
	}
	if !ok {
		return nil, fmt.Errorf("drives dir %s is not on a btrfs filesystem", basePath)
	}
	return &BtrfsStorage{basePath: basePath, quotaHelper: quotaHelper}, nil
}

func (s *BtrfsStorage) CreateVolume(ctx context.Context, name string, sizeBytes uint64) (string, error) {
	path := filepath.Join(s.basePath, name)
	if err := btrfs.CreateSubvolume(path); err != nil {
		return "", fmt.Errorf("create volume %s: %w", name, err)
	}

	if s.quotaHelper != "" && sizeBytes > 0 {
		out, err := exec.CommandContext(ctx, s.quotaHelper, "set-limit", path,
			strconv.FormatUint(sizeBytes, 10)).CombinedOutput()
		if err != nil {
			btrfs.DeleteSubvolume(path) //nolint:errcheck // rollback best-effort
			return "", fmt.Errorf("set quota on %s: %w: %s", name, err, out)
		}
	}

	return path, nil
}

func (s *BtrfsStorage) DeleteVolume(_ context.Context, name string) error {
	path := filepath.Join(s.basePath, name)
	if err := btrfs.DeleteSubvolume(path); err != nil {
		return fmt.Errorf("delete volume %s: %w", name, err)
	}
	return nil
}

func (s *BtrfsStorage) VolumePath(name string) string {
	return filepath.Join(s.basePath, name)
}
```

**Step 4: Run tests**

Run: `go test -v -run TestBtrfsStorage ./internal/infra/storage/`
Expected: All 4 tests PASS (on btrfs), SKIP (on non-btrfs).

**Step 5: Wire daemon to pass quota helper**

In `cmd/daemon.go`, update the btrfs storage construction (around line 86):

Change:
```go
bs, err := storage.NewBtrfs(drivesDir)
```
To:
```go
quotaHelper := viper.GetString("quota-helper")
if quotaHelper != "" {
    if resolved, err := exec.LookPath(quotaHelper); err != nil {
        log.Warn("quota helper not found, quota enforcement disabled", "helper", quotaHelper)
        quotaHelper = ""
    } else {
        quotaHelper = resolved
    }
}
bs, err := storage.NewBtrfsWithQuota(drivesDir, quotaHelper)
```

Add `"os/exec"` to the imports.

Add the CLI flag (in the flags block around line 157):
```go
cmd.Flags().String("quota-helper", config.DefaultQuotaHelper, "Path to nexus-quota helper binary (empty to disable)")
```

Add `"quota-helper"` to the viper bind loop (the `[]string{...}` list around line 159).

**Step 6: Run all tests**

Run: `go test ./...`
Expected: All tests pass (existing + new).

Run: `go build ./...`
Expected: Clean build.

**Step 7: Commit**

```bash
git add internal/infra/storage/btrfs.go internal/infra/storage/btrfs_test.go cmd/daemon.go
git commit -m "feat: wire quota enforcement into BtrfsStorage via helper binary

CreateVolume now calls nexus-quota set-limit after creating the
subvolume when a quota helper is configured. Rolls back on failure.
Daemon auto-discovers the helper on PATH at startup."
```

---

### Task 5: Manual integration smoke test

Verify the full end-to-end flow with the live daemon.

**Step 1: Build and set caps**

Run: `mise run build`
Run: `sudo setcap cap_sys_admin+ep build/nexus-quota` (or run dev-setcap-loop.sh)

**Step 2: Test helper directly**

```bash
# Create a test subvolume (quotas don't need to be pre-enabled —
# the helper calls EnableQuota idempotently)
btrfs subvolume create /tmp/test-quota-sub

# Set a 500M quota (this also enables quotas on the filesystem if needed)
./build/nexus-quota set-limit /tmp/test-quota-sub 524288000

# Verify via sysfs:
cat /sys/fs/btrfs/$(cat /sys/fs/btrfs/*/metadata_uuid)/qgroups/0_*/max_referenced

# Clear the quota
./build/nexus-quota clear-limit /tmp/test-quota-sub

# Cleanup
btrfs subvolume delete /tmp/test-quota-sub
```

**Step 3: Test via daemon API**

```bash
# Start the daemon (assumes nexus-quota is on PATH via mise run)
mise run run

# Create a drive with a size limit
curl -s -X POST http://127.0.0.1:9600/v1/drives \
  -d '{"name":"quota-test","size":"500M","mount_path":"/data"}'

# Check the drive was created
curl -s http://127.0.0.1:9600/v1/drives | jq .

# Verify quota is enforced via sysfs
# (find subvolume ID from the drive path, check max_referenced)
```

**Step 4: Verify graceful degradation**

```bash
# Remove quota helper from PATH and restart daemon
# The daemon should log a warning and continue without quota enforcement
NEXUS_QUOTA_HELPER="" mise run run
```

---

## Files Summary

| File | Change |
|------|--------|
| `pkg/btrfs/ioctl.go` | Add `iocFsInfo` + `ioctlFsInfoArgs`; remove tree search types |
| `pkg/btrfs/btrfs.go` | Add `GetFSID`, `formatFSID`, `readSysfsUint64`; rewrite `GetQuotaUsage` to sysfs; remove `treeSearchOne` |
| `pkg/btrfs/btrfs_test.go` | Add `TestGetFSID`, `TestGetQuotaUsageUnprivileged` |
| `cmd/nexus-quota/main.go` | **NEW** — privileged helper (set-limit, clear-limit) |
| `mise.toml` | Add nexus-quota to build/release/clean tasks |
| `scripts/dev-setcap-loop.sh` | Add nexus-quota setcap entry |
| `internal/config/config.go` | Add `DefaultQuotaHelper`, viper default |
| `internal/infra/storage/btrfs.go` | Add `quotaHelper`, `NewBtrfsWithQuota`, exec in `CreateVolume` |
| `internal/infra/storage/btrfs_test.go` | **NEW** — 4 tests (helper called, rollback, no helper, zero size) |
| `cmd/daemon.go` | `LookPath` for quota helper, pass to `NewBtrfsWithQuota`, add flag |

## Assumptions

- The `nexus-quota` binary has `cap_sys_admin+ep` set via `sudo setcap`
- No separate quota setup step needed — `set-limit` calls `EnableQuota` idempotently (one extra ioctl per call, no-op after first)
- Quota enforcement is optional — the daemon works without it and logs a warning
- btrfs automatically removes the qgroup when a subvolume is deleted (no explicit clear needed)
- sysfs qgroup entries are created synchronously when subvolumes are created on a quota-enabled filesystem
