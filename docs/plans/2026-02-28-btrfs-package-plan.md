# pkg/btrfs Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a pure Go btrfs ioctl package at `pkg/btrfs` with full unit and e2e test suites.

**Architecture:** Thin wrapper over 4 Linux btrfs ioctls + VFS deletion. Path-based public API mirroring libbtrfsutil. No CGo, no dependencies beyond `golang.org/x/sys/unix`.

**Tech Stack:** Go 1.25, `golang.org/x/sys/unix` for syscalls, `unsafe` for ioctl struct pointers.

---

### Task 1: Initialize Go module

**Files:**
- Create: `go.mod`
- Create: `go.sum`

**Step 1: Initialize the Go module**

Run:
```bash
cd /home/kazw/Work/WorkFort/nexus-go
go mod init github.com/Work-Fort/Nexus
```

**Step 2: Add the x/sys dependency**

Run:
```bash
go get golang.org/x/sys/unix
```

**Step 3: Create pkg/btrfs directory**

Run:
```bash
mkdir -p pkg/btrfs
```

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: initialize Go module github.com/Work-Fort/Nexus"
```

---

### Task 2: Write ioctl constants and struct

**Files:**
- Create: `pkg/btrfs/ioctl.go`

**Step 1: Write ioctl.go with constants, struct, and syscall helper**

```go
// SPDX-License-Identifier: GPL-2.0-only
package btrfs

import (
	"syscall"
	"unsafe"
)

// btrfs ioctl numbers from include/uapi/linux/btrfs.h.
const (
	iocSubvolCreateV2 = 0x50009418 // _IOW(0x94, 24, btrfs_ioctl_vol_args_v2)
	iocSnapCreateV2   = 0x50009417 // _IOW(0x94, 23, btrfs_ioctl_vol_args_v2)
	iocSubvolGetflags = 0x80089419 // _IOR(0x94, 25, uint64)
	iocSubvolSetflags = 0x4008941a // _IOW(0x94, 26, uint64)
)

// btrfs flags.
const (
	subvolRdonly   = uint64(1 << 1) // BTRFS_SUBVOL_RDONLY
	superMagic     = 0x9123683e     // BTRFS_SUPER_MAGIC (statfs f_type)
	firstFreeObjID = 256            // BTRFS_FIRST_FREE_OBJECTID (subvolume root inode)
)

// ioctlVolArgsV2 maps to struct btrfs_ioctl_vol_args_v2 (4096 bytes).
// All fields are naturally aligned — no packing issues in Go.
type ioctlVolArgsV2 struct {
	Fd      int64
	Transid uint64
	Flags   uint64
	Unused  [4]uint64
	Name    [4040]byte // BTRFS_SUBVOL_NAME_MAX + 1
}

// Compile-time size assertion: kernel requires exactly 4096 bytes.
var _ [4096]byte = [unsafe.Sizeof(ioctlVolArgsV2{})]byte{}

// ioctl performs a raw ioctl syscall.
func ioctl(fd uintptr, req uintptr, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}
```

**Step 2: Verify it compiles**

Run: `go build ./pkg/btrfs/`
Expected: no output, exit 0.

**Step 3: Commit**

```bash
git add pkg/btrfs/ioctl.go
git commit -m "feat(btrfs): add ioctl constants, struct, and syscall helper"
```

---

### Task 3: Write IsBtrfs and IsSubvolume

**Files:**
- Create: `pkg/btrfs/btrfs.go`

**Step 1: Write btrfs.go with errors, IsBtrfs, and IsSubvolume**

```go
// SPDX-License-Identifier: GPL-2.0-only
package btrfs

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

var (
	// ErrNotBtrfs is returned when an operation is attempted on a non-btrfs filesystem.
	ErrNotBtrfs = errors.New("btrfs: not a btrfs filesystem")

	// ErrNotSubvolume is returned when a path is not a btrfs subvolume.
	ErrNotSubvolume = errors.New("btrfs: not a subvolume")

	// ErrExists is returned when the destination already exists.
	ErrExists = errors.New("btrfs: already exists")
)

// IsBtrfs reports whether the given path resides on a btrfs filesystem.
func IsBtrfs(path string) (bool, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return false, fmt.Errorf("btrfs: statfs %s: %w", path, err)
	}
	return sfs.Type == superMagic, nil
}

// IsSubvolume reports whether the given path is a btrfs subvolume root.
// A btrfs subvolume root has inode number 256 (BTRFS_FIRST_FREE_OBJECTID)
// on a btrfs filesystem.
func IsSubvolume(path string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false, fmt.Errorf("btrfs: lstat %s: %w", path, err)
	}
	if st.Ino != firstFreeObjID {
		return false, nil
	}
	return IsBtrfs(path)
}
```

**Step 2: Write the first unit tests for IsBtrfs and IsSubvolume**

Create `pkg/btrfs/btrfs_test.go`:

```go
// SPDX-License-Identifier: GPL-2.0-only
package btrfs

import (
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
```

**Step 3: Run tests**

Run: `go test -v -race -run 'TestIs' ./pkg/btrfs/`
Expected: all pass (or skip on non-btrfs).

**Step 4: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): add IsBtrfs, IsSubvolume, and sentinel errors"
```

---

### Task 4: Implement CreateSubvolume

**Files:**
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Write the failing test**

Add to `btrfs_test.go`:

```go
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
	// /dev/shm is typically tmpfs
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
```

**Step 2: Run test to verify it fails**

Run: `go test -v -race -run 'TestCreateSubvolume$' ./pkg/btrfs/`
Expected: FAIL — `CreateSubvolume` not defined.

**Step 3: Implement CreateSubvolume**

Add to `btrfs.go`:

```go
import (
	"os"
	"path/filepath"
	"unsafe"
)

// CreateSubvolume creates a new btrfs subvolume at path.
// The parent directory must exist and reside on a btrfs filesystem.
func CreateSubvolume(path string) error {
	parent := filepath.Dir(path)
	name := filepath.Base(path)

	// Check parent is on btrfs.
	ok, err := IsBtrfs(parent)
	if err != nil {
		return fmt.Errorf("btrfs: create subvolume: %w", err)
	}
	if !ok {
		return fmt.Errorf("btrfs: create subvolume %s: %w", path, ErrNotBtrfs)
	}

	// Check destination does not already exist.
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("btrfs: create subvolume %s: %w", path, ErrExists)
	}

	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("btrfs: open parent %s: %w", parent, err)
	}
	defer unix.Close(fd)

	var args ioctlVolArgsV2
	copy(args.Name[:], name)

	if err := ioctl(uintptr(fd), iocSubvolCreateV2, uintptr(unsafe.Pointer(&args))); err != nil {
		return fmt.Errorf("btrfs: create subvolume %s: %w", path, err)
	}
	return nil
}
```

**Step 4: Run tests**

Run: `go test -v -race -run 'TestCreateSubvolume' ./pkg/btrfs/`
Expected: FAIL — `DeleteSubvolume` not defined (used in cleanup). Add a stub:

Add to `btrfs.go` temporarily:

```go
// DeleteSubvolume removes a btrfs subvolume at path using VFS operations.
func DeleteSubvolume(path string) error {
	// stub — will be implemented in Task 6
	return fmt.Errorf("btrfs: delete not implemented")
}
```

Run again: `go test -v -race -run 'TestCreateSubvolume' ./pkg/btrfs/`
Expected: `TestCreateSubvolume` passes, `TestCreateSubvolumeAlreadyExists` passes, `TestCreateSubvolumeNotBtrfs` passes.

**Step 5: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): implement CreateSubvolume with ioctl"
```

---

### Task 5: Implement GetReadOnly and SetReadOnly

**Files:**
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Write the failing tests**

Add to `btrfs_test.go`:

```go
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

	// Set read-only.
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

	// Clear read-only.
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
```

**Step 2: Run tests to verify they fail**

Run: `go test -v -race -run 'TestGetReadOnly|TestSetReadOnly' ./pkg/btrfs/`
Expected: FAIL — functions not defined.

**Step 3: Implement GetReadOnly and SetReadOnly**

Add to `btrfs.go`:

```go
// GetReadOnly reports whether the subvolume at path has the read-only flag set.
func GetReadOnly(path string) (bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return false, fmt.Errorf("btrfs: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	var flags uint64
	if err := ioctl(uintptr(fd), iocSubvolGetflags, uintptr(unsafe.Pointer(&flags))); err != nil {
		return false, fmt.Errorf("btrfs: get flags %s: %w", path, err)
	}
	return flags&subvolRdonly != 0, nil
}

// SetReadOnly sets or clears the read-only flag on the subvolume at path.
func SetReadOnly(path string, readOnly bool) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("btrfs: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	// Read current flags, then set/clear the read-only bit.
	var flags uint64
	if err := ioctl(uintptr(fd), iocSubvolGetflags, uintptr(unsafe.Pointer(&flags))); err != nil {
		return fmt.Errorf("btrfs: get flags %s: %w", path, err)
	}

	if readOnly {
		flags |= subvolRdonly
	} else {
		flags &^= subvolRdonly
	}

	if err := ioctl(uintptr(fd), iocSubvolSetflags, uintptr(unsafe.Pointer(&flags))); err != nil {
		return fmt.Errorf("btrfs: set flags %s: %w", path, err)
	}
	return nil
}
```

**Step 4: Run tests**

Run: `go test -v -race -run 'TestGetReadOnly|TestSetReadOnly' ./pkg/btrfs/`
Expected: PASS.

**Step 5: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): implement GetReadOnly and SetReadOnly"
```

---

### Task 6: Implement DeleteSubvolume

**Files:**
- Modify: `pkg/btrfs/btrfs.go` (replace stub)
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Write the failing tests**

Add to `btrfs_test.go`:

```go
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

	// Write a file, then set read-only.
	if err := os.WriteFile(filepath.Join(path, "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := SetReadOnly(path, true); err != nil {
		t.Fatalf("SetReadOnly: %v", err)
	}

	// Delete should still succeed (clears ro flag, removes contents, rmdir).
	if err := DeleteSubvolume(path); err != nil {
		t.Fatalf("DeleteSubvolume: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected subvolume to be gone, got err: %v", err)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test -v -race -run 'TestDelete' ./pkg/btrfs/`
Expected: FAIL — stub returns "not implemented".

**Step 3: Replace DeleteSubvolume stub with real implementation**

Replace the stub in `btrfs.go`:

```go
// DeleteSubvolume removes a btrfs subvolume at path using VFS operations.
// If the subvolume is read-only, the flag is cleared first.
// This avoids BTRFS_IOC_SNAP_DESTROY (which requires CAP_SYS_ADMIN).
// VFS rmdir on an empty subvolume works unprivileged since kernel 4.18.
func DeleteSubvolume(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("btrfs: delete %s: %w", path, err)
	}

	// Clear read-only flag if set (required to remove contents).
	ro, _ := GetReadOnly(path)
	if ro {
		if err := SetReadOnly(path, false); err != nil {
			return fmt.Errorf("btrfs: delete %s: cannot clear read-only: %w", path, err)
		}
	}

	// Remove all contents inside the subvolume.
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("btrfs: delete %s: read dir: %w", path, err)
	}
	for _, entry := range entries {
		p := filepath.Join(path, entry.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("btrfs: delete %s: remove %s: %w", path, p, err)
		}
	}

	// rmdir the now-empty subvolume directory.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("btrfs: delete %s: rmdir: %w", path, err)
	}
	return nil
}
```

**Step 4: Run tests**

Run: `go test -v -race -run 'TestDelete' ./pkg/btrfs/`
Expected: PASS.

**Step 5: Run ALL tests to make sure nothing regressed**

Run: `go test -v -race ./pkg/btrfs/`
Expected: all pass (cleanups now work since DeleteSubvolume is real).

**Step 6: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): implement DeleteSubvolume via VFS"
```

---

### Task 7: Implement CreateSnapshot

**Files:**
- Modify: `pkg/btrfs/btrfs.go`
- Modify: `pkg/btrfs/btrfs_test.go`

**Step 1: Write the failing tests**

Add to `btrfs_test.go`:

```go
func TestCreateSnapshot(t *testing.T) {
	dir := testDir(t)
	src := filepath.Join(dir, "@test-snap-src")
	dst := filepath.Join(dir, "@test-snap-dst")

	if err := CreateSubvolume(src); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(src) })

	// Write a file into source.
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := CreateSnapshot(src, dst, false); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(dst) })

	// Verify snapshot is a subvolume.
	ok, err := IsSubvolume(dst)
	if err != nil {
		t.Fatalf("IsSubvolume: %v", err)
	}
	if !ok {
		t.Fatal("expected snapshot to be a subvolume")
	}

	// Verify snapshot is writable by default.
	ro, err := GetReadOnly(dst)
	if err != nil {
		t.Fatalf("GetReadOnly: %v", err)
	}
	if ro {
		t.Fatal("expected writable snapshot")
	}

	// Verify file was CoW-copied.
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
```

**Step 2: Run tests to verify they fail**

Run: `go test -v -race -run 'TestCreateSnapshot' ./pkg/btrfs/`
Expected: FAIL — `CreateSnapshot` not defined.

**Step 3: Implement CreateSnapshot**

Add to `btrfs.go`:

```go
// CreateSnapshot creates a CoW snapshot of the source subvolume at dest.
// If readOnly is true, the snapshot is created with the read-only flag set.
func CreateSnapshot(source, dest string, readOnly bool) error {
	parent := filepath.Dir(dest)
	name := filepath.Base(dest)

	// Verify source is a subvolume.
	ok, err := IsSubvolume(source)
	if err != nil {
		return fmt.Errorf("btrfs: snapshot: %w", err)
	}
	if !ok {
		return fmt.Errorf("btrfs: snapshot source %s: %w", source, ErrNotSubvolume)
	}

	// Check destination does not already exist.
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("btrfs: snapshot dest %s: %w", dest, ErrExists)
	}

	// Open source subvolume.
	srcFd, err := unix.Open(source, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("btrfs: open source %s: %w", source, err)
	}
	defer unix.Close(srcFd)

	// Open destination parent directory.
	dstFd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("btrfs: open dest parent %s: %w", parent, err)
	}
	defer unix.Close(dstFd)

	var args ioctlVolArgsV2
	args.Fd = int64(srcFd)
	if readOnly {
		args.Flags = subvolRdonly
	}
	copy(args.Name[:], name)

	if err := ioctl(uintptr(dstFd), iocSnapCreateV2, uintptr(unsafe.Pointer(&args))); err != nil {
		return fmt.Errorf("btrfs: snapshot %s -> %s: %w", source, dest, err)
	}
	return nil
}
```

**Step 4: Run tests**

Run: `go test -v -race -run 'TestCreateSnapshot' ./pkg/btrfs/`
Expected: PASS.

**Step 5: Run ALL tests**

Run: `go test -v -race ./pkg/btrfs/`
Expected: all pass.

**Step 6: Commit**

```bash
git add pkg/btrfs/btrfs.go pkg/btrfs/btrfs_test.go
git commit -m "feat(btrfs): implement CreateSnapshot with ioctl"
```

---

### Task 8: Write E2E tests

**Files:**
- Create: `pkg/btrfs/e2e_test.go`

These tests use the `btrfs` CLI as an independent oracle to verify that the ioctl-based
Go code produces valid btrfs subvolumes.

**Step 1: Write e2e_test.go**

```go
// SPDX-License-Identifier: GPL-2.0-only
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

	// Verify with btrfs CLI.
	out, err := btrfsCmd(t, "subvolume", "show", path)
	if err != nil {
		t.Fatalf("btrfs subvolume show failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "@e2e-create") {
		t.Fatalf("expected subvolume name in output, got:\n%s", out)
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

	// Set read-only via Go.
	if err := SetReadOnly(path, true); err != nil {
		t.Fatalf("SetReadOnly(true): %v", err)
	}

	// Verify with btrfs CLI.
	out, err := btrfsCmd(t, "property", "get", path, "ro")
	if err != nil {
		t.Fatalf("btrfs property get failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ro=true") {
		t.Fatalf("expected ro=true, got:\n%s", out)
	}

	// Clear read-only via Go.
	if err := SetReadOnly(path, false); err != nil {
		t.Fatalf("SetReadOnly(false): %v", err)
	}

	// Verify with btrfs CLI.
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

	// Verify snapshot exists via CLI.
	outDst, err := btrfsCmd(t, "subvolume", "show", dst)
	if err != nil {
		t.Fatalf("btrfs subvolume show (snapshot) failed: %v\n%s", err, outDst)
	}

	// Verify parent UUID of snapshot matches UUID of source.
	outSrc, err := btrfsCmd(t, "subvolume", "show", src)
	if err != nil {
		t.Fatalf("btrfs subvolume show (source) failed: %v\n%s", err, outSrc)
	}

	srcUUID := extractField(outSrc, "UUID:")
	dstParentUUID := extractField(outDst, "Parent UUID:")

	if srcUUID == "" {
		t.Fatal("could not extract source UUID")
	}
	if dstParentUUID == "" {
		t.Fatal("could not extract snapshot Parent UUID")
	}
	if srcUUID != dstParentUUID {
		t.Fatalf("snapshot Parent UUID %q does not match source UUID %q", dstParentUUID, srcUUID)
	}
}

func TestE2EDeleteSubvolume(t *testing.T) {
	requireBtrfsCLI(t)
	dir := testDir(t)
	path := filepath.Join(dir, "@e2e-delete")

	if err := CreateSubvolume(path); err != nil {
		t.Fatalf("CreateSubvolume: %v", err)
	}

	if err := DeleteSubvolume(path); err != nil {
		t.Fatalf("DeleteSubvolume: %v", err)
	}

	// Verify with btrfs CLI — should fail since subvolume is gone.
	_, err := btrfsCmd(t, "subvolume", "show", path)
	if err == nil {
		t.Fatal("expected btrfs subvolume show to fail after deletion")
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

	// Write files into source subvolume.
	if err := os.WriteFile(filepath.Join(src, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("write file1: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(src, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "subdir", "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("write file2: %v", err)
	}

	// Snapshot.
	if err := CreateSnapshot(src, dst, false); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() { DeleteSubvolume(dst) })

	// Verify files exist in snapshot.
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

	// Write to snapshot should succeed (writable snapshot).
	if err := os.WriteFile(filepath.Join(dst, "file3.txt"), []byte("new"), 0644); err != nil {
		t.Fatalf("write to snapshot: %v", err)
	}

	// Source should NOT have file3.
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
```

**Step 2: Run the e2e tests**

Run: `go test -v -race -run 'TestE2E' ./pkg/btrfs/`
Expected: all pass (on btrfs with btrfs CLI available).

**Step 3: Run ALL tests together**

Run: `go test -v -race ./pkg/btrfs/`
Expected: all pass.

**Step 4: Commit**

```bash
git add pkg/btrfs/e2e_test.go
git commit -m "test(btrfs): add e2e tests using btrfs CLI as oracle"
```

---

### Task 9: Final verification and cleanup

**Step 1: Run the full test suite with race detection**

Run: `go test -v -race -count=1 ./pkg/btrfs/`
Expected: all tests pass.

**Step 2: Run go vet**

Run: `go vet ./pkg/btrfs/`
Expected: no issues.

**Step 3: Check formatting**

Run: `gofmt -l pkg/btrfs/`
Expected: no output (all files formatted).

**Step 4: Verify static build works**

Run: `CGO_ENABLED=0 go build ./pkg/btrfs/`
Expected: exit 0, no CGo linkage.

**Step 5: Verify the public API surface is correct**

Run: `go doc ./pkg/btrfs/`
Expected: shows all 7 public functions + 3 sentinel errors.
