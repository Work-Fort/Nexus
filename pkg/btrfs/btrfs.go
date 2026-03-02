// SPDX-License-Identifier: MIT

// Package btrfs provides pure-Go wrappers for Linux btrfs kernel ioctls.
// Subvolume and snapshot management works without CGo or CAP_SYS_ADMIN.
// Quota write operations (EnableQuota, SetQuota) require CAP_SYS_ADMIN.
// GetQuotaUsage reads from sysfs and works without capabilities.
package btrfs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	// ErrNotBtrfs is returned when an operation is attempted on a non-btrfs filesystem.
	ErrNotBtrfs = errors.New("btrfs: not a btrfs filesystem")

	// ErrNotSubvolume is returned when a path is not a btrfs subvolume.
	ErrNotSubvolume = errors.New("btrfs: not a subvolume")

	// ErrExists is returned when the destination already exists.
	ErrExists = errors.New("btrfs: already exists")

	// ErrNameTooLong is returned when a subvolume or snapshot name exceeds the kernel limit.
	ErrNameTooLong = errors.New("btrfs: name too long")

	// ErrQuotaNotEnabled is returned when quotas are not enabled on the filesystem.
	ErrQuotaNotEnabled = errors.New("btrfs: quotas not enabled")
)

// subvolNameMax is the maximum length of a subvolume name (BTRFS_SUBVOL_NAME_MAX).
const subvolNameMax = len(ioctlVolArgsV2{}.Name) - 1

// QuotaUsage contains disk usage and quota limits for a btrfs subvolume.
type QuotaUsage struct {
	Referenced    uint64 // total bytes referenced by this subvolume
	Exclusive     uint64 // bytes exclusive to this subvolume (not shared via CoW)
	MaxReferenced uint64 // quota limit (0 = unlimited)
	MaxExclusive  uint64 // exclusive limit (0 = unlimited)
}

// IsBtrfs reports whether the given path resides on a btrfs filesystem.
func IsBtrfs(path string) (bool, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(path, &sfs); err != nil {
		return false, fmt.Errorf("btrfs: statfs %s: %w", path, err)
	}
	return sfs.Type == superMagic, nil
}

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

// CreateSubvolume creates a new btrfs subvolume at path.
// The parent directory must exist and reside on a btrfs filesystem.
func CreateSubvolume(path string) error {
	parent := filepath.Dir(path)
	name := filepath.Base(path)

	if len(name) > subvolNameMax {
		return fmt.Errorf("btrfs: create subvolume %s: %w", path, ErrNameTooLong)
	}

	ok, err := IsBtrfs(parent)
	if err != nil {
		return fmt.Errorf("btrfs: create subvolume: %w", err)
	}
	if !ok {
		return fmt.Errorf("btrfs: create subvolume %s: %w", path, ErrNotBtrfs)
	}

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

// DeleteSubvolume removes a btrfs subvolume at path using VFS operations.
// If the subvolume is read-only, the flag is cleared first.
// This avoids BTRFS_IOC_SNAP_DESTROY (which requires CAP_SYS_ADMIN).
// VFS rmdir on an empty subvolume works unprivileged since kernel 4.18.
//
// Nested subvolumes are not supported — the caller must delete inner
// subvolumes before deleting an outer one.
func DeleteSubvolume(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("btrfs: delete %s: %w", path, err)
	}

	ro, err := GetReadOnly(path)
	if err == nil && ro {
		if err := SetReadOnly(path, false); err != nil {
			return fmt.Errorf("btrfs: delete %s: cannot clear read-only: %w", path, err)
		}
	}

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

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("btrfs: delete %s: rmdir: %w", path, err)
	}
	return nil
}

// CreateSnapshot creates a CoW snapshot of the source subvolume at dest.
// If readOnly is true, the snapshot is created with the read-only flag set.
func CreateSnapshot(source, dest string, readOnly bool) error {
	parent := filepath.Dir(dest)
	name := filepath.Base(dest)

	if len(name) > subvolNameMax {
		return fmt.Errorf("btrfs: snapshot dest %s: %w", dest, ErrNameTooLong)
	}

	ok, err := IsSubvolume(source)
	if err != nil {
		return fmt.Errorf("btrfs: snapshot: %w", err)
	}
	if !ok {
		return fmt.Errorf("btrfs: snapshot source %s: %w", source, ErrNotSubvolume)
	}

	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("btrfs: snapshot dest %s: %w", dest, ErrExists)
	}

	srcFd, err := unix.Open(source, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("btrfs: open source %s: %w", source, err)
	}
	defer unix.Close(srcFd)

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

const sysfsBase = "/sys/fs/btrfs"

// readSysfsUint64 reads a uint64 value from a sysfs file.
func readSysfsUint64(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// GetQuotaUsage returns disk usage and quota limits for the subvolume at path.
// Reads from sysfs (/sys/fs/btrfs/<fsid>/qgroups/) which is world-readable
// and does not require CAP_SYS_ADMIN.
// Quotas must be enabled first with EnableQuota.
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
