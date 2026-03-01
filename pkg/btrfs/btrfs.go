// SPDX-License-Identifier: MIT

// Package btrfs provides pure-Go wrappers for Linux btrfs kernel ioctls.
// Subvolume and snapshot management works without CGo or CAP_SYS_ADMIN.
// Quota operations (EnableQuota, SetQuota, GetQuotaUsage) require CAP_SYS_ADMIN.
package btrfs

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

// treeSearchOne searches the quota tree for a single item with the given
// subvolume ID and key type. Returns the item data or nil if not found.
func treeSearchOne(fd uintptr, subvolID uint64, keyType uint32) ([]byte, error) {
	var args ioctlSearchArgs
	args.Key.TreeID = quotaTreeObjectid
	args.Key.MinObjectid = 0
	args.Key.MaxObjectid = 0
	args.Key.MinOffset = subvolID
	args.Key.MaxOffset = subvolID
	args.Key.MinType = keyType
	args.Key.MaxType = keyType
	args.Key.MaxTransid = ^uint64(0)
	args.Key.NrItems = 1

	if err := ioctl(fd, iocTreeSearch, uintptr(unsafe.Pointer(&args))); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, ErrQuotaNotEnabled
		}
		return nil, fmt.Errorf("btrfs: tree search: %w", err)
	}

	if args.Key.NrItems == 0 {
		return nil, nil
	}

	buf := args.Buf[:]
	if len(buf) < 32 {
		return nil, nil
	}

	hdrLen := binary.LittleEndian.Uint32(buf[28:32])
	if len(buf) < int(32+hdrLen) {
		return nil, nil
	}
	return buf[32 : 32+hdrLen], nil
}

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

	// The btrfs tree search uses composite key comparison — it iterates
	// from (MinObjectid, MinType, MinOffset) to (MaxObjectid, MaxType,
	// MaxOffset) in key order. Items between type 242 and 244 at the same
	// offset can include info items for higher-numbered subvolumes and
	// relation items (type 243), so we do two targeted searches.

	// Search 1: qgroup info item (type 242).
	info, err := treeSearchOne(uintptr(fd), subvolID, qgroupInfoKey)
	if err != nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: get quota usage %s: %w", path, err)
	}
	if info == nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: get quota usage %s: %w", path, ErrQuotaNotEnabled)
	}
	if len(info) >= 40 {
		r := bytes.NewReader(info)
		var qi struct {
			Generation uint64
			Rfer       uint64
			RferCmpr   uint64
			Excl       uint64
			ExclCmpr   uint64
		}
		if err := binary.Read(r, binary.LittleEndian, &qi); err == nil {
			usage.Referenced = qi.Rfer
			usage.Exclusive = qi.Excl
		}
	}

	// Search 2: qgroup limit item (type 244). Optional — may not exist.
	lim, err := treeSearchOne(uintptr(fd), subvolID, qgroupLimitKey)
	if err != nil {
		return QuotaUsage{}, fmt.Errorf("btrfs: get quota usage %s: %w", path, err)
	}
	if lim != nil && len(lim) >= 40 {
		r := bytes.NewReader(lim)
		var ql struct {
			Flags   uint64
			MaxRfer uint64
			MaxExcl uint64
			RsvRfer uint64
			RsvExcl uint64
		}
		if err := binary.Read(r, binary.LittleEndian, &ql); err == nil {
			// ^uint64(0) means "no limit".
			if ql.MaxRfer != ^uint64(0) {
				usage.MaxReferenced = ql.MaxRfer
			}
			if ql.MaxExcl != ^uint64(0) {
				usage.MaxExclusive = ql.MaxExcl
			}
		}
	}

	return usage, nil
}
