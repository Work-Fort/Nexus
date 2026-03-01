// SPDX-License-Identifier: GPL-2.0-only
package btrfs

import (
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

// CreateSubvolume creates a new btrfs subvolume at path.
// The parent directory must exist and reside on a btrfs filesystem.
func CreateSubvolume(path string) error {
	parent := filepath.Dir(path)
	name := filepath.Base(path)

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
func DeleteSubvolume(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return fmt.Errorf("btrfs: delete %s: %w", path, err)
	}

	ro, _ := GetReadOnly(path)
	if ro {
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
