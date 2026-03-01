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

// DeleteSubvolume removes a btrfs subvolume at path using VFS operations.
func DeleteSubvolume(path string) error {
	// stub -- will be replaced in Task 6
	return fmt.Errorf("btrfs: delete not implemented")
}
