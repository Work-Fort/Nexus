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
