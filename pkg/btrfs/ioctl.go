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
// All fields are naturally aligned -- no packing issues in Go.
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
