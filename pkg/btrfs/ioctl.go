// SPDX-License-Identifier: MIT
package btrfs

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// btrfs ioctl numbers from include/uapi/linux/btrfs.h.
const (
	iocSubvolCreateV2 = 0x50009418 // _IOW(0x94, 24, btrfs_ioctl_vol_args_v2)
	iocSnapCreateV2   = 0x50009417 // _IOW(0x94, 23, btrfs_ioctl_vol_args_v2)
	iocSubvolGetflags = 0x80089419 // _IOR(0x94, 25, uint64)
	iocSubvolSetflags = 0x4008941a // _IOW(0x94, 26, uint64)
	iocFsInfo         = 0x8400941F // _IOR(0x94, 31, btrfs_ioctl_fs_info_args)
)

// Quota ioctl numbers. All require CAP_SYS_ADMIN.
const (
	iocQuotaCtl    = 0xC0109428 // _IOWR(0x94, 40, btrfs_ioctl_quota_ctl_args)
	iocQgroupLimit = 0x8030942B // _IOR(0x94, 43, btrfs_ioctl_qgroup_limit_args)
	iocInoLookup   = 0xD0009412 // _IOWR(0x94, 18, btrfs_ioctl_ino_lookup_args)
)

// btrfs flags.
const (
	subvolRdonly   = uint64(1 << 1) // BTRFS_SUBVOL_RDONLY
	superMagic     = 0x9123683e     // BTRFS_SUPER_MAGIC (statfs f_type)
	firstFreeObjID = 256            // BTRFS_FIRST_FREE_OBJECTID (subvolume root inode)
)

// Quota constants.
const (
	quotaCtlEnable     = uint64(1)       // BTRFS_QUOTA_CTL_ENABLE
	qgroupLimitMaxRfer = uint64(1 << 0)  // BTRFS_QGROUP_LIMIT_MAX_RFER
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

// ioctlFsInfoArgs maps to struct btrfs_ioctl_fs_info_args (1024 bytes).
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
	Reserved       [944]byte
}

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

// ioctlInoLookupArgs maps to struct btrfs_ioctl_ino_lookup_args (4096 bytes).
type ioctlInoLookupArgs struct {
	Treeid   uint64
	Objectid uint64
	Name     [4080]byte
}

// Compile-time size assertions: kernel requires exact sizes.
var _ [1024]byte = [unsafe.Sizeof(ioctlFsInfoArgs{})]byte{}
var _ [4096]byte = [unsafe.Sizeof(ioctlVolArgsV2{})]byte{}
var _ [16]byte = [unsafe.Sizeof(ioctlQuotaCtlArgs{})]byte{}
var _ [48]byte = [unsafe.Sizeof(ioctlQgroupLimitArgs{})]byte{}
var _ [4096]byte = [unsafe.Sizeof(ioctlInoLookupArgs{})]byte{}

// ioctl performs a raw ioctl syscall.
func ioctl(fd uintptr, req uintptr, arg uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}
