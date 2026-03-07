// SPDX-License-Identifier: GPL-3.0-or-later

// nexus-btrfs is a minimal helper that runs btrfs send/receive with
// elevated privileges. It requires CAP_SYS_ADMIN and CAP_FOWNER (via
// setcap) so that the main nexus daemon can remain unprivileged. It
// raises both as ambient capabilities and execs the btrfs binary directly.
//
// CAP_SYS_ADMIN is needed for BTRFS_IOC_SEND and BTRFS_IOC_SET_RECEIVED_SUBVOL.
// CAP_FOWNER is needed because btrfs-progs opens the mount point with
// O_NOATIME, which requires ownership or CAP_FOWNER.
//
// Usage:
//
//	nexus-btrfs send <subvolume-path>       — write send stream to stdout
//	nexus-btrfs receive <dest-dir>          — read send stream from stdin
//	nexus-btrfs set-readonly <path> <bool>  — set/clear read-only flag
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"
)

func main() {
	runtime.LockOSThread()

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: nexus-btrfs <send|receive|set-readonly> ...\n")
		os.Exit(1)
	}

	// Raise caps as ambient so the exec'd btrfs binary inherits them.
	for _, cap := range []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_FOWNER} {
		if err := raiseAmbientCap(cap); err != nil {
			fmt.Fprintf(os.Stderr, "nexus-btrfs: raise ambient cap: %v\n", err)
			os.Exit(1)
		}
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "send":
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "usage: nexus-btrfs send <subvolume-path>\n")
			os.Exit(1)
		}
		execBtrfs("send", os.Args[2])

	case "receive":
		if len(os.Args) != 3 {
			fmt.Fprintf(os.Stderr, "usage: nexus-btrfs receive <dest-dir>\n")
			os.Exit(1)
		}
		execBtrfs("receive", os.Args[2])

	case "set-readonly":
		if len(os.Args) != 4 {
			fmt.Fprintf(os.Stderr, "usage: nexus-btrfs set-readonly <path> <true|false>\n")
			os.Exit(1)
		}
		execBtrfs("property", "set", os.Args[2], "ro", os.Args[3])

	default:
		fmt.Fprintf(os.Stderr, "nexus-btrfs: unknown command %q\n", subcmd)
		os.Exit(1)
	}
}

// execBtrfs replaces the current process with `btrfs <args...>`.
func execBtrfs(args ...string) {
	btrfsPath, err := exec.LookPath("btrfs")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-btrfs: btrfs not found: %v\n", err)
		os.Exit(1)
	}
	argv := append([]string{"btrfs"}, args...)
	if err := unix.Exec(btrfsPath, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-btrfs: exec btrfs: %v\n", err)
		os.Exit(1)
	}
}

func raiseAmbientCap(cap uintptr) error {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	word := cap / 32
	bit := uint32(1 << (cap % 32))

	if data[word].Permitted&bit == 0 {
		return fmt.Errorf("CAP %d not in permitted set", cap)
	}

	data[word].Inheritable |= bit
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	return unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, cap, 0, 0)
}
