// SPDX-License-Identifier: GPL-2.0-or-later

// nexus-dns is a minimal helper that raises CAP_NET_BIND_SERVICE and execs
// the CoreDNS binary. It requires cap_net_bind_service+ep via setcap so that
// the main nexus daemon can remain unprivileged.
//
// Usage:
//
//	nexus-dns <coredns-binary> [args...]
package main

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func main() {
	runtime.LockOSThread()

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: nexus-dns <coredns-binary> [args...]\n")
		os.Exit(1)
	}

	binPath := os.Args[1]
	if _, err := os.Stat(binPath); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-dns: binary not found: %s\n", binPath)
		os.Exit(1)
	}

	if err := raiseAmbientCap(unix.CAP_NET_BIND_SERVICE); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-dns: %v\n", err)
		os.Exit(1)
	}

	// Replace this process with coredns.
	args := os.Args[1:] // ["coredns", "-conf", "...", ...]
	if err := unix.Exec(binPath, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-dns: exec %s: %v\n", binPath, err)
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
		return fmt.Errorf("CAP %d not in permitted set (missing setcap?)", cap)
	}

	data[word].Inheritable |= bit
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	return unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, cap, 0, 0)
}
