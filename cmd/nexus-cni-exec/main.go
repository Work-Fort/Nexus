// SPDX-License-Identifier: Apache-2.0

// nexus-cni-exec is a multi-call wrapper for CNI plugin execution.
// It is installed as symlinks named after each CNI plugin (e.g., "bridge",
// "host-local"). When invoked, it raises CAP_NET_ADMIN and CAP_SYS_ADMIN
// as ambient capabilities and execs the real plugin from the system CNI
// bin directory. This keeps the main nexus daemon unprivileged while
// giving CNI plugins the capabilities they need.
//
// Usage (via symlink):
//
//	ln -s nexus-cni-exec bridge
//	./bridge  → execs /opt/cni/bin/bridge with elevated caps
//
// The real plugin directory defaults to /opt/cni/bin and can be
// overridden with the NEXUS_CNI_REAL_BIN_DIR environment variable.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func main() {
	runtime.LockOSThread()

	pluginName := filepath.Base(os.Args[0])

	// When invoked as "nexus-cni-exec" directly (not via symlink),
	// dispatch subcommands.
	if pluginName == "nexus-cni-exec" {
		if len(os.Args) < 2 {
			fmt.Fprintf(os.Stderr, "nexus-cni-exec: subcommand required\n")
			os.Exit(1)
		}
		switch os.Args[1] {
		case "delete-bridge":
			deleteBridge()
		default:
			fmt.Fprintf(os.Stderr, "nexus-cni-exec: unknown subcommand %q\n", os.Args[1])
			os.Exit(1)
		}
		return
	}

	realDir := os.Getenv("NEXUS_CNI_REAL_BIN_DIR")
	if realDir == "" {
		realDir = "/opt/cni/bin"
	}
	realPlugin := filepath.Join(realDir, pluginName)

	if _, err := os.Stat(realPlugin); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: real plugin not found: %s\n", realPlugin)
		os.Exit(1)
	}

	for _, cap := range []uintptr{unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN} {
		if err := raiseAmbientCap(cap); err != nil {
			fmt.Fprintf(os.Stderr, "nexus-cni-exec: %v\n", err)
			os.Exit(1)
		}
	}

	// Replace this process with the real plugin.
	if err := unix.Exec(realPlugin, os.Args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: exec %s: %v\n", realPlugin, err)
		os.Exit(1)
	}
}

// validIfName checks that name is a valid Linux interface name:
// alphanumeric, hyphen, or underscore, max 15 chars (IFNAMSIZ - 1).
func validIfName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// deleteBridge raises CAP_NET_ADMIN and execs `ip link delete <name>`.
func deleteBridge() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: usage: nexus-cni-exec delete-bridge <ifname>\n")
		os.Exit(1)
	}
	ifName := os.Args[2]
	if !validIfName(ifName) {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: invalid interface name %q\n", ifName)
		os.Exit(1)
	}

	if err := raiseAmbientCap(unix.CAP_NET_ADMIN); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: %v\n", err)
		os.Exit(1)
	}

	ipPath, err := exec.LookPath("ip")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: ip not found: %v\n", err)
		os.Exit(1)
	}

	if err := unix.Exec(ipPath, []string{"ip", "link", "delete", ifName}, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: exec ip: %v\n", err)
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
