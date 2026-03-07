// SPDX-License-Identifier: GPL-3.0-or-later

// nexus-quota is a minimal helper that sets btrfs quota limits on subvolumes.
// It requires CAP_SYS_ADMIN (via setcap) so that the main nexus daemon can
// remain unprivileged.
//
// Usage:
//
//	nexus-quota set-limit <path> <bytes>   — set max referenced bytes
//	nexus-quota clear-limit <path>         — remove quota limit
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: nexus-quota <set-limit|clear-limit> <path> [bytes]\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "set-limit":
		setLimit()
	case "clear-limit":
		clearLimit()
	default:
		fmt.Fprintf(os.Stderr, "nexus-quota: unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}

func setLimit() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: nexus-quota set-limit <path> <bytes>\n")
		os.Exit(1)
	}
	path := os.Args[2]

	maxBytes, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: invalid bytes %q: %v\n", os.Args[3], err)
		os.Exit(1)
	}
	if maxBytes == 0 {
		fmt.Fprintf(os.Stderr, "nexus-quota: bytes must be > 0 (use clear-limit to remove)\n")
		os.Exit(1)
	}

	ok, err := btrfs.IsSubvolume(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "nexus-quota: %s is not a btrfs subvolume\n", path)
		os.Exit(1)
	}

	// Enable quotas idempotently — on first call this turns on qgroup
	// accounting for the filesystem; subsequent calls are a no-op (EEXIST).
	// This eliminates the need for a separate "sudo nexus setup btrfs-quotas" step.
	if err := btrfs.EnableQuota(path); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: enable quota: %v\n", err)
		os.Exit(1)
	}

	if err := btrfs.SetQuota(path, maxBytes); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: %v\n", err)
		os.Exit(1)
	}
}

func clearLimit() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: nexus-quota clear-limit <path>\n")
		os.Exit(1)
	}
	path := os.Args[2]

	if err := btrfs.SetQuota(path, 0); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-quota: %v\n", err)
		os.Exit(1)
	}
}
