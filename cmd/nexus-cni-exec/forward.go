// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/sys/unix"
)

const nexusChain = "NEXUS-FORWARD"

// setupForwarding creates iptables FORWARD rules for the bridge interface.
// It creates a NEXUS-FORWARD chain with rules that accept traffic from/to
// the bridge, then inserts a jump to it at the top of the FORWARD chain.
// Idempotent: safe to call multiple times.
func setupForwarding() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: nexus-cni-exec setup-forwarding <bridge>\n")
		os.Exit(1)
	}
	bridge := os.Args[2]
	if !validIfName(bridge) {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: invalid bridge name %q\n", bridge)
		os.Exit(1)
	}

	raiseForwardingCaps()
	ensureXtablesLock()

	ipt, err := newIPTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: init iptables: %v\n", err)
		os.Exit(1)
	}

	if err := setupForwardChain(ipt, bridge); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: setup forwarding: %v\n", err)
		os.Exit(1)
	}
}

// teardownForwarding removes the NEXUS-FORWARD chain and its jump rule.
// Idempotent: safe to call even if the chain doesn't exist.
func teardownForwarding() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: nexus-cni-exec teardown-forwarding <bridge>\n")
		os.Exit(1)
	}
	bridge := os.Args[2]
	if !validIfName(bridge) {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: invalid bridge name %q\n", bridge)
		os.Exit(1)
	}

	raiseForwardingCaps()
	ensureXtablesLock()

	ipt, err := newIPTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: init iptables: %v\n", err)
		os.Exit(1)
	}

	if err := teardownForwardChain(ipt, bridge); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: teardown forwarding: %v\n", err)
		os.Exit(1)
	}
}

// raiseForwardingCaps raises capabilities needed for iptables.
// CAP_NET_ADMIN is required for netfilter operations.
// CAP_NET_RAW is required for legacy iptables (raw socket access).
func raiseForwardingCaps() {
	if err := raiseAmbientCap(unix.CAP_NET_ADMIN); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: raise CAP_NET_ADMIN: %v\n", err)
		os.Exit(1)
	}
	// Best-effort: CAP_NET_RAW is only needed for legacy iptables.
	// If not in the permitted set (binary lacks it), skip silently.
	raiseAmbientCap(unix.CAP_NET_RAW) //nolint:errcheck
}

func setupForwardChain(ipt *iptables.IPTables, bridge string) error {
	// Flush existing rules to ensure idempotent state (ClearChain creates if needed).
	if err := ipt.ClearChain("filter", nexusChain); err != nil {
		return fmt.Errorf("clear chain: %w", err)
	}

	// Rule 1: Accept all traffic coming FROM the bridge (VM → internet).
	if err := ipt.AppendUnique("filter", nexusChain,
		"-i", bridge, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add forward-in rule: %w", err)
	}

	// Rule 2: Accept return traffic going TO the bridge (internet → VM).
	if err := ipt.AppendUnique("filter", nexusChain,
		"-o", bridge, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
		"-j", "ACCEPT"); err != nil {
		return fmt.Errorf("add forward-out rule: %w", err)
	}

	// Insert jump at top of FORWARD chain (if not already present).
	exists, err := ipt.Exists("filter", "FORWARD", "-j", nexusChain)
	if err != nil {
		return fmt.Errorf("check forward jump: %w", err)
	}
	if !exists {
		if err := ipt.Insert("filter", "FORWARD", 1, "-j", nexusChain); err != nil {
			return fmt.Errorf("insert forward jump: %w", err)
		}
	}

	return nil
}

// newIPTables creates an iptables handle. It uses the system default
// iptables binary first (which matches the host firewall's backend),
// falling back to iptables-nft. Using the same backend as the firewall
// is critical: iptables-legacy and iptables-nft operate on separate
// netfilter hook registrations, so rules in one don't affect the other.
func newIPTables() (*iptables.IPTables, error) {
	ipt, err := iptables.New()
	if err == nil {
		return ipt, nil
	}
	// System default failed (e.g. legacy iptables without CAP_NET_RAW).
	// Try iptables-nft explicitly as a fallback.
	if path, lookErr := exec.LookPath("iptables-nft"); lookErr == nil {
		return iptables.New(iptables.Path(path))
	}
	return nil, err
}

// ensureXtablesLock sets XTABLES_LOCKFILE to a user-writable path if the
// system lock file (/run/xtables.lock) is not accessible. This is needed
// because the lock file is typically root-owned 0600, and CAP_NET_ADMIN
// does not bypass regular file permission checks.
func ensureXtablesLock() {
	if f, err := os.OpenFile("/run/xtables.lock", os.O_RDWR, 0); err == nil {
		f.Close()
		return
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = fmt.Sprintf("/tmp/nexus-%d", os.Getuid())
	}
	lockDir := filepath.Join(dir, "nexus")
	os.MkdirAll(lockDir, 0700) //nolint:errcheck
	os.Setenv("XTABLES_LOCKFILE", filepath.Join(lockDir, "xtables.lock"))
}

func teardownForwardChain(ipt *iptables.IPTables, bridge string) error {
	// Remove jump from FORWARD chain (ignore error if not present).
	ipt.DeleteIfExists("filter", "FORWARD", "-j", nexusChain) //nolint:errcheck

	// Flush and delete the chain (ignore errors if chain doesn't exist).
	ipt.ClearChain("filter", nexusChain)  //nolint:errcheck
	ipt.DeleteChain("filter", nexusChain) //nolint:errcheck

	return nil
}
