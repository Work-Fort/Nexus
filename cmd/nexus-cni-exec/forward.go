// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/coreos/go-iptables/iptables"
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

	ipt, err := iptables.New()
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

	ipt, err := iptables.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: init iptables: %v\n", err)
		os.Exit(1)
	}

	if err := teardownForwardChain(ipt, bridge); err != nil {
		fmt.Fprintf(os.Stderr, "nexus-cni-exec: teardown forwarding: %v\n", err)
		os.Exit(1)
	}
}

func setupForwardChain(ipt *iptables.IPTables, bridge string) error {
	// Create chain (idempotent — NewChain returns error if exists, ignore it).
	ipt.NewChain("filter", nexusChain) //nolint:errcheck

	// Flush existing rules to ensure idempotent state.
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

func teardownForwardChain(ipt *iptables.IPTables, bridge string) error {
	// Remove jump from FORWARD chain (ignore error if not present).
	ipt.DeleteIfExists("filter", "FORWARD", "-j", nexusChain) //nolint:errcheck

	// Flush and delete the chain (ignore errors if chain doesn't exist).
	ipt.ClearChain("filter", nexusChain)  //nolint:errcheck
	ipt.DeleteChain("filter", nexusChain) //nolint:errcheck

	return nil
}
