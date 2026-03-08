# Firewall Forwarding Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Automatically manage iptables FORWARD rules so VMs can reach external services even when a host firewall (UFW, firewalld) is active.

**Architecture:** Extend `nexus-cni-exec` with `setup-forwarding` / `teardown-forwarding` subcommands using `coreos/go-iptables`. The daemon calls these during network init (`cni.New()`) and shutdown (`cni.Close()`). Also remove the obsolete `nexus setup` command.

**Tech Stack:** Go, `coreos/go-iptables`, `nexus-cni-exec` helper binary

**Design doc:** `docs/firewall-forwarding-design.md`

---

### Task 1: Add go-iptables dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Add the dependency**

Run: `go get github.com/coreos/go-iptables@latest`
Expected: go.mod and go.sum updated with new dependency

**Step 2: Verify it compiles**

Run: `go build ./...`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add coreos/go-iptables dependency"
```

---

### Task 2: Implement forwarding logic in nexus-cni-exec

**Files:**
- Create: `cmd/nexus-cni-exec/forward.go`

This file contains the core firewall forwarding logic: setup, teardown,
and idempotency handling. It uses `coreos/go-iptables` to manage a
`NEXUS-FORWARD` chain in the iptables filter table.

**Step 1: Write forward.go**

```go
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
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/nexus-cni-exec/`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add cmd/nexus-cni-exec/forward.go
git commit -m "feat(nexus-cni-exec): add firewall forwarding management"
```

---

### Task 3: Wire subcommands into nexus-cni-exec dispatch

**Files:**
- Modify: `cmd/nexus-cni-exec/main.go:41-48`

**Step 1: Add subcommand dispatch**

In `main()`, the switch statement at line 41-48 currently handles only
`delete-bridge`. Add `setup-forwarding` and `teardown-forwarding`:

```go
		switch os.Args[1] {
		case "delete-bridge":
			deleteBridge()
		case "setup-forwarding":
			setupForwarding()
		case "teardown-forwarding":
			teardownForwarding()
		default:
			fmt.Fprintf(os.Stderr, "nexus-cni-exec: unknown subcommand %q\n", os.Args[1])
			os.Exit(1)
		}
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/nexus-cni-exec/`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add cmd/nexus-cni-exec/main.go
git commit -m "feat(nexus-cni-exec): wire setup/teardown-forwarding subcommands"
```

---

### Task 4: Call setup-forwarding from cni.New()

**Files:**
- Modify: `internal/infra/cni/network.go:62-184`

The daemon calls `cni.New()` at startup. Add a call to
`nexus-cni-exec setup-forwarding <bridge>` at the end of `New()`, just
before the return statement. This is best-effort — if the iptables binary
is unavailable (e.g., minimal container), log a warning but don't fail.

**Step 1: Add setup-forwarding call to New()**

Add this block just before the `return &Network{...}` statement at
line 172 of `network.go`:

```go
	// Best-effort firewall forwarding setup. Ensures the host firewall
	// (UFW, firewalld) allows FORWARD traffic for the bridge interface.
	// Non-fatal: on systems without iptables, networking may still work
	// if the host has no restrictive firewall.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, cniExecAbs, "setup-forwarding", "nexus0").CombinedOutput()
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "nexus: warning: setup forwarding: %v: %s\n", err, out)
		}
	}
```

Add `"time"` to the import block if not already present.

**Step 2: Verify it compiles**

Run: `go build ./...`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add internal/infra/cni/network.go
git commit -m "feat(cni): call setup-forwarding on network init"
```

---

### Task 5: Call teardown-forwarding from cni.Close()

**Files:**
- Modify: `internal/infra/cni/network.go:186-190`

Add teardown-forwarding to `Close()` so firewall rules are cleaned up
when the daemon shuts down. Best-effort (don't fail the close).

**Step 1: Update Close()**

Replace the existing `Close()` method:

```go
// Close removes firewall rules and temporary directories.
func (n *Network) Close() error {
	// Best-effort firewall cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	exec.CommandContext(ctx, n.cniExecBin, "teardown-forwarding", n.bridgeName).CombinedOutput() //nolint:errcheck
	cancel()

	os.RemoveAll(n.wrapperDir)
	return os.RemoveAll(n.confDir)
}
```

**Step 2: Verify it compiles**

Run: `go build ./...`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add internal/infra/cni/network.go
git commit -m "feat(cni): teardown forwarding rules on close"
```

---

### Task 6: Remove obsolete `nexus setup` command

The `nexus setup` command group is obsolete now that all privileged
operations are handled by helper binaries:

- `btrfs-quotas` → handled by `nexus-quota` (idempotent on every call)
- `firewall` → handled by `nexus-cni-exec` (automatic on daemon start)

**Files:**
- Delete: `cmd/setup.go`
- Modify: `cmd/root.go:92`

**Step 1: Remove setup.go**

Run: `rm cmd/setup.go`

**Step 2: Remove registration from root.go**

In `cmd/root.go`, remove line 92:
```go
	rootCmd.AddCommand(newSetupCmd())
```

**Step 3: Verify it compiles**

Run: `go build ./...`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add cmd/setup.go cmd/root.go
git commit -m "chore: remove obsolete nexus setup command

btrfs-quotas is handled automatically by nexus-quota helper.
Firewall forwarding is handled by nexus-cni-exec helper."
```

---

### Task 7: Add E2E test for TCP outbound connectivity

**Files:**
- Modify: `tests/e2e/nexus_test.go`

The existing `TestOutboundConnectivity` tests ICMP (ping), which works
even without firewall forwarding rules. Add a TCP connectivity test
that would fail without the FORWARD chain rules.

**Step 1: Add TestOutboundTCP to nexus_test.go**

Add this test after the existing `TestOutboundConnectivity`:

```go
func TestOutboundTCP(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVMWithImage("test-tcp", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Wait for networking to come up, then test TCP connectivity.
	var result *harness.ExecResult
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "/dev/null", "--timeout=5", "http://example.com"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec wget: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("wget failed (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("TCP outbound OK: wget http://example.com succeeded")
}
```

**Step 2: Run the E2E test suite**

Run: `cd tests/e2e && go test -v -count=1 -run TestOutboundTCP -timeout 5m .`
Expected: PASS (test succeeds because forwarding rules are in place)

**Step 3: Commit**

```bash
git add tests/e2e/nexus_test.go
git commit -m "test(e2e): add TCP outbound connectivity test"
```

---

### Task 8: Update networking docs

**Files:**
- Modify: `docs/networking.md`

Update the networking documentation to reflect that firewall forwarding
is now automatic (managed by `nexus-cni-exec`), and remove any manual
firewall setup instructions.

**Step 1: Read current docs**

Run: Read `docs/networking.md` to understand the current content.

**Step 2: Update docs**

Add a "Firewall" section explaining:
- The daemon automatically manages iptables FORWARD rules via `nexus-cni-exec`
- Rules are added on daemon start and removed on shutdown
- A `NEXUS-FORWARD` chain is created in the filter table
- Works with UFW, firewalld, and bare iptables/nftables setups
- No manual firewall configuration is needed

**Step 3: Commit**

```bash
git add docs/networking.md
git commit -m "docs: document automatic firewall forwarding"
```

---

### Task 9: Build, install, and verify

**Step 1: Build**

Run: `mise run build`
Expected: All binaries compile successfully

**Step 2: Verify setup-forwarding works manually**

Run: `build/nexus-cni-exec setup-forwarding nexus0`
Then: `sudo iptables -L NEXUS-FORWARD -n -v`
Expected: Chain exists with two rules (accept in from bridge, accept established/related out to bridge)

And: `sudo iptables -L FORWARD -n -v | head -5`
Expected: First rule is `-j NEXUS-FORWARD`

**Step 3: Verify teardown-forwarding works**

Run: `build/nexus-cni-exec teardown-forwarding nexus0`
Then: `sudo iptables -L NEXUS-FORWARD -n -v 2>&1`
Expected: Error (chain doesn't exist — it was removed)

**Step 4: Start daemon and test VM connectivity**

Run: `mise run run` (in background)
Create a VM via MCP, exec `wget -q -O /dev/null http://example.com`
Expected: TCP download succeeds

**Step 5: Final commit if any adjustments were needed**

```bash
git add -A
git commit -m "fix: address feedback from manual testing"
```
