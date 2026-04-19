---
type: plan
step: "1"
title: "nexus e2e harness — orphan-leak hardening"
status: pending
assessment_status: complete
provenance:
  source: roadmap
  issue_id: null
  roadmap_step: null
dates:
  created: "2026-04-19"
  approved: null
  completed: null
related_plans: []
---

# Nexus E2E Harness — Orphan-Leak Hardening

**Goal:** Add the missing `Setpgid`, negative-pid kill, and
`WaitDelay` to Nexus's e2e daemon spawn so leaked descendants
(containerd shims that survive a stuck reaper, future helper binaries)
get reaped with the daemon. The current harness already has the
`*os.File` stderr workaround at `tests/e2e/harness/harness.go:194-203`
(specifically because containerd shims kept `cmd.Wait` hanging when
stderr was a pipe — the comment in that block calls out the exact
mechanism). Three of the four canonical fix parts are still missing.

**Canonical fix** (see `/home/kazw/Work/WorkFort/skills/lead/go-service-architecture/references/architecture-reference.md` — section
"Orphan-Process Hardening (Required)"):

1. **`Setpgid: true`** in `cmd.SysProcAttr` — missing, add.
2. **`*os.File` for stdout/stderr** — already present (L194-203,
  L301-310 in `StartDaemonWithNamespace`).
3. **Negative-pid kill** (`syscall.Kill(-pgid, sig)`) — missing,
  add to `Stop`, `Kill`, `GracefulStop`, and the failure-path
  cleanup in both spawn helpers.
4. **`cmd.WaitDelay = 10 * time.Second`** — missing, add.

All four parts are load-bearing — the existing `*os.File` workaround
stops the most common leak path (containerd shims inheriting the
stderr pipe) but does not stop a shim that holds a separate pipe of
its own (CNI exec, drive helpers). Setpgid + group-kill is the only
defence against that class.

**Repo specifics.** Nexus is the only repo with a second reaper path:
`cleanupNamespace` (line 433-463) shells out to `ctr` to tear down
containerd containers, snapshots, and images. The two paths must not
race. The `cleanupNamespace` work is best-effort and bounded by per-
command timeouts already; the new group-kill happens in `Stop` (line
408-425) before `cleanup()` is called, so by the time `cleanupNamespace`
runs, the daemon is gone but containerd shims may still be in the
process group. `kill(-pgid, SIGKILL)` on the shutdown path will signal
those shims directly — they are children of containerd, not children
of the daemon, so they may or may not be in the daemon's pgid
depending on how containerd spawned them. `cleanupNamespace` remains
the authoritative containerd-specific reaper; the group-kill is a
belt-and-suspenders cleanup for direct daemon children only.

This plan does NOT try to bring containerd children into the daemon's
pgid (that would require changes to containerd, which Nexus does not
own). The two reapers continue to coexist: Setpgid + group-kill kills
direct daemon children; `cleanupNamespace` handles containerd-spawned
shims via `ctr`. Both run on the same `Stop` path, in this order:
group-kill → wait → containerd cleanup.

The new pgid-based reaping is a strict improvement for direct daemon
helpers — CNI exec, btrfs-helper, netns-helper, node-exporter, and
any other helper binary the daemon spawns directly. These ARE in the
daemon's pgid and are killed by `kill(-pgid, ...)` even if the daemon
exits before their `SIGCHLD` is delivered. The pre-existing
`cleanupNamespace` continues to handle containerd-spawned shims
(which are children of containerd, not the daemon, so outside the
daemon's pgid). Two reapers, distinct scopes, no race.

**Tech stack:** Go 1.26 (e2e nested module), `os/exec`, `syscall`.
No new dependencies.

**Commands:** `mise run e2e` (the existing task at
`.mise/tasks/e2e.sh`) builds and runs `cd tests/e2e && go test -v
-count=1 -parallel 1 -timeout 10m .`. Targeted runs use
`cd tests/e2e && go test -run TestX -count=1 ./harness/...`.

---

## Prerequisites

- `tests/e2e/go.mod` (Go 1.26.0) — `cmd.WaitDelay` (Go 1.20+) is
  available.
- `e2e.sh` requires root, containerd, and btrfs to run the full suite.
  The leak-detection test added by this plan does not require any of
  those — it only spawns the daemon long enough to verify pgid
  membership and tears it down.

---

## Conventions

- Run all build/test commands via `mise run <task>` from `nexus/lead/`.
  Targeted go test runs are permitted from inside `tests/e2e/`.
- Commit after each task with the multi-line conventional-commits
  HEREDOC and the Co-Authored-By trailer below.

```bash
git add <files>
git commit -m "$(cat <<'EOF'
<type>(<scope>): <description>

<body explaining why, not what>

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task Breakdown

### Task 1: Write the failing leak-detection test

**Files:**
- Create: `tests/e2e/harness/daemon_leak_test.go`

**Step 1: Write the test**

The test starts a daemon (with networking and DNS off — no containerd
churn, no root requirement), reads its pgid, calls `Stop`, then
asserts the group is empty. Without `Setpgid`,
`syscall.Getpgid(daemonPID)` returns the harness's group, not the
daemon's PID — the test fails immediately.

```go
// SPDX-License-Identifier: GPL-3.0-or-later
package harness

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestDaemonStop_KillsProcessGroup(t *testing.T) {
	binary := os.Getenv("NEXUS_BINARY")
	if binary == "" {
		t.Skip("NEXUS_BINARY not set; run via 'mise run e2e'")
	}
	binDir := os.Getenv("NEXUS_BIN_DIR")
	if binDir == "" {
		// An empty NEXUS_BIN_DIR is fine: helper binaries (CNI,
		// btrfs-helper, netns-helper) are only resolved at VM-create
		// time, not daemon-start time. /tmp is an arbitrary stub.
		binDir = "/tmp"
	}

	addr, err := FreePort()
	if err != nil {
		t.Fatalf("FreePort: %v", err)
	}

	// Network/DNS off keeps this test free of root requirements.
	d, err := StartDaemon(binary, binDir, addr,
		WithNetworkEnabled(false),
		WithDNSEnabled(false),
	)
	if err != nil {
		t.Fatalf("StartDaemon: %v", err)
	}
	pid := d.cmd.Process.Pid

	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("Getpgid(%d): %v", pid, err)
	}
	if pgid != pid {
		t.Fatalf("daemon pgid = %d, want %d (Setpgid not set)", pgid, pid)
	}
	// Defence against the (vanishingly rare) case where the test
	// process itself is in a group whose id equals the daemon PID —
	// pgid == pid would pass spuriously.
	if pgid == os.Getpid() {
		t.Fatalf("daemon pgid (%d) equals harness pid; daemon inherited harness group", pgid)
	}

	if err := d.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Use errors.Is (not direct ==) because syscall.Errno implements
	// the errors.Is contract and errors.Is is the idiomatic Go choice.
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("kill(-%d, 0) = %v, want ESRCH (group still has live members)", pgid, err)
	}
}
```

`StartDaemon` already accepts `WithNetworkEnabled(false)` and
`WithDNSEnabled(false)` — see lines 53-59 of `harness.go`.

**Step 2: Run the test to verify it fails**

The full e2e setup is heavyweight (root, containerd, btrfs). For the
TDD loop only, build the daemon by hand and run the targeted test:

```
cd nexus/lead && go build -o /tmp/nexus ./
NEXUS_BINARY=/tmp/nexus NEXUS_BIN_DIR=/tmp \
  go test -run TestDaemonStop_KillsProcessGroup -count=1 \
  ./tests/e2e/harness/...
```

The raw `go build` is permitted under planner.md's TDD-loop exception
for native test runners. The full regression run in Task 2 Step 6
goes through `sudo -E mise run e2e`.

Expected: FAIL with `daemon pgid = <harness_pgid>, want <daemon_pid>
(Setpgid not set)`.

**Step 3: Commit the failing test**

```bash
git add tests/e2e/harness/daemon_leak_test.go
git commit -m "$(cat <<'EOF'
test(e2e): add failing TestDaemonStop_KillsProcessGroup

Asserts the nexus daemon spawns into its own process group and that
Stop empties the group. Currently fails because StartDaemon does not
set Setpgid; the next task adds the missing canonical-fix parts on
top of the existing *os.File stderr workaround.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Add Setpgid + WaitDelay + group-kill to both spawn helpers

**Depends on:** Task 1

**Files:**
- Modify: `tests/e2e/harness/harness.go` — `StartDaemon` (line 125),
  `StartDaemonWithNamespace` (line 246), `Stop` (line 408), `Kill`
  (line 370), `GracefulStop` (line 380), and the failure-path
  cleanups inside both spawn helpers.

**Step 1: Add Setpgid + WaitDelay to `StartDaemon`'s `cmd` setup**

Insert a comment block plus two new lines immediately after
`cmd.Stderr = stderrFile` (line 211). The existing comment at lines
193-198 about the `*os.File` workaround stays — it explains the
second part of the canonical fix. The result reads:

```go
	cmd.Stdout = os.Stderr
	cmd.Stderr = stderrFile
	// Setpgid puts the daemon and any direct descendants in a fresh
	// process group equal to the daemon PID; the negative-pid kill
	// in Stop signals the whole group. Containerd-spawned shims may
	// not be in the group (they're children of containerd, not the
	// daemon), so cleanupNamespace remains the authoritative ctr-
	// based reaper for those. WaitDelay force-closes any inherited
	// fds after the daemon exits. See the orphan-process hardening
	// section of go-service-architecture.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 10 * time.Second
```

**Step 2: Update `StartDaemon`'s failure-path kill (line 236-237)**

Currently:

```go
	cmd.Process.Kill()
	cmd.Wait()
	stderrFile.Close()
	os.Remove(stderrFile.Name())
	os.RemoveAll(xdgDir)
	return nil, fmt.Errorf("daemon did not become ready on %s within 10s", addr)
```

Replace with:

```go
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	cmd.Wait()
	stderrFile.Close()
	os.Remove(stderrFile.Name())
	os.RemoveAll(xdgDir)
	return nil, fmt.Errorf("daemon did not become ready on %s within 10s", addr)
```

**Step 3: Apply the same two changes to `StartDaemonWithNamespace`**

`StartDaemonWithNamespace` (line 246) is a near-clone of `StartDaemon`
that reuses an existing namespace. Apply identical edits:

- Insert `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` and
  `cmd.WaitDelay = 10 * time.Second` after `cmd.Stderr = stderrFile`
  (line 318).
- Replace the failure-path `cmd.Process.Kill(); cmd.Wait()` (line
  342-343) with the negative-pid kill block from Step 2.

**Step 4: Rewrite `Stop`, `Kill`, and `GracefulStop` to use group-kill**

Replace `Kill` (lines 370-375) with:

```go
// Kill sends SIGKILL to the daemon's process group (simulates crash).
// Does NOT clean up namespace or XDG dir — those are reused by the
// next daemon instance.
func (d *Daemon) Kill() {
	if d.cmd.Process != nil {
		pgid := d.cmd.Process.Pid
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		d.cmd.Wait()
	}
}
```

Replace `GracefulStop` (lines 380-395) with:

```go
// GracefulStop sends SIGTERM to the daemon's process group and waits
// for the daemon to exit, but does NOT clean up the namespace or XDG
// dir. Use this to test graceful shutdown behavior across daemon
// restarts.
func (d *Daemon) GracefulStop() error {
	if d.cmd.Process == nil {
		return nil
	}
	pgid := d.cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
		return fmt.Errorf("daemon did not exit after SIGTERM")
	}
}
```

Replace `Stop` (lines 408-425) with:

```go
func (d *Daemon) Stop() error {
	if d.cmd.Process == nil {
		return nil
	}
	pgid := d.cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case err := <-done:
		d.cleanup()
		return err
	case <-time.After(20 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
		d.cleanup()
		return fmt.Errorf("daemon did not exit after SIGTERM")
	}
}
```

`d.cleanup()` (line 427-431) is unchanged — it still calls
`cleanupNamespace(d.namespace)` and `os.RemoveAll(d.xdgDir)`. The
order matters: group-kill happens first (signal direct daemon
children), then `cmd.Wait` returns, then `cleanupNamespace` runs `ctr`
commands to reap any containerd shims that survived because they were
not in the daemon's pgid. The two reapers are sequential, not
concurrent — no race.

**Step 5: Run the leak test to verify it passes**

```
cd nexus/lead && go build -o /tmp/nexus ./
NEXUS_BINARY=/tmp/nexus NEXUS_BIN_DIR=/tmp \
  go test -run TestDaemonStop_KillsProcessGroup -count=1 \
  ./tests/e2e/harness/...
```

Expected: PASS.

**Step 6: Run the full e2e suite to verify no regression**

Full e2e requires root + containerd + btrfs. Run as root:

```
sudo -E mise run e2e
```

Expected: PASS. The graceful-SIGTERM-then-SIGKILL ordering is
unchanged in `Stop` and `GracefulStop`; only the kill mechanism is
upgraded to a group-kill. `cleanupNamespace`'s ctr-based reaping is
untouched.

If the full suite is not available locally, run the harness package
unit tests at minimum (the leak test covers the daemon spawn
behaviour):

```
cd tests/e2e && go test -run "TestDaemonStop|TestFreePort|TestRandomNamespace" -count=1 ./harness/...
```

**Step 7: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "$(cat <<'EOF'
fix(e2e): add Setpgid + group-kill + WaitDelay to daemon harness

Adds the three missing parts of the canonical orphan-process fix on
top of the existing *os.File stderr workaround. The daemon now
spawns into its own process group; Stop, Kill, GracefulStop, and
the StartDaemon failure paths all signal the group via
kill(-pgid, ...); WaitDelay force-closes any inherited fd after the
daemon exits.

The existing cleanupNamespace ctr-based reaper continues to run
after Stop drains cmd.Wait — containerd-spawned shims are children
of containerd, not the daemon, so they may not be in the daemon's
pgid. The two reapers are sequential (group-kill first, then ctr
cleanup); no concurrent reaping race. Direct daemon helpers (CNI
exec, btrfs-helper, netns-helper, node-exporter) ARE in the pgid
and are now reaped by the group-kill — a strict improvement over
today, where they leak if the daemon exits before reaping them.

Implements the canonical e2e-harness orphan-leak hardening pattern
documented in skills/lead/go-service-architecture/references/architecture-reference.md
(section "Orphan-Process Hardening (Required)").

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Verify cleanup is bounded under simulated test failure

**Depends on:** Task 2

**Files:**
- (Temporary, reverted) inject `t.Fatal` into a cheap existing
  harness test.

**Step 1: Confirm working tree is clean**

Run `git status`. Expected: clean. The next step injects a temporary
edit; a clean tree before this step ensures revert is unambiguous.

**Step 2: Inject a forced failure**

Pick an existing test that calls `StartDaemon` (any in
`tests/e2e/`) and add `t.Fatal("synthetic failure to verify cleanup
bound")` immediately after `StartDaemon` returns. Do not commit.
Optionally `git stash push -k -m "synthetic-failure"` then
`git stash pop` so the diff is recoverable if the timing run is
interrupted.

**Step 3: Time the e2e run**

If running the full suite (root required):

```
sudo -E time mise run e2e
```

Otherwise the harness leak test is enough:

```
time go test -run TestDaemonStop_KillsProcessGroup -count=1 \
  ./tests/e2e/harness/...
```

Expected:

- The synthetic test FAILs.
- `Stop` returns within ~21 seconds worst case (20s SIGTERM grace +
  bounded `cleanupNamespace`); typical runs are well under 5
  seconds.

If `Stop` exceeds 30 seconds, inspect:

- `ps -o pid,pgid,cmd -p $(pgrep -f nexus.*daemon)` — daemon
  surviving means SIGTERM/SIGKILL not delivered to the group.
- `pgrep -f containerd-shim` — shim surviving means
  `cleanupNamespace` didn't catch it; that's a separate pre-existing
  issue, not regression.

**Step 4: Revert the synthetic failure**

`git checkout -- <test_file>` to restore. Run `git status` and
confirm the working tree is clean.

**Step 5: Final regression run**

Run the harness leak test:

```
go test -run TestDaemonStop_KillsProcessGroup -count=1 \
  ./tests/e2e/harness/...
```

Expected: PASS.

No commit for this task — verification only.

---

## Verification Checklist

After all tasks complete:

- [ ] `TestDaemonStop_KillsProcessGroup` passes; reverting either
  Setpgid-line in `harness.go` makes it fail with the expected
  message.
- [ ] Both `StartDaemon` and `StartDaemonWithNamespace` set
  `Setpgid: true` and `WaitDelay = 10s` on the spawned `cmd`.
- [ ] `Stop`, `Kill`, `GracefulStop`, and both spawn-helper failure
  paths use `syscall.Kill(-pgid, sig)`, never `cmd.Process.Signal`/
  `cmd.Process.Kill`.
- [ ] The `*os.File` stderr workaround at lines 194-203 / 301-310 is
  preserved (its comment explaining containerd-shim leakage stays).
- [ ] `cleanupNamespace` is unchanged — runs after `cmd.Wait`
  returns, not concurrently.
- [ ] Full `mise run e2e` (root) passes if available; harness
  package leak test passes regardless.

## Out of Scope

- Changing `cleanupNamespace` to use a different reaper. The
  existing `ctr`-based path is bounded by per-command timeouts and
  works.
- Putting containerd-spawned shims into the daemon's pgid. Would
  require changes to containerd, outside Nexus's surface.
- Restructuring the `StartDaemon` / `StartDaemonWithNamespace` near-
  duplication. Out of scope for this hardening pass.
- Adding new health checks or DATA RACE detection. Nexus already
  uses the stderr file for that via `StopFatal` (line 352-366).
