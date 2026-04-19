---
type: plan
step: "1"
title: "nexus e2e — skip-guard hardening for cap-dependent tests"
status: complete
assessment_status: complete
provenance:
  source: roadmap
  issue_id: null
  roadmap_step: null
dates:
  created: "2026-04-19"
  approved: "2026-04-19"
  completed: "2026-04-19"
related_plans:
  - docs/plans/2026-04-19-e2e-harness-orphan-leak-hardening.md
---

# Nexus E2E — Skip-Guard Hardening for Cap-Dependent Tests

**Goal:** Convert two classes of FAIL-on-missing-capabilities into clean
`t.Skip` with actionable messages, and resolve the dirty `web/vite.config.ts`
that the QA agent flagged.

The two test files at issue both already have a guard, but each guard
under-checks the environment:

- `tests/e2e/backup_test.go::requireBtrfs` checks the filesystem and the
  `btrfs` CLI but does NOT verify that `build/nexus-btrfs` carries
  `cap_sys_admin`. When the binary exists without caps, the four export/import
  tests proceed past the guard and fail with `CAP 21 not in permitted set` →
  HTTP 500.
- `tests/e2e/metrics_test.go::requireNetworking` checks that
  `build/nexus-netns` and `build/nexus-cni-exec` exist but does NOT verify
  caps. When uncapabilitated, `TestPrometheusTargets` fails with HTTP 500 on
  the first VM creation.

The gold-standard pattern is `requireNetworkCaps` in `tests/e2e/nexus_test.go:92`,
which shells out to `getcap`, polls for up to 5 seconds, and `t.Skip`s with a
message that names the exact `sudo` command. We extend the same pattern to
`build/nexus-btrfs` and to the metrics-test networking guard.

Skipping when the environment cannot be made suitable without root is the
explicitly-allowed `t.Skip` exception per `feedback_no_test_failures.md`.

A third, unrelated cleanup task: `web/vite.config.ts` carries an uncommitted
`base: './'` change with an inline comment explaining why. Investigation shows
the change is correct and load-bearing — commit it.

**Tech stack:** Go 1.26 (e2e nested module), `os/exec`. No new dependencies.

**Commands:** `mise run e2e` for the e2e suite. Targeted runs during TDD use
`go test -run <Name>` from `tests/e2e/`.

## Prerequisites

- `mise run build` produces `build/nexus-btrfs`, `build/nexus-netns`,
  `build/nexus-cni-exec`.
- For full local verification (not for the developer to commit), `sudo
  ./scripts/dev-setcap-loop.sh` running in a separate terminal sets the caps;
  alternatively `sudo mise run install:local` performs a one-shot setcap.
- Workspace must be clean apart from the changes this plan introduces. Begin
  by inspecting `git status` — `docs/remaining-features.md` was modified by
  the QA agent that filed DEF-1/DEF-2 and stays untouched until the task that
  removes those entries (Task 1 closes DEF-1, Task 2 closes DEF-2, both
  delete the corresponding "Known Defects" subsection).

## Task Breakdown

### Task 1: Cap-aware skip guard for backup tests (DEF-1)

**Files:**
- Modify: `tests/e2e/snapshot_test.go:19-31` (extend `requireBtrfs` is
  rejected — see rationale; instead add a sibling helper)
- Modify: `tests/e2e/backup_test.go:16,103,173,285` (4 call sites)
- Modify: `docs/remaining-features.md` (remove the DEF-1 subsection)

**Rationale for new helper instead of extending `requireBtrfs`:**
`requireBtrfs` is called from 9 sites in `snapshot_test.go` that exercise
snapshot-only operations (`btrfs subvolume snapshot`, which needs no caps —
the daemon performs it directly without going through `build/nexus-btrfs`).
Adding a cap check there would cause unnecessary skips on a machine that has
btrfs but no setcap. The send/receive path used by export/import is the only
caller of `build/nexus-btrfs`, so a sibling guard `requireBtrfsSend` is the
right scope.

**Step 1: Write the new helper**

Add to `tests/e2e/snapshot_test.go` immediately after `requireBtrfs`:

```go
// requireBtrfsSend skips the test if the build/nexus-btrfs helper is
// missing CAP_SYS_ADMIN. The btrfs send/receive path used by drive
// export/import shells out to this helper, which silently returns
// "CAP 21 not in permitted set" when uncapabilitated. Run
// `sudo ./scripts/dev-setcap-loop.sh` (or `sudo mise run install:local`)
// to set caps; this helper polls up to 5s in case the loop is mid-cycle.
func requireBtrfsSend(t *testing.T) {
	t.Helper()
	requireBtrfs(t)

	helper, err := filepath.Abs("../../build/nexus-btrfs")
	if err != nil {
		t.Skipf("cannot resolve build/nexus-btrfs: %v", err)
	}
	if _, err := os.Stat(helper); err != nil {
		t.Skipf("build/nexus-btrfs not found (run `mise run build`): %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("getcap", helper).Output()
		if err == nil && strings.Contains(string(out), "cap_sys_admin") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Skipf("build/nexus-btrfs lacks cap_sys_admin — run: sudo ./scripts/dev-setcap-loop.sh")
}
```

The `time` and `strings` imports are already present in `snapshot_test.go`
via `os/exec` siblings? Verify and add if missing — the existing import block
in `snapshot_test.go` is `os`, `os/exec`, `path/filepath`, `strings`,
`syscall`, `testing`, `harness`. Add `time` to that list.

**Step 2: Run the helper without callers to confirm it compiles**

Run: `cd tests/e2e && go vet ./...`
Expected: PASS (no diagnostics).

**Step 3: Switch the four backup tests to the new guard**

In `tests/e2e/backup_test.go`, replace `requireBtrfs(t)` with
`requireBtrfsSend(t)` at lines 16, 103, 173, 285.

```go
func TestExportImportWithDrive(t *testing.T) {
	requireBtrfsSend(t)
	// ... rest unchanged
}

func TestExportImportMultipleDrives(t *testing.T) {
	requireBtrfsSend(t)
	// ...
}

func TestExportImportCrossDaemon(t *testing.T) {
	requireBtrfsSend(t)
	// ...
}

func TestExportImportNameConflict(t *testing.T) {
	requireBtrfsSend(t)
	// ...
}
```

**Step 4: Verify tests SKIP cleanly when caps are missing**

Run: `cd tests/e2e && go test -run 'TestExportImport' -v .`

Two acceptable outcomes:
- If `build/nexus-btrfs` has `cap_sys_admin`: tests run normally (PASS or
  pre-existing FAIL — out of scope).
- If `build/nexus-btrfs` lacks `cap_sys_admin`: each of the 4 tests prints
  `--- SKIP: TestExportImport...` with the message
  `build/nexus-btrfs lacks cap_sys_admin — run: sudo ./scripts/dev-setcap-loop.sh`.

The developer SHOULD verify both branches before committing — once with caps
unset (e.g., `sudo setcap -r build/nexus-btrfs`) to see the SKIP path, then
re-set caps via `sudo ./scripts/dev-setcap-loop.sh` (or `sudo mise run
install:local`) to confirm the run path still works. The cap-removal step is
NOT committed; it is only for local verification.

Expected SKIP output:
```
=== RUN   TestExportImportWithDrive
    snapshot_test.go:NN: build/nexus-btrfs lacks cap_sys_admin — run: sudo ./scripts/dev-setcap-loop.sh
--- SKIP: TestExportImportWithDrive (5.01s)
```

**Step 5: Remove DEF-1 from `docs/remaining-features.md`**

Delete the entire `#### DEF-1: backup_test.go ...` subsection (the block
spanning roughly lines 311-326 in the working-tree diff). Leave the parent
"Known Defects: Missing `t.Skip` Guards (filed 2026-04-19)" section header
and the DEF-2 subsection in place — DEF-2 is closed by Task 2.

**Step 6: Commit**

```
git commit -m "$(cat <<'EOF'
test(e2e): skip backup tests when nexus-btrfs lacks cap_sys_admin

The four export/import tests in backup_test.go shell out via
build/nexus-btrfs, which needs CAP_SYS_ADMIN to invoke btrfs
send/receive. The previous requireBtrfs guard checked only for
the btrfs filesystem and CLI presence, so on a host that built
the helper but had not run setcap, tests proceeded past the
guard and failed with an opaque HTTP 500 / "CAP 21 not in
permitted set".

Add requireBtrfsSend in snapshot_test.go modeled on the existing
requireNetworkCaps pattern: poll getcap for up to 5 seconds, then
t.Skip with a message naming the exact remediation command. The
existing requireBtrfs is left in place for snapshot tests, which
exercise the no-caps subvolume path.

Closes DEF-1 in docs/remaining-features.md.

mise run e2e (with caps): backup tests pass
mise run e2e (caps cleared): backup tests SKIP with actionable message

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Cap-aware skip guard for `TestPrometheusTargets` (DEF-2)

**Depends on:** none (independent of Task 1).

**Files:**
- Modify: `tests/e2e/metrics_test.go:15-26` (`requireNetworking`)
- Modify: `docs/remaining-features.md` (remove the DEF-2 subsection)

**Rationale:** `requireNetworking` already lives in `metrics_test.go` and is
used only by `startNetworkedDaemon`, which is called only by
`TestPrometheusTargets`. Extending it in place is the lowest-blast-radius
change. We keep the existing existence check and add a cap poll on top.

We deliberately do NOT consolidate with the broader `requireNetworkCaps` in
`nexus_test.go`: that helper is keyed on `binDir` (the per-test temp dir
under `.e2e-bin-*`), whereas `startNetworkedDaemon` uses the `build/`
copies. The two paths look identical but reach different files, so
duplicating the few lines is clearer than threading a path argument.

**Step 1: Replace `requireNetworking` with cap-aware version**

Replace `tests/e2e/metrics_test.go:15-26`:

```go
// requireNetworking skips the test if the networking helpers in build/
// are missing or lack the capabilities that dev-setcap-loop sets. The
// daemon's network path returns HTTP 500 if nexus-cni-exec is invoked
// without cap_net_admin, so the existence-only check is insufficient.
func requireNetworking(t *testing.T) {
	t.Helper()

	netnsPath, err := filepath.Abs("../../build/nexus-netns")
	if err != nil {
		t.Skipf("cannot resolve build/nexus-netns: %v", err)
	}
	cniPath, err := filepath.Abs("../../build/nexus-cni-exec")
	if err != nil {
		t.Skipf("cannot resolve build/nexus-cni-exec: %v", err)
	}
	for _, p := range []string{netnsPath, cniPath} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s not found (run `mise run build`): %v", p, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		netnsOut, err1 := exec.Command("getcap", netnsPath).Output()
		cniOut, err2 := exec.Command("getcap", cniPath).Output()
		if err1 == nil && strings.Contains(string(netnsOut), "cap_sys_admin") &&
			err2 == nil && strings.Contains(string(cniOut), "cap_net_admin") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Skipf("networking helpers in build/ lack required caps — run: sudo ./scripts/dev-setcap-loop.sh")
}
```

Add the new imports needed at the top of `metrics_test.go`:

```go
import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Work-Fort/nexus-e2e/harness"
)
```

(`os/exec`, `strings`, and `time` are the new entries; `os`, `path/filepath`,
`testing`, and `harness` are already present.)

**Step 2: Verify it compiles**

Run: `cd tests/e2e && go vet ./...`
Expected: PASS (no diagnostics).

**Step 3: Verify the two SKIP/RUN branches**

Run: `cd tests/e2e && go test -run TestPrometheusTargets -v .`

- With caps: test runs (PASS or pre-existing failure unrelated to caps).
- Without caps (`sudo setcap -r build/nexus-cni-exec` then re-run): test
  prints `--- SKIP: TestPrometheusTargets` with
  `networking helpers in build/ lack required caps — run: sudo ./scripts/dev-setcap-loop.sh`.

Re-set caps via `sudo ./scripts/dev-setcap-loop.sh` after the SKIP-path check.

**Step 4: Remove DEF-2 from `docs/remaining-features.md`**

Delete the `#### DEF-2: metrics_test.go ...` subsection. If both DEF-1 (Task
1) and DEF-2 (this task) have been removed, also delete the now-empty
section header `### Known Defects: Missing `t.Skip` Guards (filed
2026-04-19)`. Order between Task 1 and Task 2 does not matter; whichever
commit lands second cleans up the header.

**Step 5: Commit**

```
git commit -m "$(cat <<'EOF'
test(e2e): skip metrics test when network helpers lack caps

requireNetworking in metrics_test.go checked only that
build/nexus-netns and build/nexus-cni-exec existed on disk.
On a host that built the helpers but had not run setcap,
TestPrometheusTargets proceeded into the daemon, which then
returned HTTP 500 from the first VM creation.

Extend the guard to poll getcap (5s window, mirroring the
requireNetworkCaps pattern in nexus_test.go) and t.Skip with
a message naming the exact remediation command.

Closes DEF-2 in docs/remaining-features.md.

mise run e2e (with caps): TestPrometheusTargets passes
mise run e2e (caps cleared): TestPrometheusTargets SKIPs

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Resolve the uncommitted `web/vite.config.ts`

**Depends on:** none (independent of Tasks 1 and 2).

**Files:**
- Modify: `web/vite.config.ts` (the change is already in the working tree;
  this task either commits it as-is or reverts it)

**Investigation summary (already done; the developer should re-verify before
committing):**

The change adds `base: './'` to the Vite config, with an inline comment that
reads: "Served under /ui/ by the Nexus daemon (see cmd/daemon.go). Using
'./' keeps all asset references relative to index.html so they resolve
correctly under any mount prefix."

Verify the claim:
- `cmd/daemon.go:301,308` mounts the embedded UI at `/ui/`
  (`mux.Handle("/ui/", frontend.Handler(...))`).
- Vite's default `base` is `/`, which produces `<script src="/assets/..."` in
  the built `index.html` — these paths would resolve to `/assets/...` at the
  host root, NOT `/ui/assets/...` where the daemon serves them. The page
  loads but every asset 404s.
- `base: './'` produces relative paths like `<script src="./assets/..."`
  which resolve against the page URL. Under `/ui/` that becomes
  `/ui/assets/...`, which is what the daemon serves.

The change is correct and load-bearing — without it, the embedded UI is
broken at runtime. Commit it.

**Step 1: Confirm the only working-tree changes are the planned ones**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && git status`
Expected (after Tasks 1 and 2 have been committed): only `web/vite.config.ts`
modified. If `docs/remaining-features.md` is still showing as modified, that
means Task 1 or Task 2 is incomplete — finish them first; this task does
NOT touch that file.

**Step 2: Confirm the diff matches the investigation**

Run: `git diff web/vite.config.ts`
Expected: the 4-line addition introducing `base: './'` plus its comment, with
no other changes.

**Step 3: Stage and commit**

```
git add web/vite.config.ts
git commit -m "$(cat <<'EOF'
fix(ui): set vite base to ./ for /ui/ mount prefix

The embedded UI is served at /ui/ by cmd/daemon.go (lines 301
and 308). Vite's default base of "/" produces absolute asset
paths like /assets/index-<hash>.js, which the daemon does not
serve at the host root and which therefore 404 when index.html
is loaded under /ui/.

Setting base: './' produces page-relative asset paths
(./assets/index-<hash>.js), which resolve against the current
URL — so under /ui/ they correctly become /ui/assets/...,
matching what the daemon serves.

Verified by inspection of the built dist/ output (asset hrefs
in index.html are relative).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

**Alternative (only if the developer's investigation contradicts the
findings above):** revert with `git checkout -- web/vite.config.ts` and add
a one-line entry to `docs/remaining-features.md` describing the divergence
so a follow-up plan can address it. This branch is NOT expected — the
investigation above is complete and the daemon code matches the comment's
claim.

## Verification Checklist

After all three tasks land:

- [ ] `cd /home/kazw/Work/WorkFort/nexus/lead && git status` → clean working
      tree (no modified files).
- [ ] `cd tests/e2e && go vet ./...` → no diagnostics.
- [ ] `mise run e2e` from the repo root → previously-FAILing backup and
      metrics tests now SKIP cleanly when caps are unset, or PASS when caps
      are set; no regressions in other tests.
- [ ] `git log --oneline -5` shows three new commits with correct
      `Co-Authored-By` trailers, no `!` markers, no `BREAKING CHANGE:`
      footers.
- [ ] `docs/remaining-features.md` no longer mentions DEF-1 or DEF-2 and
      the parent "Known Defects: Missing `t.Skip` Guards" section is removed
      (it had only those two children).
- [ ] `web/vite.config.ts` carries `base: './'` on master.
