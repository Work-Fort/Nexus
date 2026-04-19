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
