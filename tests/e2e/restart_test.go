// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Work-Fort/nexus-e2e/harness"
)

// cleanBridge removes a bridge interface (best-effort) to prevent stale
// bridges from previous test runs from interfering. Uses the nexus-cni-exec
// helper which has the required CAP_NET_ADMIN capability.
func cleanBridge(t *testing.T, bridge string) {
	t.Helper()
	cniExec := filepath.Join(binDir, "nexus-cni-exec")
	if out, err := exec.Command(cniExec, "delete-bridge", bridge).CombinedOutput(); err != nil {
		t.Logf("clean bridge %s (best-effort): %v: %s", bridge, err, out)
	}
}

// TestGracefulRestartNonePolicy verifies that a VM with restart_policy=none
// can be started after a graceful daemon restart (SIGTERM). This was broken
// when stale containerd tasks were not cleaned up on shutdown.
func TestGracefulRestartNonePolicy(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVM("test-graceful-none", "agent")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Graceful shutdown — should clean up containerd tasks.
	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	// Start second daemon on same state.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// VM should be stopped (policy=none).
	got, err := c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.State != "stopped" {
		t.Fatalf("expected state=stopped, got %s", got.State)
	}

	// The critical test: starting should succeed (no stale task blocking).
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start after restart: %v", err)
	}
	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after start: %v", err)
	}
	if got.State != "running" {
		t.Fatalf("expected state=running after start, got %s", got.State)
	}
}

// TestGracefulRestartOnBootPolicy verifies that a VM with restart_policy=on-boot
// auto-starts after a graceful daemon restart.
func TestGracefulRestartOnBootPolicy(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithRestartPolicy("test-graceful-onboot", "agent", "on-boot", "immediate")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// VM should auto-start (policy=on-boot).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if got.State == "running" {
			t.Log("VM auto-started after graceful restart (policy=on-boot)")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM not running within 10s after graceful restart (policy=on-boot)")
}

// TestGracefulRestartAlwaysPolicy verifies that a VM with restart_policy=always
// auto-starts after a graceful daemon restart.
func TestGracefulRestartAlwaysPolicy(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithRestartPolicy("test-graceful-always", "agent", "always", "immediate")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if got.State == "running" {
			t.Log("VM auto-started after graceful restart (policy=always)")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM not running within 10s after graceful restart (policy=always)")
}

// TestKill9ThenStartNonePolicy verifies that after a daemon crash (SIGKILL),
// a VM with restart_policy=none can be restarted by the user. This exercises
// the defensive stale-task cleanup in runtime.Start().
func TestKill9ThenStartNonePolicy(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVM("test-kill9-start", "agent")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// SIGKILL — no graceful shutdown, stale task left in containerd.
	d1.Kill()

	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// Wait for RestoreVMs to mark it stopped.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err == nil && got.State == "stopped" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	got, err := c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.State != "stopped" {
		t.Fatalf("expected state=stopped after kill -9 recovery, got %s", got.State)
	}

	// The critical test: starting should succeed despite the stale task.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start after kill -9 restart: %v", err)
	}
	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after start: %v", err)
	}
	if got.State != "running" {
		t.Fatalf("expected state=running after start, got %s", got.State)
	}
}

// TestNetworkMigrationOnRestart verifies that when the daemon restarts with a
// different network subnet, existing VMs get their IPs migrated to the new
// subnet (network-auto-migrate defaults to true).
func TestNetworkMigrationOnRestart(t *testing.T) {
	requireNetworkCaps(t)

	subnetA := "10.97.0.0/24"
	subnetB := "10.98.0.0/24"
	bridge := "nexmig0"

	// Clean up stale bridge from previous runs.
	cleanBridge(t, bridge)
	t.Cleanup(func() { cleanBridge(t, bridge) })

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr,
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet(subnetA),
		harness.WithBridgeName(bridge),
	)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithImage("test-net-migrate", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Get the VM's original IP and verify it's in subnet A (10.97.0.x).
	got, err := c.GetVM(vm.ID)
	if err != nil {
		d1.Stop()
		t.Fatalf("get VM: %v", err)
	}
	if !strings.HasPrefix(got.IP, "10.97.0.") {
		d1.Stop()
		t.Fatalf("expected IP in 10.97.0.0/24, got %s", got.IP)
	}
	origIP := got.IP
	t.Logf("original IP: %s", origIP)

	// Graceful shutdown — keeps namespace and XDG dir.
	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	// Restart with the SAME data dir but a DIFFERENT subnet.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir(),
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet(subnetB),
		harness.WithBridgeName(bridge),
	)
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// Wait for RestoreVMs to complete migration (poll for new IP).
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		got, err = c.GetVM(vm.ID)
		if err == nil && strings.HasPrefix(got.IP, "10.98.0.") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// VM should have been migrated to subnet B (10.98.0.x).
	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after restart: %v", err)
	}
	if !strings.HasPrefix(got.IP, "10.98.0.") {
		t.Fatalf("expected IP in 10.98.0.0/24 after migration, got %s", got.IP)
	}
	if got.IP == origIP {
		t.Fatalf("IP should have changed after subnet migration, still %s", got.IP)
	}
	t.Logf("migrated IP: %s", got.IP)

	// Start the VM and verify loopback works (network namespace is functional).
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM after migration: %v", err)
	}

	var result *harness.ExecResult
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"ip", "link", "show", "lo"})
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec ip link show lo: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("lo interface not found (exit %d): stderr=%s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "UP") {
		t.Fatalf("lo interface not UP: %s", result.Stdout)
	}
	t.Logf("lo interface after migration: %s", strings.TrimSpace(result.Stdout))
}

// TestNetworkNoMigrationSameConfig verifies that when the daemon restarts with
// the same network config, VM IPs are preserved (no unnecessary migration).
func TestNetworkNoMigrationSameConfig(t *testing.T) {
	requireNetworkCaps(t)

	subnet := "10.97.0.0/24"
	bridge := "nexnomig0"

	// Clean up stale bridge from previous runs.
	cleanBridge(t, bridge)
	t.Cleanup(func() { cleanBridge(t, bridge) })

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr,
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet(subnet),
		harness.WithBridgeName(bridge),
	)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithImage("test-net-nomigrate", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Get the VM's original IP.
	got, err := c.GetVM(vm.ID)
	if err != nil {
		d1.Stop()
		t.Fatalf("get VM: %v", err)
	}
	if !strings.HasPrefix(got.IP, "10.97.0.") {
		d1.Stop()
		t.Fatalf("expected IP in 10.97.0.0/24, got %s", got.IP)
	}
	origIP := got.IP
	t.Logf("original IP: %s", origIP)

	// Graceful shutdown — keeps namespace and XDG dir.
	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	// Restart with the SAME data dir and SAME subnet.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir(),
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet(subnet),
		harness.WithBridgeName(bridge),
	)
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// VM IP should be unchanged.
	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after restart: %v", err)
	}
	if got.IP != origIP {
		t.Fatalf("expected IP preserved as %s, got %s", origIP, got.IP)
	}
	t.Logf("IP preserved after same-config restart: %s", got.IP)
}

// wipeNetnsDir removes all network namespace files and the config hash file
// from XDG_RUNTIME_DIR to simulate a system reboot wiping /run (tmpfs).
// Namespace files are bind mounts, so they must be unmounted before deletion.
func wipeNetnsDir(t *testing.T) {
	t.Helper()
	xdgRuntime := os.Getenv("XDG_RUNTIME_DIR")
	if xdgRuntime == "" {
		xdgRuntime = fmt.Sprintf("/tmp/nexus-netns-%d", os.Getuid())
	}
	netnsDir := filepath.Join(xdgRuntime, "nexus", "netns")

	// Unmount and delete each namespace file using the helper binary
	// (which has CAP_SYS_ADMIN for unmount).
	netnsHelper := filepath.Join(binDir, "nexus-netns")
	entries, err := os.ReadDir(netnsDir)
	if err != nil {
		t.Logf("read netns dir %s: %v", netnsDir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue // skip .ipam, .cache, .cni-config-hash
		}
		nsPath := filepath.Join(netnsDir, e.Name())
		if out, err := exec.Command(netnsHelper, "delete", nsPath).CombinedOutput(); err != nil {
			t.Logf("delete netns %s: %v: %s", nsPath, err, out)
		}
	}

	// Remove the entire directory (including .ipam, .cache, .cni-config-hash).
	if err := os.RemoveAll(netnsDir); err != nil {
		t.Logf("wipe netns dir %s: %v", netnsDir, err)
	}
	t.Logf("wiped netns dir: %s", netnsDir)
}

// TestCleanRebootAlwaysPolicy simulates a full system reboot where /run (tmpfs)
// is wiped. After reboot, the network namespace files are gone but the database
// persists. A VM with restart_policy=always should auto-start because RestoreVMs
// must recreate its namespace before starting.
func TestCleanRebootAlwaysPolicy(t *testing.T) {
	requireNetworkCaps(t)

	bridge := "nexreboot0"
	cleanBridge(t, bridge)
	t.Cleanup(func() { cleanBridge(t, bridge) })

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr,
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
	)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithImageAndRestartPolicy("test-reboot-always", "agent", "docker.io/library/nginx:alpine", "always", "immediate")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Verify VM is running and has a network namespace.
	got, err := c.GetVM(vm.ID)
	if err != nil {
		d1.Stop()
		t.Fatalf("get VM: %v", err)
	}
	if got.IP == "" {
		d1.Stop()
		t.Fatal("VM has no IP after start")
	}
	t.Logf("VM running with IP %s", got.IP)

	// Graceful shutdown.
	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	// Simulate reboot: wipe runtime dirs (tmpfs contents).
	wipeNetnsDir(t)
	wipeDNSDir(t)
	cleanBridge(t, bridge)

	// Restart daemon with same persistent state but cleared runtime state.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir(),
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
		harness.WithLogLevel("info"),
	)
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// VM should auto-start (policy=always) with namespace recreated.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		got, err = c.GetVM(vm.ID)
		if err == nil && got.State == "running" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after reboot: %v", err)
	}
	if got.State != "running" {
		t.Fatalf("expected state=running after clean reboot (policy=always), got %s", got.State)
	}
	if got.IP == "" {
		t.Fatal("VM has no IP after clean reboot")
	}
	t.Logf("VM auto-started after clean reboot with IP %s", got.IP)

	// Verify VM is actually functional (not just state=running in DB).
	var result *harness.ExecResult
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"echo", "alive"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		// Try multiple log paths.
		for _, logPath := range []string{
			filepath.Join(d2.XDGDir(), "state", "nexus", "debug.log"),
			filepath.Join(d1.XDGDir(), "state", "nexus", "debug.log"),
		} {
			if logs, logErr := os.ReadFile(logPath); logErr == nil && len(logs) > 0 {
				lines := strings.Split(string(logs), "\n")
				start := 0
				if len(lines) > 30 {
					start = len(lines) - 30
				}
				t.Logf("daemon log (%s, last 30 lines):\n%s", logPath, strings.Join(lines[start:], "\n"))
				break
			} else {
				t.Logf("log not found at %s: %v", logPath, logErr)
			}
		}
		t.Fatalf("exec after clean reboot: %v", err)
	}
	t.Logf("VM exec works after clean reboot: %s", strings.TrimSpace(result.Stdout))
}

// TestCleanRebootNonePolicyManualStart simulates a full system reboot and
// verifies that a VM with restart_policy=none can be manually started
// afterward. The namespace must be recreated even though the VM isn't
// auto-started.
func TestCleanRebootNonePolicyManualStart(t *testing.T) {
	requireNetworkCaps(t)

	bridge := "nexreboot1"
	cleanBridge(t, bridge)
	t.Cleanup(func() { cleanBridge(t, bridge) })

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr,
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
	)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVM("test-reboot-none", "agent")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Verify VM is running and has a network namespace.
	got, err := c.GetVM(vm.ID)
	if err != nil {
		d1.Stop()
		t.Fatalf("get VM: %v", err)
	}
	if got.IP == "" {
		d1.Stop()
		t.Fatal("VM has no IP after start")
	}
	t.Logf("VM running with IP %s", got.IP)

	// Graceful shutdown.
	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	// Simulate reboot: wipe runtime dirs (tmpfs contents).
	wipeNetnsDir(t)
	wipeDNSDir(t)
	cleanBridge(t, bridge)

	// Restart daemon with same persistent state but cleared runtime state.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir(),
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
	)
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// VM should be stopped (policy=none, was running before "reboot").
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err = c.GetVM(vm.ID)
		if err == nil && got.State == "stopped" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.State != "stopped" {
		t.Fatalf("expected state=stopped (policy=none), got %s", got.State)
	}

	// The critical test: manually starting the VM should succeed.
	// The namespace must have been recreated during RestoreVMs.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("manual start after clean reboot: %v", err)
	}
	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after manual start: %v", err)
	}
	if got.State != "running" {
		t.Fatalf("expected state=running after manual start, got %s", got.State)
	}
	t.Logf("VM manually started after clean reboot with IP %s", got.IP)
}

// wipeDNSDir removes all per-VM resolv.conf files from XDG_RUNTIME_DIR
// to simulate a system reboot wiping /run (tmpfs).
func wipeDNSDir(t *testing.T) {
	t.Helper()
	xdgRuntime := os.Getenv("XDG_RUNTIME_DIR")
	if xdgRuntime == "" {
		xdgRuntime = fmt.Sprintf("/tmp/nexus-dns-%d", os.Getuid())
	}
	dnsDir := filepath.Join(xdgRuntime, "nexus", "dns")
	if err := os.RemoveAll(dnsDir); err != nil {
		t.Logf("wipe dns dir %s: %v", dnsDir, err)
	}
	t.Logf("wiped dns dir: %s", dnsDir)
}

// TestCleanRebootWithDNS simulates a full system reboot with DNS enabled.
// After reboot, per-VM resolv.conf files on tmpfs are gone. The migration
// code must regenerate them so VMs can start (the OCI spec bind-mounts
// the resolv.conf into the container).
func TestCleanRebootWithDNS(t *testing.T) {
	requireNetworkCaps(t)

	bridge := "nexreboot2"
	cleanBridge(t, bridge)
	t.Cleanup(func() { cleanBridge(t, bridge) })

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr,
		harness.WithNetworkEnabled(true),
		harness.WithDNSEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
		harness.WithDNSLoopback("127.0.0.102"),
	)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithImageAndRestartPolicy("test-reboot-dns", "agent", "docker.io/library/nginx:alpine", "always", "immediate")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Verify VM is running with network and DNS.
	got, err := c.GetVM(vm.ID)
	if err != nil {
		d1.Stop()
		t.Fatalf("get VM: %v", err)
	}
	if got.IP == "" {
		d1.Stop()
		t.Fatal("VM has no IP after start")
	}
	t.Logf("VM running with IP %s", got.IP)

	// Graceful shutdown.
	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	// Simulate reboot: wipe both netns and DNS dirs (both on tmpfs).
	wipeNetnsDir(t)
	wipeDNSDir(t)
	cleanBridge(t, bridge)

	// Restart daemon with same persistent state but cleared runtime state.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir(),
		harness.WithNetworkEnabled(true),
		harness.WithDNSEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
		harness.WithDNSLoopback("127.0.0.102"),
	)
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// VM should auto-start (policy=always) with namespace AND resolv.conf
	// regenerated by the migration/boot process.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		got, err = c.GetVM(vm.ID)
		if err == nil && got.State == "running" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM after reboot: %v", err)
	}
	if got.State != "running" {
		t.Fatalf("expected state=running after clean reboot with DNS, got %s", got.State)
	}
	t.Logf("VM auto-started after clean reboot with DNS, IP %s", got.IP)
}

// TestCleanRebootDNSResolution simulates a full system reboot with DNS enabled
// and verifies that CoreDNS starts correctly and VMs can resolve names. After
// a reboot, the bridge has no IP until CNI runs during migration — CoreDNS must
// not fail to bind before that happens.
func TestCleanRebootDNSResolution(t *testing.T) {
	requireNetworkCaps(t)

	bridge := "nexreboot3"
	cleanBridge(t, bridge)
	t.Cleanup(func() { cleanBridge(t, bridge) })

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr,
		harness.WithNetworkEnabled(true),
		harness.WithDNSEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
		harness.WithDNSLoopback("127.0.0.103"),
	)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithImageAndRestartPolicy("test-reboot-dnsres", "agent", "docker.io/library/nginx:alpine", "always", "immediate")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	got, err := c.GetVM(vm.ID)
	if err != nil {
		d1.Stop()
		t.Fatalf("get VM: %v", err)
	}
	t.Logf("VM running with IP %s", got.IP)

	if err := d1.GracefulStop(); err != nil {
		t.Logf("graceful stop: %v", err)
	}

	// Simulate reboot: wipe all runtime state.
	wipeNetnsDir(t)
	wipeDNSDir(t)
	cleanBridge(t, bridge)

	// Restart daemon — CoreDNS must bind successfully even though the
	// bridge has no IP yet (it gets assigned during migration).
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir(),
		harness.WithNetworkEnabled(true),
		harness.WithDNSEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
		harness.WithDNSLoopback("127.0.0.103"),
		harness.WithLogLevel("info"),
	)
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// Wait for VM to auto-start.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		got, err = c.GetVM(vm.ID)
		if err == nil && got.State == "running" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if got.State != "running" {
		t.Fatalf("expected state=running after clean reboot, got %s", got.State)
	}

	// Verify exec works at all first.
	var result *harness.ExecResult
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"echo", "hello"})
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec echo after clean reboot: %v", err)
	}
	t.Logf("exec works: %s", strings.TrimSpace(result.Stdout))

	// The critical test: DNS resolution must work from inside the VM.
	// nslookup queries the gateway IP (where CoreDNS should be listening).
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"nslookup", "test-reboot-dnsres.nexus"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("nslookup after clean reboot: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("nslookup failed (exit %d): stdout=%s stderr=%s", result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("DNS resolution works after clean reboot: %s", strings.TrimSpace(result.Stdout))
}
