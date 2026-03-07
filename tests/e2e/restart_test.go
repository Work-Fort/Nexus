// SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"testing"
	"time"

	"github.com/Work-Fort/nexus-e2e/harness"
)

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
