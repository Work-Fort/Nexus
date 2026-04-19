// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Work-Fort/nexus-e2e/harness"
)

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

// startNetworkedDaemon starts a daemon with CNI networking enabled,
// using the build/ copies of network helpers that have caps from dev-setcap-loop.
func startNetworkedDaemon(t *testing.T, extraOpts ...harness.DaemonOption) (*harness.Daemon, *harness.Client) {
	t.Helper()
	requireNetworking(t)

	netnsHelper, _ := filepath.Abs("../../build/nexus-netns")
	cniExecBin, _ := filepath.Abs("../../build/nexus-cni-exec")

	opts := []harness.DaemonOption{
		harness.WithNetworkEnabled(true),
		harness.WithNetworkSubnet(e2eSubnet),
		harness.WithBridgeName(e2eBridgeName),
		harness.WithNetNSHelper(netnsHelper),
		harness.WithCNIExecBin(cniExecBin),
	}

	// Use node_exporter from build/ if available (downloaded by mise run build).
	nodeExporter, _ := filepath.Abs("../../build/node_exporter")
	if _, err := os.Stat(nodeExporter); err == nil {
		opts = append(opts, harness.WithNodeExporterPath(nodeExporter))
	}

	opts = append(opts, extraOpts...)

	return startDaemon(t, opts...)
}

func TestPrometheusTargets(t *testing.T) {
	_, c := startNetworkedDaemon(t)

	// No VMs — should return empty array.
	targets, err := c.PrometheusTargets()
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}

	// Create and start a VM.
	vm, err := c.CreateVM("metrics-test", "agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Should appear as a target.
	targets, err = c.PrometheusTargets()
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Labels["__meta_nexus_vm_name"] != "metrics-test" {
		t.Errorf("label vm_name = %q, want metrics-test", targets[0].Labels["__meta_nexus_vm_name"])
	}
	if !strings.Contains(targets[0].Targets[0], ":9100") {
		t.Errorf("target = %q, expected :9100 port", targets[0].Targets[0])
	}
	// Verify tag label is present.
	if targets[0].Labels["__meta_nexus_vm_tag_agent"] != "true" {
		t.Errorf("expected tag label agent=true, got %v", targets[0].Labels)
	}

	// Stop VM — should disappear from targets.
	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	targets, err = c.PrometheusTargets()
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets after stop, got %d", len(targets))
	}
}
