// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Work-Fort/nexus-e2e/harness"
)

// requireNetworking skips the test if the networking helpers in build/
// are not available (they need caps from dev-setcap-loop).
func requireNetworking(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"nexus-netns", "nexus-cni-exec"} {
		p, err := filepath.Abs(filepath.Join("..", "..", "build", bin))
		if err != nil {
			t.Skipf("cannot resolve build/%s: %v", bin, err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Skipf("build/%s not found (run mise run build and dev-setcap-loop): %v", bin, err)
		}
	}
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
