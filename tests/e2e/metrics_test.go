// SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"strings"
	"testing"
)

func TestPrometheusTargets(t *testing.T) {
	_, c := startDaemon(t)

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
