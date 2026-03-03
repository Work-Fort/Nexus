// SPDX-License-Identifier: Apache-2.0
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Work-Fort/nexus-e2e/harness"
)

var (
	nexusBin string // path to compiled nexus binary
	binDir   string // directory containing all helper binaries
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "nexus-e2e-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}
	projectRoot := filepath.Join(wd, "..", "..")

	// Build targets: main binary + helpers.
	targets := []struct {
		name string
		path string
	}{
		{"nexus", "."},
		{"nexus-netns", "./cmd/nexus-netns/"},
		{"nexus-cni-exec", "./cmd/nexus-cni-exec/"},
		{"nexus-quota", "./cmd/nexus-quota/"},
		{"nexus-dns", "./cmd/nexus-dns/"},
	}

	for _, t := range targets {
		binPath := filepath.Join(tmpDir, t.name)
		cmd := exec.Command("go", "build", "-race", "-o", binPath, t.path)
		cmd.Dir = projectRoot
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n", t.name, err)
			os.Exit(1)
		}
	}

	nexusBin = filepath.Join(tmpDir, "nexus")
	binDir = tmpDir
	os.Exit(m.Run())
}

// startDaemon is a test helper that starts a daemon and registers cleanup.
func startDaemon(t *testing.T, opts ...harness.DaemonOption) (*harness.Daemon, *harness.Client) {
	t.Helper()

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d, err := harness.StartDaemon(nexusBin, binDir, addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.StopFatal(t) })

	return d, harness.NewClient(addr)
}

func TestSmoke(t *testing.T) {
	_, c := startDaemon(t)
	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 0 {
		t.Errorf("expected 0 VMs, got %d", len(vms))
	}
}
