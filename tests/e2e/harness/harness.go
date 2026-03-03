// SPDX-License-Identifier: Apache-2.0
package harness

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// --- Daemon ---

type daemonConfig struct {
	networkEnabled bool
	dnsEnabled     bool
	runtime        string
	drivesDir      string
}

type DaemonOption func(*daemonConfig)

func WithNetworkEnabled(enabled bool) DaemonOption {
	return func(c *daemonConfig) { c.networkEnabled = enabled }
}

func WithDNSEnabled(enabled bool) DaemonOption {
	return func(c *daemonConfig) { c.dnsEnabled = enabled }
}

func WithRuntime(runtime string) DaemonOption {
	return func(c *daemonConfig) { c.runtime = runtime }
}

func WithDrivesDir(dir string) DaemonOption {
	return func(c *daemonConfig) { c.drivesDir = dir }
}

type Daemon struct {
	cmd       *exec.Cmd
	addr      string
	xdgDir    string
	namespace string
	stderr    *bytes.Buffer
}

func StartDaemon(binary, binDir, addr string, opts ...DaemonOption) (*Daemon, error) {
	cfg := &daemonConfig{}
	for _, o := range opts {
		o(cfg)
	}

	xdgDir, err := os.MkdirTemp("", "nexus-e2e-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	namespace := randomNamespace()

	args := []string{
		"daemon",
		"--listen", addr,
		"--namespace", namespace,
		"--log-level", "disabled",
		fmt.Sprintf("--network-enabled=%t", cfg.networkEnabled),
		fmt.Sprintf("--dns-enabled=%t", cfg.dnsEnabled),
	}
	if cfg.runtime != "" {
		args = append(args, "--runtime", cfg.runtime)
	}
	if cfg.drivesDir != "" {
		args = append(args, "--drives-dir", cfg.drivesDir)
	}

	var stderrBuf bytes.Buffer

	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+xdgDir+"/config",
		"XDG_STATE_HOME="+xdgDir+"/state",
		"PATH="+binDir+":"+os.Getenv("PATH"),
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	if err := cmd.Start(); err != nil {
		os.RemoveAll(xdgDir)
		return nil, fmt.Errorf("start daemon: %w", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return &Daemon{
				cmd:       cmd,
				addr:      addr,
				xdgDir:    xdgDir,
				namespace: namespace,
				stderr:    &stderrBuf,
			}, nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	cmd.Process.Kill()
	cmd.Wait()
	os.RemoveAll(xdgDir)
	return nil, fmt.Errorf("daemon did not become ready on %s within 10s", addr)
}

func (d *Daemon) Addr() string      { return d.addr }
func (d *Daemon) Namespace() string { return d.namespace }

// StopFatal stops the daemon and fails the test if a data race was detected.
func (d *Daemon) StopFatal(t testing.TB) {
	t.Helper()
	if err := d.Stop(); err != nil {
		t.Logf("daemon stop: %v", err)
	}
	if d.stderr != nil && strings.Contains(d.stderr.String(), "DATA RACE") {
		t.Fatal("data race detected in daemon (see stderr output above)")
	}
}

func (d *Daemon) Stop() error {
	if d.cmd.Process == nil {
		return nil
	}
	d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case err := <-done:
		d.cleanup()
		return err
	case <-time.After(5 * time.Second):
		d.cmd.Process.Kill()
		<-done
		d.cleanup()
		return fmt.Errorf("daemon did not exit after SIGTERM")
	}
}

func (d *Daemon) cleanup() {
	// Best-effort containerd namespace cleanup.
	cleanupNamespace(d.namespace)
	os.RemoveAll(d.xdgDir)
}

func cleanupNamespace(ns string) {
	// Kill all tasks, delete all containers, remove namespace.
	// Errors are ignored — best-effort cleanup.
	out, err := exec.Command("ctr", "-n", ns, "containers", "list", "-q").Output()
	if err != nil {
		return
	}
	ids := strings.Fields(strings.TrimSpace(string(out)))
	for _, id := range ids {
		exec.Command("ctr", "-n", ns, "tasks", "kill", id).Run()
		exec.Command("ctr", "-n", ns, "tasks", "delete", id).Run()
		exec.Command("ctr", "-n", ns, "containers", "delete", id).Run()
	}
	exec.Command("ctr", "namespaces", "remove", ns).Run()
}

// --- Helpers ---

func FreePort() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr, nil
}

func randomNamespace() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("nexus-e2e-%x", b)
}
