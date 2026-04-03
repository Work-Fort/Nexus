// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Work-Fort/nexus-e2e/harness"
	"github.com/gorilla/websocket"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	nexusBin string // path to compiled nexus binary
	binDir   string // directory containing all helper binaries
)

// e2eSubnet is an isolated subnet for E2E tests so they don't conflict
// with a running system daemon (which uses the default 172.16.0.0/12).
const e2eSubnet = "10.99.0.0/24"

// e2eLoopback is a separate loopback address for E2E DNS so it doesn't
// conflict with the system daemon's CoreDNS on 127.0.0.100.
const e2eLoopback = "127.0.0.101"

// e2eBridgeName is a separate bridge interface for E2E tests so they don't
// share the system daemon's nexus0 bridge.
const e2eBridgeName = "nexus-e2e"

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}
	projectRoot := filepath.Join(wd, "..", "..")

	// Build into the project tree (not /tmp) so file capabilities work.
	// /tmp is typically mounted nosuid, which silently ignores setcap.
	tmpDir, err := os.MkdirTemp(projectRoot, ".e2e-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	// Build targets: main binary + helpers.
	targets := []struct {
		name string
		path string
	}{
		{"nexus", "."},
		{"nexusctl", "./cmd/nexusctl/"},
		{"nexus-netns", "./cmd/nexus-netns/"},
		{"nexus-cni-exec", "./cmd/nexus-cni-exec/"},
		{"nexus-quota", "./cmd/nexus-quota/"},
		{"nexus-btrfs", "./cmd/nexus-btrfs/"},
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
	code := m.Run()
	os.RemoveAll(tmpDir)
	os.Exit(code)
}

// requireNetworkCaps waits up to 5s for the setcap loop to set capabilities
// on the E2E-built binaries. Networking tests require CAP_NET_ADMIN on
// nexus-cni-exec and CAP_NET_BIND_SERVICE on nexus-dns. The dev-setcap-loop.sh
// script (run with sudo in a separate terminal) sets these every 2 seconds.
func requireNetworkCaps(t *testing.T) {
	t.Helper()
	cniExec := filepath.Join(binDir, "nexus-cni-exec")
	dnsHelper := filepath.Join(binDir, "nexus-dns")

	// Verify the binary is NOT on a nosuid filesystem (caps are silently
	// ignored on nosuid mounts like /tmp).
	out, err := exec.Command("findmnt", "-n", "-o", "OPTIONS", "--target", binDir).Output()
	if err == nil && strings.Contains(string(out), "nosuid") {
		t.Fatalf("E2E binaries are on a nosuid filesystem (%s); file capabilities will not work — build to project root instead", binDir)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cniOut, err1 := exec.Command("getcap", cniExec).Output()
		dnsOut, err2 := exec.Command("getcap", dnsHelper).Output()
		if err1 == nil && strings.Contains(string(cniOut), "cap_net_admin") &&
			err2 == nil && strings.Contains(string(dnsOut), "cap_net_bind_service") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Skipf("networking capabilities not set on %s — run: sudo ./scripts/dev-setcap-loop.sh", binDir)
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

func TestCreateVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-create", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if vm.ID == "" {
		t.Fatal("expected non-empty VM ID")
	}
	if vm.Name != "test-create" {
		t.Errorf("name = %q, want %q", vm.Name, "test-create")
	}
	if vm.State != "created" {
		t.Errorf("state = %q, want %q", vm.State, "created")
	}

	// Verify it appears in list.
	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(vms))
	}
	if vms[0].ID != vm.ID {
		t.Errorf("list VM ID = %q, want %q", vms[0].ID, vm.ID)
	}
}

func TestCreateVMWithInit(t *testing.T) {
	_, c := startDaemon(t)

	// Use a multi-layer image to exercise chain ID computation
	// in DetectDistro (single-layer images mask the bug since
	// diffID == chainID for the first layer).
	vm, err := c.CreateVMWithInit("test-init", "docker.io/library/node:22-alpine")
	if err != nil {
		t.Fatalf("create VM with init: %v", err)
	}
	if vm.ID == "" {
		t.Fatal("expected non-empty VM ID")
	}
	if vm.State != "created" {
		t.Errorf("state = %q, want %q", vm.State, "created")
	}
}

func TestInitOpenRC(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithDNSEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithDNSLoopback(e2eLoopback), harness.WithBridgeName(e2eBridgeName))

	vm, err := c.CreateVMWithInit("test-openrc", "docker.io/library/alpine:latest")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// The init script installs OpenRC (apk add) then exec's /sbin/init.
	// Wait for rc-status to succeed, which means OpenRC booted.
	var result *harness.ExecResult
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"rc-status"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		t.Fatalf("exec rc-status: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("rc-status exit code = %d, want 0 (stderr: %s)", result.ExitCode, result.Stderr)
	}
	t.Logf("rc-status output:\n%s", result.Stdout)
}

func TestInitSystemD(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithDNSEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithDNSLoopback(e2eLoopback), harness.WithBridgeName(e2eBridgeName))

	vm, err := c.CreateVMWithInit("test-systemd", "docker.io/library/ubuntu:latest")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// The init script installs systemd (apt-get install systemd-sysv dbus)
	// then exec's /lib/systemd/systemd. The apt-get can take 2-3 minutes
	// on a cold cache. Wait for systemctl is-system-running to report
	// "running" or "degraded" (degraded means some non-critical units failed).
	var result *harness.ExecResult
	var status string
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"systemctl", "is-system-running"})
		if err == nil {
			status = strings.TrimSpace(result.Stdout)
			if status == "running" || status == "degraded" {
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		t.Fatalf("exec systemctl: %v", err)
	}
	if status != "running" && status != "degraded" {
		t.Fatalf("systemctl is-system-running = %q, want running or degraded", status)
	}
	t.Logf("systemd status: %s", status)
}

func TestStartStopVM(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine because its master process stays alive, unlike
	// plain alpine whose /bin/sh exits immediately with NullIO.
	vm, err := c.CreateVMWithImage("test-startstop", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	got, err := c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.State != "running" {
		t.Errorf("state after start = %q, want %q", got.State, "running")
	}

	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop VM: %v", err)
	}

	got, err = c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.State != "stopped" {
		t.Errorf("state after stop = %q, want %q", got.State, "stopped")
	}
}

func TestExecVM(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine because its master process stays alive, unlike
	// plain alpine whose /bin/sh exits immediately with NullIO.
	vm, err := c.CreateVMWithImage("test-exec", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// The container task may need a moment to initialize.
	var result *harness.ExecResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"uname", "-r"})
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", result.ExitCode, result.Stderr)
	}
	if result.Stdout == "" {
		t.Error("expected non-empty stdout from uname -r")
	}
	t.Logf("guest kernel: %s", result.Stdout)
}

func TestOutboundConnectivity(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithBridgeName(e2eBridgeName))

	vm, err := c.CreateVMWithImage("test-ping", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Wait for the container to be ready, then ping an external IP.
	var result *harness.ExecResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"ping", "-c", "1", "-W", "2", "8.8.8.8"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec ping: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ping failed (exit %d): stdout=%s stderr=%s", result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("ping output: %s", result.Stdout)
}

func TestOutboundTCP(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithBridgeName(e2eBridgeName))

	vm, err := c.CreateVMWithImage("test-tcp", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Wait for networking to come up, then test TCP connectivity to 1.1.1.1:443.
	var result *harness.ExecResult
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"nc", "-z", "-w", "3", "1.1.1.1", "443"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec nc: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("TCP connect failed (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("TCP outbound OK: nc -z 1.1.1.1 443 succeeded")
}

func TestLoopbackInterface(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithBridgeName(e2eBridgeName))

	vm, err := c.CreateVMWithImage("test-lo", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Wait for exec readiness.
	var result *harness.ExecResult
	deadline := time.Now().Add(5 * time.Second)
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
	t.Logf("lo interface: %s", strings.TrimSpace(result.Stdout))

	// Verify 127.0.0.1 is reachable.
	result, err = c.ExecVM(vm.ID, []string{"ping", "-c", "1", "-W", "2", "127.0.0.1"})
	if err != nil {
		t.Fatalf("exec ping 127.0.0.1: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ping 127.0.0.1 failed (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("loopback ping OK: %s", strings.TrimSpace(result.Stdout))
}

func TestDNSResolution(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithDNSEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithDNSLoopback(e2eLoopback), harness.WithBridgeName(e2eBridgeName))

	vm, err := c.CreateVMWithImage("test-dns", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Test 1: VM can resolve external domains via nexus-dns on the gateway.
	// This verifies the INPUT chain allows VM → host DNS traffic.
	var result *harness.ExecResult
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"nslookup", "example.com"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec nslookup: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("DNS resolution failed (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("DNS external resolution OK")

	// Test 2: VM can resolve its own local hostname (vm-name.nexus).
	// Retry because CoreDNS reloads the hosts file every 2s.
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"nslookup", "test-dns.nexus"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		t.Fatalf("exec nslookup local: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("local DNS resolution failed (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("DNS local resolution OK: %s", result.Stdout)
}

func TestVanityDomainDNS(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t,
		harness.WithNetworkEnabled(true),
		harness.WithDNSEnabled(true),
		harness.WithNetworkSubnet(e2eSubnet),
		harness.WithDNSLoopback(e2eLoopback),
		harness.WithBridgeName(e2eBridgeName),
		harness.WithDNSDomains("nexus,test-vanity"),
	)

	vm, err := c.CreateVMWithImage("vanity-vm", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Wait for CoreDNS to reload the hosts file (2s interval).
	time.Sleep(3 * time.Second)

	// Test 1: VM resolves its own name via the vanity domain.
	var result *harness.ExecResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"nslookup", "vanity-vm.test-vanity"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		t.Fatalf("exec nslookup vanity: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("vanity domain resolution failed in VM (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("VM vanity domain resolution OK: %s", result.Stdout)

	// Test 2: VM resolves via the default .nexus domain too.
	result, err = c.ExecVM(vm.ID, []string{"nslookup", "vanity-vm.nexus"})
	if err != nil {
		t.Fatalf("exec nslookup nexus: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf(".nexus resolution failed in VM (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("VM .nexus domain resolution OK: %s", result.Stdout)

	// Test 3: Host resolves VM via loopback for .nexus domain.
	loopback := "@" + e2eLoopback
	out, digErr := exec.Command("dig", "+short", loopback, "vanity-vm.nexus").CombinedOutput()
	if digErr != nil {
		t.Fatalf("dig vanity-vm.nexus %s: %v: %s", loopback, digErr, out)
	}
	resolved := strings.TrimSpace(string(out))
	if resolved == "" || !strings.Contains(resolved, ".") {
		t.Fatalf("host loopback .nexus resolution returned no IP: %q", resolved)
	}
	t.Logf("Host loopback .nexus resolution OK: vanity-vm.nexus → %s", resolved)

	// Test 4: Host resolves VM via loopback for vanity domain.
	out, digErr = exec.Command("dig", "+short", loopback, "vanity-vm.test-vanity").CombinedOutput()
	if digErr != nil {
		t.Fatalf("dig vanity-vm.test-vanity %s: %v: %s", loopback, digErr, out)
	}
	resolved2 := strings.TrimSpace(string(out))
	if resolved2 == "" || !strings.Contains(resolved2, ".") {
		t.Fatalf("host loopback vanity resolution returned no IP: %q", resolved2)
	}
	if resolved != resolved2 {
		t.Errorf("loopback IPs differ: .nexus=%s vanity=%s", resolved, resolved2)
	}
	t.Logf("Host loopback vanity resolution OK: vanity-vm.test-vanity → %s", resolved2)
}

func TestHTTPDownload(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithDNSEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithDNSLoopback(e2eLoopback), harness.WithBridgeName(e2eBridgeName))

	vm, err := c.CreateVMWithImage("test-http", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// End-to-end: DNS resolution + TCP connection + HTTP download.
	// Tests the full stack: INPUT (DNS), FORWARD (TCP), NAT (masquerade).
	var result *harness.ExecResult
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "/dev/null", "--timeout=5", "http://example.com"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec wget: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("wget failed (exit %d): stdout=%s stderr=%s",
			result.ExitCode, result.Stdout, result.Stderr)
	}
	t.Logf("HTTP download OK: wget http://example.com succeeded")
}

func TestDeleteVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-delete", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete VM: %v", err)
	}

	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 0 {
		t.Errorf("expected 0 VMs after delete, got %d", len(vms))
	}
}

func TestDeleteRunningVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-delrunning", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// The API auto-stops running VMs before deleting them.
	if err := c.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete running VM: %v", err)
	}

	vms, err := c.ListVMs()
	if err != nil {
		t.Fatalf("list VMs: %v", err)
	}
	if len(vms) != 0 {
		t.Errorf("expected 0 VMs after delete, got %d", len(vms))
	}
}

func TestCreateDuplicateName(t *testing.T) {
	_, c := startDaemon(t)

	_, err := c.CreateVM("test-dup", "agent")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err = c.CreateVM("test-dup", "agent")
	if err == nil {
		t.Fatal("expected error creating duplicate name, got nil")
	}
}

func TestCreateDrive(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDrive("test-drive", "1G", "/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if d.ID == "" {
		t.Fatal("expected non-empty drive ID")
	}
	if d.Name != "test-drive" {
		t.Errorf("name = %q, want %q", d.Name, "test-drive")
	}

	drives, err := c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(drives) != 1 {
		t.Fatalf("expected 1 drive, got %d", len(drives))
	}
}

func TestAttachDetachDrive(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-drive-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDrive("test-attach", "512M", "/mnt/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}

	if err := c.AttachDrive(d.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// Verify drive shows vm_id.
	got, err := c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(got) != 1 || got[0].VMID == nil || *got[0].VMID != vm.ID {
		t.Errorf("drive should show vm_id=%s after attach", vm.ID)
	}

	if err := c.DetachDrive(d.ID); err != nil {
		t.Fatalf("detach drive: %v", err)
	}

	got, err = c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(got) != 1 || got[0].VMID != nil {
		t.Error("drive should have nil vm_id after detach")
	}
}

func TestDeleteAttachedDrive(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-delattach-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDrive("test-delattach", "256M", "/mnt/x")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}

	if err := c.AttachDrive(d.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	err = c.DeleteDrive(d.ID)
	if err == nil {
		t.Fatal("expected error deleting attached drive, got nil")
	}

	// Clean up.
	c.DetachDrive(d.ID)
	c.DeleteDrive(d.ID)
}

func TestDriveInVM(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine so the container stays alive for exec.
	vm, err := c.CreateVMWithImage("test-driveinvm", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDrive("test-visible", "256M", "/mnt/testdrive")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}

	if err := c.AttachDrive(d.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	result, err := c.ExecVM(vm.ID, []string{"mount"})
	if err != nil {
		t.Fatalf("exec mount: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("mount exit code = %d, stderr: %s", result.ExitCode, result.Stderr)
	}
	t.Logf("mount output:\n%s", result.Stdout)

	// Stop + cleanup.
	c.StopVM(vm.ID)
}

func TestDeleteDrive(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDrive("test-deldrive", "128M", "/data")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}
	if err := c.DeleteDrive(d.ID); err != nil {
		t.Fatalf("delete drive: %v", err)
	}

	drives, err := c.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	if len(drives) != 0 {
		t.Errorf("expected 0 drives after delete, got %d", len(drives))
	}
}

func TestCreateDevice(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDevice("test-dev", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if d.ID == "" {
		t.Fatal("expected non-empty device ID")
	}

	devices, err := c.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
}

func TestAttachDetachDevice(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-dev-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDevice("test-devattach", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := c.AttachDevice(d.ID, vm.ID); err != nil {
		t.Fatalf("attach device: %v", err)
	}

	devices, err := c.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 1 || devices[0].VMID == nil || *devices[0].VMID != vm.ID {
		t.Errorf("device should show vm_id=%s after attach", vm.ID)
	}

	if err := c.DetachDevice(d.ID); err != nil {
		t.Fatalf("detach device: %v", err)
	}
}

func TestDeleteAttachedDevice(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-devdelatt-vm", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	d, err := c.CreateDevice("test-devdelatt", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}

	if err := c.AttachDevice(d.ID, vm.ID); err != nil {
		t.Fatalf("attach device: %v", err)
	}

	err = c.DeleteDevice(d.ID)
	if err == nil {
		t.Fatal("expected error deleting attached device, got nil")
	}

	// Clean up.
	c.DetachDevice(d.ID)
	c.DeleteDevice(d.ID)
}

func TestDeleteDevice(t *testing.T) {
	_, c := startDaemon(t)

	d, err := c.CreateDevice("test-devdel", "/dev/null", "/dev/null", "rwm")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := c.DeleteDevice(d.ID); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	devices, err := c.ListDevices()
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices after delete, got %d", len(devices))
	}
}

func TestVMEnvVars(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithBridgeName(e2eBridgeName))

	// Step 1: Create VM with env vars.
	env := map[string]string{"MY_VAR": "hello", "OTHER": "world"}
	vm, err := c.CreateVMWithEnv("test-env", "agent", "docker.io/library/nginx:alpine", env)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Step 2: Start and verify env var via exec.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	var result *harness.ExecResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"printenv", "MY_VAR"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec printenv MY_VAR: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "hello" {
		t.Fatalf("MY_VAR = %q, want %q", got, "hello")
	}

	// Step 3: Check GetVM response has correct env vars.
	got, err := c.GetVM(vm.ID)
	if err != nil {
		t.Fatalf("get VM: %v", err)
	}
	if got.Env["MY_VAR"] != "hello" || got.Env["OTHER"] != "world" {
		t.Fatalf("env = %v, want MY_VAR=hello OTHER=world", got.Env)
	}

	// Step 4: Stop VM and update env (replace, not merge).
	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop VM: %v", err)
	}
	newEnv := map[string]string{"MY_VAR": "updated", "NEW_KEY": "new_value"}
	if _, err := c.UpdateEnv(vm.ID, newEnv); err != nil {
		t.Fatalf("update env: %v", err)
	}

	// Step 5: Start again and verify updated env.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM after env update: %v", err)
	}

	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"printenv", "MY_VAR"})
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec printenv MY_VAR after update: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "updated" {
		t.Fatalf("MY_VAR = %q after update, want %q", got, "updated")
	}

	// Step 6: Verify OTHER is gone (replaced, not merged) and NEW_KEY exists.
	result, err = c.ExecVM(vm.ID, []string{"printenv", "OTHER"})
	if err == nil && result.ExitCode == 0 {
		t.Fatalf("OTHER should be gone after env replace, but got: %q", result.Stdout)
	}

	result, err = c.ExecVM(vm.ID, []string{"printenv", "NEW_KEY"})
	if err != nil {
		t.Fatalf("exec printenv NEW_KEY: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "new_value" {
		t.Fatalf("NEW_KEY = %q, want %q", got, "new_value")
	}
}

func TestGetNonexistentVM(t *testing.T) {
	_, c := startDaemon(t)

	_, err := c.GetVM("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent VM, got nil")
	}
	var apiErr *harness.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Status != 404 {
		t.Errorf("status = %d, want 404", apiErr.Status)
	}
}

func TestStartAlreadyRunningVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-doublestart", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("first start: %v", err)
	}

	// Second start — should return a conflict error.
	err = c.StartVM(vm.ID)
	t.Logf("second start result: %v", err)

	// Clean up.
	c.StopVM(vm.ID)
}

func TestStopAlreadyStopped(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-doublestop", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Stop a VM that was never started.
	err = c.StopVM(vm.ID)
	t.Logf("stop created (not started) VM result: %v", err)
}

func TestInvalidCreatePayload(t *testing.T) {
	_, c := startDaemon(t)

	// Missing name — should fail validation.
	resp, err := c.RawRequest("POST", "/v1/vms", strings.NewReader(`{"tags":["agent"]}`))
	if err != nil {
		t.Fatalf("raw request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 201 {
		t.Error("expected non-201 for missing name")
	}

	// Invalid tag name.
	resp, err = c.RawRequest("POST", "/v1/vms", strings.NewReader(`{"name":"bad","tags":["inv@lid!"]}`))
	if err != nil {
		t.Fatalf("raw request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 201 {
		t.Error("expected non-201 for invalid tag")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	_, c := startDaemon(t)

	// Create VM with nginx:alpine (stays alive for exec).
	// Note: drive export/import requires btrfs storage. This E2E test
	// validates the core VM + image round-trip without drives. The full
	// drive round-trip is covered by the integration test in app/.
	vm, err := c.CreateVMWithImage("test-backup", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// Export a created (not running) VM.
	archive, err := c.ExportVM(vm.ID, false)
	if err != nil {
		t.Fatalf("export VM: %v", err)
	}
	if len(archive) == 0 {
		t.Fatal("expected non-empty archive")
	}
	t.Logf("archive size: %d bytes", len(archive))

	// Delete original VM to free the name.
	if err := c.DeleteVM(vm.ID); err != nil {
		t.Fatalf("delete original VM: %v", err)
	}

	// Import from archive.
	imported, err := c.ImportVM(archive, false)
	if err != nil {
		t.Fatalf("import VM: %v", err)
	}
	if imported.VM.Name != "test-backup" {
		t.Errorf("imported name = %q, want %q", imported.VM.Name, "test-backup")
	}
	if imported.VM.State != "created" {
		t.Errorf("imported state = %q, want %q", imported.VM.State, "created")
	}

	// Start imported VM and verify it works.
	if err := c.StartVM(imported.VM.ID); err != nil {
		t.Fatalf("start imported VM: %v", err)
	}
	var result *harness.ExecResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(imported.VM.ID, []string{"uname", "-r"})
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exec exit code = %d, stderr: %s", result.ExitCode, result.Stderr)
	}
	t.Logf("imported VM kernel: %s", result.Stdout)

	// Clean up.
	c.StopVM(imported.VM.ID)
}

func TestCrashRestart(t *testing.T) {
	d, c := startDaemon(t)

	// Use nginx:alpine so the process stays alive for the external kill.
	// Plain alpine with NullIO exits immediately, leaving no task to kill.
	vm, err := c.CreateVMWithImage("test-crash-restart", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if _, err := c.UpdateRestartPolicy(vm.ID, "always", "immediate"); err != nil {
		t.Fatalf("update restart policy: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Give the task a moment to fully initialize before killing it.
	time.Sleep(1 * time.Second)

	// Kill the containerd task externally.
	killCmd := exec.Command("ctr", "-n", d.Namespace(), "tasks", "kill", vm.ID, "--signal", "SIGKILL")
	if out, err := killCmd.CombinedOutput(); err != nil {
		t.Fatalf("ctr tasks kill: %v: %s", err, out)
	}

	// Wait for the crash monitor to restart the VM.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			t.Fatalf("get VM: %v", err)
		}
		if got.State == "running" {
			t.Log("VM restarted after crash")
			return // success
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM did not restart within 10s after task kill")
}

func TestBootRecoveryKill9(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	// Start first daemon instance.
	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVMWithRestartPolicy("test-boot-recovery", "agent", "always", "immediate")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Kill the daemon with SIGKILL (simulates crash — no graceful shutdown).
	d1.Kill()

	// Start a second daemon on the same addr, namespace, and state dir.
	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// The boot recovery should have restarted the VM.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if got.State == "running" {
			t.Log("VM restored after daemon kill -9")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM not restored to running within 10s after daemon restart")
}

func TestNoPolicyCleanupKill9(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d1, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	// Default policy is "none".
	vm, err := c.CreateVM("test-no-policy-cleanup", "agent")
	if err != nil {
		d1.Stop()
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		d1.Stop()
		t.Fatalf("start VM: %v", err)
	}

	// Verify it's running.
	got, err := c.GetVM(vm.ID)
	if err != nil || got.State != "running" {
		d1.Stop()
		t.Fatalf("VM should be running, state=%s err=%v", got.State, err)
	}

	d1.Kill()

	d2, err := harness.StartDaemonWithNamespace(nexusBin, binDir, addr, d1.Namespace(), d1.XDGDir())
	if err != nil {
		t.Fatalf("start second daemon: %v", err)
	}
	defer d2.StopFatal(t)

	// The boot recovery should have marked the VM as stopped.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.GetVM(vm.ID)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if got.State == "stopped" {
			t.Log("VM correctly marked as stopped after daemon kill -9 (policy=none)")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("VM not marked as stopped within 10s after daemon restart")
}

func TestExecStream(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine because its master process stays alive.
	vm, err := c.CreateVMWithImage("test-stream", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Wait for the container task to initialize (retry like existing exec test).
	var events []harness.SSEEvent
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		events, err = c.ExecStreamVM(vm.ID, []string{"echo", "hello world"})
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("ExecStreamVM: %v", err)
	}

	// Must have at least one stdout event and exactly one exit event.
	var gotStdout bool
	var exitEvent *harness.SSEEvent
	for i := range events {
		switch events[i].Type {
		case "stdout":
			gotStdout = true
		case "exit":
			exitEvent = &events[i]
		}
	}

	if !gotStdout {
		t.Fatal("expected at least one stdout event")
	}
	if exitEvent == nil {
		t.Fatal("expected an exit event")
	}
	if !strings.Contains(exitEvent.Data, `"exit_code":0`) && !strings.Contains(exitEvent.Data, `"exit_code": 0`) {
		t.Fatalf("expected exit_code 0, got: %s", exitEvent.Data)
	}

	// Stream exec: write to stderr.
	events, err = c.ExecStreamVM(vm.ID, []string{"sh", "-c", "echo err >&2"})
	if err != nil {
		t.Fatalf("ExecStreamVM stderr: %v", err)
	}

	var gotStderr bool
	for i := range events {
		if events[i].Type == "stderr" {
			gotStderr = true
		}
	}
	if !gotStderr {
		t.Fatal("expected at least one stderr event")
	}

	// Stream exec: non-zero exit code.
	events, err = c.ExecStreamVM(vm.ID, []string{"sh", "-c", "exit 42"})
	if err != nil {
		t.Fatalf("ExecStreamVM exit 42: %v", err)
	}

	exitEvent = nil
	for i := range events {
		if events[i].Type == "exit" {
			exitEvent = &events[i]
		}
	}
	if exitEvent == nil {
		t.Fatal("expected an exit event")
	}
	if !strings.Contains(exitEvent.Data, `"exit_code":42`) && !strings.Contains(exitEvent.Data, `"exit_code": 42`) {
		t.Fatalf("expected exit_code 42, got: %s", exitEvent.Data)
	}
}

func TestConsole(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine because its master process stays alive, unlike
	// plain alpine whose /bin/sh exits immediately with NullIO.
	vm, err := c.CreateVMWithImage("console-test", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Open console session.
	sess, err := c.ConsoleVM(vm.ID, 80, 24)
	if err != nil {
		t.Fatalf("ConsoleVM: %v", err)
	}
	defer sess.Close()

	// Send a command and exit.
	if err := sess.Send("echo hello-console\n"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := sess.Send("exit\n"); err != nil {
		t.Fatalf("send exit: %v", err)
	}

	output, exitCode, err := sess.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "hello-console") {
		t.Errorf("output missing 'hello-console', got: %q", output)
	}
}

func TestConsoleResize(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine because its master process stays alive, unlike
	// plain alpine whose /bin/sh exits immediately with NullIO.
	vm, err := c.CreateVMWithImage("console-resize", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	sess, err := c.ConsoleVM(vm.ID, 80, 24)
	if err != nil {
		t.Fatalf("ConsoleVM: %v", err)
	}
	defer sess.Close()

	// Resize should not error.
	if err := sess.Resize(120, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}

	// Verify the terminal still works after resize.
	if err := sess.Send("echo resize-ok\n"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := sess.Send("exit\n"); err != nil {
		t.Fatalf("send exit: %v", err)
	}

	output, exitCode, err := sess.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if !strings.Contains(output, "resize-ok") {
		t.Errorf("output missing 'resize-ok', got: %q", output)
	}
}

func TestConsoleCustomShell(t *testing.T) {
	_, c := startDaemon(t)

	// Use nginx:alpine because its master process stays alive, unlike
	// plain alpine whose /bin/sh exits immediately with NullIO.
	vm, err := c.CreateVMWithImage("console-shell", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// Open console with explicit command override via raw WebSocket.
	wsURL := "ws" + strings.TrimPrefix(c.BaseURL(), "http") +
		fmt.Sprintf("/v1/vms/%s/console?cmd=/bin/sh&cols=80&rows=24", vm.ID)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	ws.WriteMessage(websocket.TextMessage, []byte("echo cmd-override\n")) //nolint:errcheck
	ws.WriteMessage(websocket.TextMessage, []byte("exit\n"))              //nolint:errcheck

	// Read until exit or timeout.
	var output string
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			break
		}
		output += string(data)
		if strings.Contains(output, "cmd-override") {
			break
		}
	}

	if !strings.Contains(output, "cmd-override") {
		t.Errorf("output missing 'cmd-override', got: %q", output)
	}
}

func TestMCPVMLifecycle(t *testing.T) {
	_, c := startDaemon(t)

	// 1. vm_create via MCP (use nginx:alpine so the container stays alive for exec).
	createResult, err := c.MCPCall("vm_create", map[string]any{
		"name":  "mcp-test",
		"image": "docker.io/library/nginx:alpine",
	})
	if err != nil {
		t.Fatalf("MCP vm_create: %v", err)
	}
	if createResult.IsError {
		t.Fatalf("MCP vm_create returned error: %s", createResult.Content)
	}

	// Parse VM ID from the JSON response content.
	var createdVM struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(createResult.Content), &createdVM); err != nil {
		t.Fatalf("parse vm_create result: %v", err)
	}
	if createdVM.ID == "" {
		t.Fatal("expected non-empty VM ID from vm_create")
	}
	if createdVM.Name != "mcp-test" {
		t.Errorf("vm name = %q, want %q", createdVM.Name, "mcp-test")
	}

	// 2. vm_list via MCP.
	listResult, err := c.MCPCall("vm_list", map[string]any{})
	if err != nil {
		t.Fatalf("MCP vm_list: %v", err)
	}
	if listResult.IsError {
		t.Fatalf("MCP vm_list returned error: %s", listResult.Content)
	}
	var vmList []json.RawMessage
	if err := json.Unmarshal([]byte(listResult.Content), &vmList); err != nil {
		t.Fatalf("parse vm_list result: %v", err)
	}
	if len(vmList) == 0 {
		t.Fatal("expected non-empty VM list")
	}

	// 3. vm_get via MCP.
	getResult, err := c.MCPCall("vm_get", map[string]any{
		"id": createdVM.ID,
	})
	if err != nil {
		t.Fatalf("MCP vm_get: %v", err)
	}
	if getResult.IsError {
		t.Fatalf("MCP vm_get returned error: %s", getResult.Content)
	}

	// 4. vm_start via MCP.
	startResult, err := c.MCPCall("vm_start", map[string]any{
		"id": createdVM.ID,
	})
	if err != nil {
		t.Fatalf("MCP vm_start: %v", err)
	}
	if startResult.IsError {
		t.Fatalf("MCP vm_start returned error: %s", startResult.Content)
	}

	// 5. vm_exec via MCP (cmd is a JSON string array).
	var execResult *harness.MCPToolResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		execResult, err = c.MCPCall("vm_exec", map[string]any{
			"id":  createdVM.ID,
			"cmd": `["echo","hello from mcp"]`,
		})
		if err == nil && !execResult.IsError {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("MCP vm_exec: %v", err)
	}
	if execResult.IsError {
		t.Fatalf("MCP vm_exec returned error: %s", execResult.Content)
	}

	var execOutput struct {
		ExitCode int    `json:"exit_code"`
		Stdout   string `json:"stdout"`
	}
	if err := json.Unmarshal([]byte(execResult.Content), &execOutput); err != nil {
		t.Fatalf("parse vm_exec result: %v", err)
	}
	if execOutput.ExitCode != 0 {
		t.Errorf("exec exit code = %d, want 0", execOutput.ExitCode)
	}
	if !strings.Contains(execOutput.Stdout, "hello from mcp") {
		t.Errorf("exec stdout = %q, want to contain %q", execOutput.Stdout, "hello from mcp")
	}

	// 6. vm_stop via MCP.
	stopResult, err := c.MCPCall("vm_stop", map[string]any{
		"id": createdVM.ID,
	})
	if err != nil {
		t.Fatalf("MCP vm_stop: %v", err)
	}
	if stopResult.IsError {
		t.Fatalf("MCP vm_stop returned error: %s", stopResult.Content)
	}

	// 7. vm_delete via MCP.
	deleteResult, err := c.MCPCall("vm_delete", map[string]any{
		"id": createdVM.ID,
	})
	if err != nil {
		t.Fatalf("MCP vm_delete: %v", err)
	}
	if deleteResult.IsError {
		t.Fatalf("MCP vm_delete returned error: %s", deleteResult.Content)
	}

	// Verify VM was deleted via vm_list.
	listResult, err = c.MCPCall("vm_list", map[string]any{})
	if err != nil {
		t.Fatalf("MCP vm_list after delete: %v", err)
	}
	if err := json.Unmarshal([]byte(listResult.Content), &vmList); err != nil {
		t.Fatalf("parse vm_list result: %v", err)
	}
	if len(vmList) != 0 {
		t.Errorf("expected 0 VMs after delete, got %d", len(vmList))
	}
}

func TestMCPSchemaCompliance(t *testing.T) {
	_, c := startDaemon(t)

	schemaFile := filepath.Join("testdata", "mcp-schema-2025-03-26.json")
	schemaData, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatalf("read MCP schema: %v", err)
	}

	schemaDoc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaData)))
	if err != nil {
		t.Fatalf("parse MCP schema: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("mcp.json", schemaDoc); err != nil {
		t.Fatalf("add MCP schema resource: %v", err)
	}

	// Validate InitializeResult.
	initRefDoc, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"$ref": "mcp.json#/definitions/InitializeResult"}`))
	if err != nil {
		t.Fatalf("parse InitializeResult ref: %v", err)
	}
	if err := compiler.AddResource("init-ref.json", initRefDoc); err != nil {
		t.Fatalf("add init ref resource: %v", err)
	}
	initSchema, err := compiler.Compile("init-ref.json")
	if err != nil {
		t.Fatalf("compile InitializeResult schema: %v", err)
	}

	initResult, err := c.MCPInitRaw()
	if err != nil {
		t.Fatalf("MCP init: %v", err)
	}

	var initObj any
	if err := json.Unmarshal(initResult, &initObj); err != nil {
		t.Fatalf("unmarshal init result: %v", err)
	}
	if err := initSchema.Validate(initObj); err != nil {
		t.Errorf("InitializeResult schema validation failed:\n%v", err)
	}

	// Validate ListToolsResult.
	toolsRefDoc, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"$ref": "mcp.json#/definitions/ListToolsResult"}`))
	if err != nil {
		t.Fatalf("parse ListToolsResult ref: %v", err)
	}
	if err := compiler.AddResource("tools-ref.json", toolsRefDoc); err != nil {
		t.Fatalf("add tools ref resource: %v", err)
	}
	toolsSchema, err := compiler.Compile("tools-ref.json")
	if err != nil {
		t.Fatalf("compile ListToolsResult schema: %v", err)
	}

	toolsResult, err := c.MCPListTools()
	if err != nil {
		t.Fatalf("MCP tools/list: %v", err)
	}

	var toolsObj any
	if err := json.Unmarshal(toolsResult, &toolsObj); err != nil {
		t.Fatalf("unmarshal tools/list result: %v", err)
	}
	if err := toolsSchema.Validate(toolsObj); err != nil {
		t.Errorf("ListToolsResult schema validation failed:\n%v", err)
	}
}

// TestMCPBridgeTimeoutWhenDaemonUnreachable verifies that the MCP bridge
// exits with a non-zero status when the Nexus daemon is unreachable, rather
// than hanging indefinitely waiting for stdin. MCP clients (e.g. Claude Code)
// expect the bridge process to fail fast so they can report the error.
func TestMCPBridgeTimeoutWhenDaemonUnreachable(t *testing.T) {
	nexusctlBin := filepath.Join(binDir, "nexusctl")

	// Get a port that nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := "http://" + ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, nexusctlBin, "mcp-bridge", "--addr", deadAddr)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start mcp-bridge: %v", err)
	}

	// Send an MCP initialize request — the first message any client sends.
	initMsg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"test","version":"1.0"}}}`
	io.WriteString(stdin, initMsg+"\n")
	stdin.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("mcp-bridge exited with status 0 — should exit non-zero when daemon is unreachable")
		}
		t.Logf("mcp-bridge exited with error (expected): %v", err)
	case <-ctx.Done():
		cmd.Process.Kill()
		t.Fatal("mcp-bridge did not exit within 15 seconds when daemon is unreachable — it hung")
	}
}

func TestGracefulShutdown(t *testing.T) {
	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d, err := harness.StartDaemon(nexusBin, binDir, addr)
	if err != nil {
		t.Fatal(err)
	}

	c := harness.NewClient(addr)
	vm, err := c.CreateVM("test-shutdown", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	_ = vm

	// Send SIGTERM — daemon should exit cleanly.
	if err := d.Stop(); err != nil {
		t.Logf("daemon stop: %v", err)
	}

	// Verify daemon is no longer listening.
	_, err = c.ListVMs()
	if err == nil {
		t.Error("expected error after daemon shutdown, but request succeeded")
	}
}

func TestVMImageUpdate(t *testing.T) {
	requireNetworkCaps(t)
	_, c := startDaemon(t, harness.WithNetworkEnabled(true), harness.WithNetworkSubnet(e2eSubnet), harness.WithBridgeName(e2eBridgeName))

	const (
		oldImage = "docker.io/library/nginx:1.26-alpine"
		newImage = "docker.io/library/nginx:1.27-alpine"
	)

	// 1. Create VM with old nginx image.
	vm, err := c.CreateVMWithImage("test-imgupdate", "agent", oldImage)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}

	// 2. Create a drive mounted at nginx's html root.
	drv, err := c.CreateDrive("html-data", "64M", "/usr/share/nginx/html")
	if err != nil {
		t.Fatalf("create drive: %v", err)
	}

	// 3. Attach drive to VM.
	if err := c.AttachDrive(drv.ID, vm.ID); err != nil {
		t.Fatalf("attach drive: %v", err)
	}

	// 4. Start VM.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	// 5. Write custom index.html into the drive-backed html root.
	const customContent = "WorkFort Nexus Test Page"
	writeCmd := []string{"sh", "-c", fmt.Sprintf("echo '%s' > /usr/share/nginx/html/index.html", customContent)}
	var result *harness.ExecResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, writeCmd)
		if err == nil && result.ExitCode == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec write index.html: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("write index.html failed (exit %d): stderr=%s", result.ExitCode, result.Stderr)
	}

	// 6. Verify the custom page is served.
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "-", "http://127.0.0.1/"})
		if err == nil && result.ExitCode == 0 && strings.Contains(result.Stdout, customContent) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec wget (before update): %v", err)
	}
	if !strings.Contains(result.Stdout, customContent) {
		t.Fatalf("expected custom page before update, got: %s", result.Stdout)
	}

	// 7. Check old nginx version (informational).
	result, err = c.ExecVM(vm.ID, []string{"nginx", "-v"})
	if err == nil {
		t.Logf("nginx version before update: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		if !strings.Contains(result.Stderr, "1.26") {
			t.Logf("WARNING: expected nginx/1.26 in stderr, got: %s", result.Stderr)
		}
	} else {
		t.Logf("nginx -v exec failed (non-fatal): %v", err)
	}

	// 8. Stop VM.
	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop VM: %v", err)
	}

	// 9. Update image to new nginx version.
	updated, err := c.UpdateImage(vm.ID, newImage)
	if err != nil {
		t.Fatalf("update image: %v", err)
	}
	if updated.Image != newImage {
		t.Fatalf("expected image %q after update, got %q", newImage, updated.Image)
	}

	// 10. Start VM again with new image.
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM after image update: %v", err)
	}

	// 11. Verify custom page content survived the image update (drive preserved).
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err = c.ExecVM(vm.ID, []string{"wget", "-q", "-O", "-", "http://127.0.0.1/"})
		if err == nil && result.ExitCode == 0 && strings.Contains(result.Stdout, customContent) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("exec wget (after update): %v", err)
	}
	if !strings.Contains(result.Stdout, customContent) {
		t.Fatalf("drive data lost after image update: expected %q, got: %s", customContent, result.Stdout)
	}

	// 12. Check new nginx version (informational).
	result, err = c.ExecVM(vm.ID, []string{"nginx", "-v"})
	if err == nil {
		t.Logf("nginx version after update: stdout=%s stderr=%s", result.Stdout, result.Stderr)
		if !strings.Contains(result.Stderr, "1.27") {
			t.Logf("WARNING: expected nginx/1.27 in stderr, got: %s", result.Stderr)
		}
	} else {
		t.Logf("nginx -v exec failed (non-fatal): %v", err)
	}

	// Cleanup.
	c.StopVM(vm.ID)
}

// TestResolvedDNSSelfHeal verifies that the health check detects when
// systemd-resolved loses the DNS routing registration (e.g. Wi-Fi
// reconnect) and automatically re-registers it.
func TestResolvedDNSSelfHeal(t *testing.T) {
	requireNetworkCaps(t)

	bridge := "nexresolv0"
	loopback := "127.0.0.104"

	cleanBridge(t, bridge)
	t.Cleanup(func() { cleanBridge(t, bridge) })

	addr, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	d, err := harness.StartDaemon(nexusBin, binDir, addr,
		harness.WithNetworkEnabled(true),
		harness.WithDNSEnabled(true),
		harness.WithNetworkSubnet("10.99.0.0/24"),
		harness.WithBridgeName(bridge),
		harness.WithDNSLoopback(loopback),
		harness.WithLogLevel("info"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer d.StopFatal(t)

	c := harness.NewClient(addr)

	// Create and start a VM so the bridge gets its IP (CNI assigns it).
	vm, err := c.CreateVMWithImage("test-resolved", "agent", "docker.io/library/nginx:alpine")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}
	defer c.StopVM(vm.ID)

	// Wait for the health check to report healthy or degraded (self-healed).
	// On first startup the health check may run before the daemon's own
	// resolved.Register call, so it self-heals and reports degraded initially.
	var health *harness.HealthReport
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		health, err = c.GetHealth()
		if err == nil {
			if r, ok := health.Checks["resolved-dns"]; ok && (r.Status == "healthy" || r.Status == "degraded") {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
	if health == nil {
		t.Fatal("could not get health report")
	}
	r, ok := health.Checks["resolved-dns"]
	if !ok {
		t.Fatal("resolved-dns check not found in health report")
	}
	if r.Status == "unhealthy" {
		t.Fatalf("expected resolved-dns healthy or degraded, got unhealthy: %s", r.Message)
	}
	t.Logf("resolved-dns initial status: %s — %s", r.Status, r.Message)

	// Wait for it to settle to healthy before proceeding with the revert test.
	deadline = time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		health, err = c.GetHealth()
		if err == nil {
			if r, ok := health.Checks["resolved-dns"]; ok && r.Status == "healthy" {
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("resolved-dns settled: %s", health.Checks["resolved-dns"].Status)

	// Simulate resolved losing the registration (Wi-Fi reconnect, etc.).
	revertCmd := exec.Command("resolvectl", "revert", bridge)
	if out, err := revertCmd.CombinedOutput(); err != nil {
		t.Fatalf("resolvectl revert: %v: %s", err, out)
	}
	t.Log("reverted resolved registration — simulating Wi-Fi reconnect")

	// Wait for the health check to detect and self-heal.
	// The check runs every 30s, so we wait up to 45s.
	healed := false
	deadline = time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		health, err = c.GetHealth()
		if err == nil {
			r = health.Checks["resolved-dns"]
			// After self-heal it reports "degraded" (re-registered),
			// then on next cycle it reports "healthy" again.
			if r.Status == "degraded" || r.Status == "healthy" {
				if r.Message != "" && r.Status == "degraded" {
					t.Logf("self-healed: %s", r.Message)
					healed = true
					break
				}
				// If already back to healthy, the heal + recheck happened fast.
				if r.Status == "healthy" && healed {
					break
				}
			}
		}
		time.Sleep(2 * time.Second)
	}

	// Final check: verify DNS resolution works again.
	health, _ = c.GetHealth()
	r = health.Checks["resolved-dns"]
	if r.Status == "unhealthy" {
		t.Fatalf("resolved-dns still unhealthy after self-heal attempt: %s", r.Message)
	}
	t.Logf("final resolved-dns status: %s — %s", r.Status, r.Message)
}
