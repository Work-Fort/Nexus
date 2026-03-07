# E2E Test Suite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a full-stack E2E test suite that exercises the Nexus binary end-to-end against real containerd, Kata/runc, and btrfs.

**Architecture:** Separate Go module in `tests/e2e/` with no internal imports. Subprocess harness starts the compiled Nexus binary per test with XDG isolation and per-test containerd namespaces. Thin HTTP client wraps the REST API. Follows Sharkfin's `tests/e2e/` pattern exactly.

**Tech Stack:** Go 1.26, `net/http` (client), `os/exec` (subprocess), `testing` (stdlib), containerd (external dependency), btrfs (host filesystem)

**Reference:** Design doc at `docs/e2e-test-suite-design.md`. Sharkfin harness at `~/Work/WorkFort/sharkfin/tests/e2e/harness/harness.go`.

---

### Task 1: Create Go Module

**Files:**
- Create: `tests/e2e/go.mod`

**Step 1: Create the module directory**

```bash
mkdir -p tests/e2e/harness
```

**Step 2: Initialize the module**

```bash
cd tests/e2e && go mod init github.com/Work-Fort/nexus-e2e
```

This creates `tests/e2e/go.mod` with:
```
module github.com/Work-Fort/nexus-e2e

go 1.26.0
```

**Step 3: Commit**

```bash
git add tests/e2e/go.mod
git commit -m "test(e2e): init separate Go module for E2E tests"
```

---

### Task 2: Harness — Daemon

**Files:**
- Create: `tests/e2e/harness/harness.go`

**Step 1: Write the Daemon type and helpers**

Create `tests/e2e/harness/harness.go` with these components:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
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
```

Key differences from Sharkfin harness:
- `binDir` parameter puts helper binaries on PATH
- Random containerd namespace per daemon
- `cleanupNamespace` does best-effort `ctr` cleanup on stop
- 10s ready timeout (VM runtimes take longer than Sharkfin's chat server)
- `--network-enabled=false` and `--dns-enabled=false` by default

**Step 2: Verify it compiles**

```bash
cd tests/e2e && go build ./harness/
```

Expected: success, no output.

**Step 3: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "test(e2e): add Daemon harness with XDG isolation and namespace cleanup"
```

---

### Task 3: Harness — Client

**Files:**
- Modify: `tests/e2e/harness/harness.go`

**Step 1: Add the Client type and response structs**

Append to `tests/e2e/harness/harness.go`, adding `"encoding/json"` and `"net/http"` to imports:

```go
// --- Client ---

type Client struct {
	base string
	http *http.Client
}

func NewClient(daemonAddr string) *Client {
	return &Client{
		base: "http://" + daemonAddr,
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

// --- Response types ---

type VM struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	State     string     `json:"state"`
	Image     string     `json:"image"`
	Runtime   string     `json:"runtime"`
	IP        string     `json:"ip,omitempty"`
	Gateway   string     `json:"gateway,omitempty"`
	CreatedAt string     `json:"created_at"`
	StartedAt *string    `json:"started_at,omitempty"`
	StoppedAt *string    `json:"stopped_at,omitempty"`
}

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type Drive struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	SizeBytes uint64  `json:"size_bytes"`
	MountPath string  `json:"mount_path"`
	VMID      *string `json:"vm_id,omitempty"`
	CreatedAt string  `json:"created_at"`
}

type Device struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	HostPath      string  `json:"host_path"`
	ContainerPath string  `json:"container_path"`
	Permissions   string  `json:"permissions"`
	GID           uint32  `json:"gid"`
	VMID          *string `json:"vm_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

type APIError struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

func (e *APIError) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Title) }

// --- VM operations ---

func (c *Client) CreateVM(name, role string) (*VM, error) {
	body := fmt.Sprintf(`{"name":%q,"role":%q}`, name, role)
	resp, err := c.post("/v1/vms", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	var vm VM
	return &vm, json.NewDecoder(resp.Body).Decode(&vm)
}

func (c *Client) GetVM(id string) (*VM, error) {
	resp, err := c.get("/v1/vms/" + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var vm VM
	return &vm, json.NewDecoder(resp.Body).Decode(&vm)
}

func (c *Client) ListVMs() ([]*VM, error) {
	resp, err := c.get("/v1/vms")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var vms []*VM
	return vms, json.NewDecoder(resp.Body).Decode(&vms)
}

func (c *Client) DeleteVM(id string) error {
	resp, err := c.delete("/v1/vms/" + id)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusNoContent)
}

func (c *Client) StartVM(id string) error {
	resp, err := c.post("/v1/vms/"+id+"/start", "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusNoContent)
}

func (c *Client) StopVM(id string) error {
	resp, err := c.post("/v1/vms/"+id+"/stop", "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusNoContent)
}

func (c *Client) ExecVM(id string, cmd []string) (*ExecResult, error) {
	cmdJSON, _ := json.Marshal(cmd)
	body := fmt.Sprintf(`{"cmd":%s}`, cmdJSON)
	resp, err := c.post("/v1/vms/"+id+"/exec", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var result ExecResult
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// --- Drive operations ---

func (c *Client) CreateDrive(name, size, mountPath string) (*Drive, error) {
	body := fmt.Sprintf(`{"name":%q,"size":%q,"mount_path":%q}`, name, size, mountPath)
	resp, err := c.post("/v1/drives", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	var d Drive
	return &d, json.NewDecoder(resp.Body).Decode(&d)
}

func (c *Client) ListDrives() ([]*Drive, error) {
	resp, err := c.get("/v1/drives")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var drives []*Drive
	return drives, json.NewDecoder(resp.Body).Decode(&drives)
}

func (c *Client) DeleteDrive(id string) error {
	resp, err := c.delete("/v1/drives/" + id)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusNoContent)
}

func (c *Client) AttachDrive(id, vmID string) error {
	body := fmt.Sprintf(`{"vm_id":%q}`, vmID)
	resp, err := c.post("/v1/drives/"+id+"/attach", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusOK)
}

func (c *Client) DetachDrive(id string) error {
	resp, err := c.post("/v1/drives/"+id+"/detach", "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusOK)
}

// --- Device operations ---

func (c *Client) CreateDevice(name, hostPath, containerPath, permissions string) (*Device, error) {
	body := fmt.Sprintf(`{"name":%q,"host_path":%q,"container_path":%q,"permissions":%q}`,
		name, hostPath, containerPath, permissions)
	resp, err := c.post("/v1/devices", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	var d Device
	return &d, json.NewDecoder(resp.Body).Decode(&d)
}

func (c *Client) ListDevices() ([]*Device, error) {
	resp, err := c.get("/v1/devices")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var devices []*Device
	return devices, json.NewDecoder(resp.Body).Decode(&devices)
}

func (c *Client) DeleteDevice(id string) error {
	resp, err := c.delete("/v1/devices/" + id)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusNoContent)
}

func (c *Client) AttachDevice(id, vmID string) error {
	body := fmt.Sprintf(`{"vm_id":%q}`, vmID)
	resp, err := c.post("/v1/devices/"+id+"/attach", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusOK)
}

func (c *Client) DetachDevice(id string) error {
	resp, err := c.post("/v1/devices/"+id+"/detach", "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp, http.StatusOK)
}

// --- Raw access ---

func (c *Client) RawRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// --- internal helpers ---

func (c *Client) get(path string) (*http.Response, error) {
	return c.http.Get(c.base + path)
}

func (c *Client) post(path, body string) (*http.Response, error) {
	return c.http.Post(c.base+path, "application/json", strings.NewReader(body))
}

func (c *Client) delete(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func checkStatus(resp *http.Response, expected int) error {
	if resp.StatusCode == expected {
		return nil
	}
	var apiErr APIError
	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
		return fmt.Errorf("unexpected status %d (wanted %d)", resp.StatusCode, expected)
	}
	apiErr.Status = resp.StatusCode
	return &apiErr
}
```

Key points:
- `Client.http` has a 60s timeout — VM start/exec can be slow
- `checkStatus` parses huma error responses into `*APIError`
- `CreateDrive` takes `name, size, mountPath` to match the API
- `CreateDevice` takes all required fields from the API
- Response types mirror `handler.go` JSON shape exactly

**Step 2: Verify it compiles**

```bash
cd tests/e2e && go build ./harness/
```

Expected: success.

**Step 3: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "test(e2e): add HTTP Client to harness with VM/Drive/Device operations"
```

---

### Task 4: TestMain and Build Helpers

**Files:**
- Create: `tests/e2e/nexus_test.go`

**Step 1: Write TestMain that builds all binaries**

Create `tests/e2e/nexus_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later
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
```

Key points:
- `buildBinaries` builds the main binary AND all 4 helper binaries with `-race`
- `startDaemon` helper reduces boilerplate in every test — starts daemon, registers cleanup
- Project root is `../..` relative to `tests/e2e/`

**Step 2: Add a smoke test to verify the build works**

Add to the same file:

```go
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
```

**Step 3: Run the smoke test**

```bash
cd tests/e2e && sudo go test -v -count=1 -parallel 1 -run TestSmoke -timeout 5m .
```

Expected: PASS. The daemon starts on a free port with an empty containerd namespace, list returns 0 VMs, daemon stops cleanly.

**Step 4: Commit**

```bash
git add tests/e2e/nexus_test.go
git commit -m "test(e2e): add TestMain with binary build and smoke test"
```

---

### Task 5: VM Lifecycle Tests

**Files:**
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Write VM lifecycle tests**

Add these test functions to `nexus_test.go`:

```go
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

func TestStartStopVM(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("test-startstop", "agent")
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

	vm, err := c.CreateVM("test-exec", "agent")
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start VM: %v", err)
	}

	result, err := c.ExecVM(vm.ID, []string{"uname", "-r"})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", result.ExitCode, result.Stderr)
	}
	// The output should be a kernel version, not empty.
	if result.Stdout == "" {
		t.Error("expected non-empty stdout from uname -r")
	}
	t.Logf("guest kernel: %s", result.Stdout)
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

	err = c.DeleteVM(vm.ID)
	if err == nil {
		t.Fatal("expected error deleting running VM, got nil")
	}

	// Clean up: stop then delete.
	c.StopVM(vm.ID)
	c.DeleteVM(vm.ID)
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
```

**Step 2: Run the VM lifecycle tests**

```bash
cd tests/e2e && sudo go test -v -count=1 -parallel 1 -run 'TestCreateVM|TestStartStopVM|TestExecVM|TestDeleteVM|TestDeleteRunningVM|TestCreateDuplicateName' -timeout 10m .
```

Expected: all PASS. `TestExecVM` logs the guest kernel version. `TestDeleteRunningVM` confirms the error. `TestCreateDuplicateName` confirms the conflict error.

**Step 3: Commit**

```bash
git add tests/e2e/nexus_test.go
git commit -m "test(e2e): add VM lifecycle tests (create, start/stop, exec, delete)"
```

---

### Task 6: Drive Tests

**Files:**
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Write drive tests**

Add to `nexus_test.go`:

```go
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

	vm, err := c.CreateVM("test-driveinvm", "agent")
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
```

**Step 2: Run the drive tests**

```bash
cd tests/e2e && sudo go test -v -count=1 -parallel 1 -run 'TestCreateDrive|TestAttachDetachDrive|TestDeleteAttachedDrive|TestDriveInVM|TestDeleteDrive' -timeout 10m .
```

Expected: all PASS. `TestDriveInVM` logs mount output showing the drive is visible inside the VM.

**Step 3: Commit**

```bash
git add tests/e2e/nexus_test.go
git commit -m "test(e2e): add drive tests (create, attach/detach, delete, visible in VM)"
```

---

### Task 7: Device Tests

**Files:**
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Write device tests**

Add to `nexus_test.go`:

```go
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
```

All device tests use `/dev/null` as the host path — it exists everywhere and is safe to map.

**Step 2: Run the device tests**

```bash
cd tests/e2e && sudo go test -v -count=1 -parallel 1 -run 'TestCreateDevice|TestAttachDetachDevice|TestDeleteAttachedDevice|TestDeleteDevice' -timeout 10m .
```

Expected: all PASS.

**Step 3: Commit**

```bash
git add tests/e2e/nexus_test.go
git commit -m "test(e2e): add device tests (create, attach/detach, delete)"
```

---

### Task 8: Error Case and Signal Tests

**Files:**
- Modify: `tests/e2e/nexus_test.go`

**Step 1: Write error case and signal tests**

Add to `nexus_test.go`, adding `"errors"` and `"syscall"` to imports if not already present:

```go
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

	// Second start — should either succeed (idempotent) or return a clear error.
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
	resp, err := c.RawRequest("POST", "/v1/vms", strings.NewReader(`{"role":"agent"}`))
	if err != nil {
		t.Fatalf("raw request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 201 {
		t.Error("expected non-201 for missing name")
	}

	// Invalid role.
	resp, err = c.RawRequest("POST", "/v1/vms", strings.NewReader(`{"name":"bad","role":"invalid"}`))
	if err != nil {
		t.Fatalf("raw request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 201 {
		t.Error("expected non-201 for invalid role")
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
		// Stop sends SIGTERM and waits. A non-nil error means either
		// the daemon didn't exit in time or exited with non-zero.
		t.Logf("daemon stop: %v", err)
	}

	// Verify daemon is no longer listening.
	_, err = c.ListVMs()
	if err == nil {
		t.Error("expected error after daemon shutdown, but request succeeded")
	}
}
```

Add `"strings"` to the import block.

**Step 2: Run the error and signal tests**

```bash
cd tests/e2e && sudo go test -v -count=1 -parallel 1 -run 'TestGetNonexistent|TestStartAlready|TestStopAlready|TestInvalidCreate|TestGraceful' -timeout 10m .
```

Expected: all PASS. The `TestStartAlreadyRunningVM` and `TestStopAlreadyStopped` tests log the behavior (idempotent or error) without asserting — they document current behavior.

**Step 3: Commit**

```bash
git add tests/e2e/nexus_test.go
git commit -m "test(e2e): add error case and graceful shutdown tests"
```

---

### Task 9: Mise Integration

**Files:**
- Modify: `mise.toml`

**Step 1: Add e2e and e2e:clean tasks**

Add to the end of `mise.toml`:

```toml
[tasks.e2e]
description = "Run E2E tests (requires root, containerd, btrfs)"
depends = ["build"]
run = "cd tests/e2e && sudo go test -v -count=1 -parallel 1 -timeout 10m ."

[tasks."e2e:clean"]
description = "Clean up leaked E2E containerd namespaces"
run = """
#!/usr/bin/env bash
set -e
echo "Cleaning E2E namespaces..."
for ns in $(sudo ctr namespaces list -q | grep ^nexus-e2e- 2>/dev/null); do
  echo "  Cleaning namespace: $ns"
  for c in $(sudo ctr -n "$ns" containers list -q 2>/dev/null); do
    sudo ctr -n "$ns" tasks kill "$c" 2>/dev/null || true
    sudo ctr -n "$ns" tasks delete "$c" 2>/dev/null || true
    sudo ctr -n "$ns" containers delete "$c" 2>/dev/null || true
  done
  sudo ctr namespaces remove "$ns" 2>/dev/null || true
done
echo "E2E cleanup done"
"""
```

**Step 2: Verify the tasks are listed**

```bash
mise tasks ls | grep e2e
```

Expected:
```
e2e           Run E2E tests (requires root, containerd, btrfs)
e2e:clean     Clean up leaked E2E containerd namespaces
```

**Step 3: Commit**

```bash
git add mise.toml
git commit -m "feat: add mise e2e and e2e:clean tasks"
```

---

### Task 10: Run Full Suite and Verify

**Step 1: Run the full E2E suite via mise**

```bash
mise run e2e
```

Expected: all 20 tests pass. Output shows each test starting its own daemon, exercising the API, and shutting down.

**Step 2: Verify no leaked namespaces**

```bash
sudo ctr namespaces list -q | grep nexus-e2e
```

Expected: no output (all namespaces cleaned up).

**Step 3: Run e2e:clean just to verify it works**

```bash
mise run e2e:clean
```

Expected: "E2E cleanup done" (nothing to clean).

**Step 4: Final commit if any adjustments were needed**

If tests revealed issues that required code changes, commit those fixes:

```bash
git add -A
git commit -m "test(e2e): fix issues found during full suite run"
```

**Step 5: Merge to master**

```bash
git checkout master
git merge --ff-only <branch-name>
git checkout <branch-name>
```
