// SPDX-License-Identifier: Apache-2.0
package harness

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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

// StartDaemonWithNamespace starts a daemon reusing an existing namespace and
// XDG directory. Used for testing boot recovery after daemon crash.
func StartDaemonWithNamespace(binary, binDir, addr, namespace, xdgDir string, opts ...DaemonOption) (*Daemon, error) {
	cfg := &daemonConfig{}
	for _, o := range opts {
		o(cfg)
	}

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

// Kill sends SIGKILL to the daemon (simulates crash). Does NOT clean up
// namespace or XDG dir — those are reused by the next daemon instance.
func (d *Daemon) Kill() {
	if d.cmd.Process != nil {
		d.cmd.Process.Kill()
		d.cmd.Wait()
	}
}

// GracefulStop sends SIGTERM and waits for the daemon to exit, but does NOT
// clean up the namespace or XDG dir. Use this to test graceful shutdown
// behavior across daemon restarts.
func (d *Daemon) GracefulStop() error {
	if d.cmd.Process == nil {
		return nil
	}
	d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		d.cmd.Process.Kill()
		<-done
		return fmt.Errorf("daemon did not exit after SIGTERM")
	}
}

// XDGDir returns the XDG temp directory used by this daemon.
func (d *Daemon) XDGDir() string { return d.xdgDir }

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
	// Kill all tasks, delete all containers, remove images/snapshots, then namespace.
	// Errors are ignored — best-effort cleanup.
	out, err := exec.Command("ctr", "-n", ns, "containers", "list", "-q").Output()
	if err != nil {
		return
	}
	ids := strings.Fields(strings.TrimSpace(string(out)))
	for _, id := range ids {
		exec.Command("ctr", "-n", ns, "tasks", "kill", id).Run()
		exec.Command("ctr", "-n", ns, "tasks", "delete", id).Run()
		exec.Command("ctr", "-n", ns, "snapshots", "rm", id+"-snap").Run()
		exec.Command("ctr", "-n", ns, "containers", "delete", id).Run()
	}
	// Remove images pulled into this namespace.
	imgOut, _ := exec.Command("ctr", "-n", ns, "images", "list", "-q").Output()
	for _, img := range strings.Fields(strings.TrimSpace(string(imgOut))) {
		exec.Command("ctr", "-n", ns, "images", "remove", img).Run()
	}
	// Note: we intentionally do NOT run "content prune references" here because
	// it operates globally across namespaces and can remove content that a
	// concurrent or subsequent test still needs for image export.
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

// --- Client ---

type Client struct {
	base       string
	http       *http.Client
	mcpSession string // MCP session ID, set after MCPInit
}

func NewClient(daemonAddr string) *Client {
	return &Client{
		base: "http://" + daemonAddr,
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

// BaseURL returns the base HTTP URL of the API.
func (c *Client) BaseURL() string {
	return c.base
}

// --- Response types ---

type VM struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Tags      []string `json:"tags"`
	State     string   `json:"state"`
	Image     string   `json:"image"`
	Runtime   string   `json:"runtime"`
	IP        string   `json:"ip,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	CreatedAt       string  `json:"created_at"`
	StartedAt       *string `json:"started_at,omitempty"`
	StoppedAt       *string `json:"stopped_at,omitempty"`
	RestartPolicy   string  `json:"restart_policy"`
	RestartStrategy string  `json:"restart_strategy"`
	Shell           string  `json:"shell"`
}

type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// SSEEvent represents a parsed SSE event from the exec stream endpoint.
type SSEEvent struct {
	Type string // "stdout", "stderr", or "exit"
	Data string // raw data field
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

func (c *Client) CreateVM(name, tag string) (*VM, error) {
	tagsJSON, _ := json.Marshal([]string{tag})
	body := fmt.Sprintf(`{"name":%q,"tags":%s}`, name, tagsJSON)
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

func (c *Client) CreateVMWithImage(name, tag, image string) (*VM, error) {
	tagsJSON, _ := json.Marshal([]string{tag})
	body := fmt.Sprintf(`{"name":%q,"tags":%s,"image":%q}`, name, tagsJSON, image)
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

func (c *Client) CreateVMWithRestartPolicy(name, tag, policy, strategy string) (*VM, error) {
	tagsJSON, _ := json.Marshal([]string{tag})
	body := fmt.Sprintf(`{"name":%q,"tags":%s,"restart_policy":%q,"restart_strategy":%q}`,
		name, tagsJSON, policy, strategy)
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

func (c *Client) UpdateRestartPolicy(id, policy, strategy string) (*VM, error) {
	body := fmt.Sprintf(`{"restart_policy":%q,"restart_strategy":%q}`, policy, strategy)
	resp, err := c.put("/v1/vms/"+id+"/restart-policy", body)
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

func (c *Client) ExecStreamVM(id string, cmd []string) ([]SSEEvent, error) {
	cmdJSON, _ := json.Marshal(cmd)
	body := fmt.Sprintf(`{"cmd":%s}`, cmdJSON)
	resp, err := c.post("/v1/vms/"+id+"/exec/stream", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return parseSSEStream(resp.Body)
}

// SyncShell detects and persists the VM's root shell.
func (c *Client) SyncShell(id string) (*VM, error) {
	resp, err := c.post("/v1/vms/"+id+"/sync-shell", "")
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

func parseSSEStream(r io.Reader) ([]SSEEvent, error) {
	var events []SSEEvent
	var currentType, currentData string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			currentType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			currentData = strings.TrimPrefix(line, "data: ")
		case line == "":
			if currentType != "" {
				events = append(events, SSEEvent{Type: currentType, Data: currentData})
				currentType = ""
				currentData = ""
			}
		}
	}
	if currentType != "" {
		events = append(events, SSEEvent{Type: currentType, Data: currentData})
	}

	return events, scanner.Err()
}

// --- Console operations ---

// ConsoleSession wraps a WebSocket connection to a VM console.
type ConsoleSession struct {
	ws *websocket.Conn
}

// ConsoleVM opens a WebSocket console to the VM.
func (c *Client) ConsoleVM(id string, cols, rows int) (*ConsoleSession, error) {
	// Convert http:// to ws://
	wsURL := "ws" + strings.TrimPrefix(c.base, "http") +
		fmt.Sprintf("/v1/vms/%s/console?cols=%d&rows=%d", id, cols, rows)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial console: %w", err)
	}
	return &ConsoleSession{ws: ws}, nil
}

// Send writes data to the console stdin.
func (cs *ConsoleSession) Send(data string) error {
	return cs.ws.WriteMessage(websocket.TextMessage, []byte(data))
}

// Resize sends a resize message.
func (cs *ConsoleSession) Resize(cols, rows int) error {
	msg, _ := json.Marshal(map[string]any{"type": "resize", "cols": cols, "rows": rows})
	return cs.ws.WriteMessage(websocket.TextMessage, msg)
}

// ReadAll reads all messages until the WebSocket closes or an exit event is
// received. Returns collected output and the exit code.
func (cs *ConsoleSession) ReadAll() (output string, exitCode int, err error) {
	exitCode = -1
	for {
		msgType, data, err := cs.ws.ReadMessage()
		if err != nil {
			return output, exitCode, nil // connection closed
		}
		if msgType == websocket.TextMessage {
			var msg struct {
				Type     string `json:"type"`
				ExitCode int    `json:"exit_code"`
			}
			if json.Unmarshal(data, &msg) == nil && msg.Type == "exit" {
				return output, msg.ExitCode, nil
			}
		}
		if msgType == websocket.BinaryMessage {
			output += string(data)
		}
	}
}

// Close closes the WebSocket connection.
func (cs *ConsoleSession) Close() error {
	return cs.ws.Close()
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

// --- Backup operations ---

type ImportResponse struct {
	VM       VM       `json:"vm"`
	Warnings []string `json:"warnings,omitempty"`
}

func (c *Client) ExportVM(id string, includeDevices bool) ([]byte, error) {
	u := fmt.Sprintf("%s/v1/vms/%s/export?include_devices=%t", c.base, id, includeDevices)
	resp, err := c.http.Post(u, "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) ImportVM(archive []byte, strictDevices bool) (*ImportResponse, error) {
	u := fmt.Sprintf("%s/v1/vms/import?strict_devices=%t", c.base, strictDevices)
	resp, err := c.http.Post(u, "application/zstd", bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	var result ImportResponse
	return &result, json.NewDecoder(resp.Body).Decode(&result)
}

// --- Prometheus operations ---

type PrometheusTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

func (c *Client) PrometheusTargets() ([]PrometheusTarget, error) {
	resp, err := c.get("/v1/prometheus/targets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var targets []PrometheusTarget
	return targets, json.NewDecoder(resp.Body).Decode(&targets)
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

// --- MCP operations ---

// MCPToolResult holds the parsed content from an MCP tool call.
type MCPToolResult struct {
	Content string
	IsError bool
}

// MCPInit sends an MCP initialize request to establish a session.
// It is called automatically by MCPCall if no session exists.
func (c *Client) MCPInit() error {
	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      0,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":   map[string]any{},
			"clientInfo": map[string]any{
				"name":    "nexus-e2e",
				"version": "1.0.0",
			},
		},
	}

	body, err := json.Marshal(initReq)
	if err != nil {
		return fmt.Errorf("marshal init request: %w", err)
	}

	resp, err := c.http.Post(c.base+"/mcp", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("MCP init request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MCP init: unexpected status %d", resp.StatusCode)
	}

	// Capture the session ID from the response header.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.mcpSession = sid
	}

	return nil
}

// MCPCall invokes an MCP tool via JSON-RPC at /mcp.
// It automatically initializes the session on first call.
func (c *Client) MCPCall(toolName string, args map[string]any) (*MCPToolResult, error) {
	// Auto-initialize session if not yet done.
	if c.mcpSession == "" {
		if err := c.MCPInit(); err != nil {
			return nil, fmt.Errorf("MCP auto-init: %w", err)
		}
	}

	callReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": args,
		},
	}

	body, err := json.Marshal(callReq)
	if err != nil {
		return nil, fmt.Errorf("marshal call request: %w", err)
	}

	req, err := http.NewRequest("POST", c.base+"/mcp", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.mcpSession != "" {
		req.Header.Set("Mcp-Session-Id", c.mcpSession)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MCP call request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MCP call %s: status %d: %s", toolName, resp.StatusCode, string(respBody))
	}

	// Parse JSON-RPC response.
	var rpcResp struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("decode MCP response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("MCP JSON-RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	// Extract text content.
	var content string
	for _, c := range rpcResp.Result.Content {
		if c.Type == "text" {
			content += c.Text
		}
	}

	return &MCPToolResult{
		Content: content,
		IsError: rpcResp.Result.IsError,
	}, nil
}

// --- internal helpers ---

func (c *Client) get(path string) (*http.Response, error) {
	return c.http.Get(c.base + path)
}

func (c *Client) post(path, body string) (*http.Response, error) {
	return c.http.Post(c.base+path, "application/json", strings.NewReader(body))
}

func (c *Client) put(path, body string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, c.base+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
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
