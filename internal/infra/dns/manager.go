// SPDX-License-Identifier: GPL-2.0-or-later

// Package dns manages internal DNS for VM name resolution via CoreDNS.
package dns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// Config holds DNS manager configuration.
type Config struct {
	CoreDNSBin string   // path to coredns binary
	DNSHelper  string   // path to nexus-dns helper (raises cap_net_bind_service)
	GatewayIP  string   // bridge gateway IP (e.g. "172.16.0.1")
	StateDir   string   // persistent dir for Corefile + hosts
	RuntimeDir string   // runtime dir for per-VM resolv.conf files
	Upstreams  []string // upstream DNS servers (nil = auto-detect)
}

// Manager manages CoreDNS and the hosts file for internal DNS.
type Manager struct {
	cfg     Config
	cmd     *exec.Cmd
	mu      sync.Mutex
	records map[string]string // name -> IP
}

// New creates a DNS manager. Call Start() to launch CoreDNS.
func New(cfg Config) (*Manager, error) {
	if cfg.CoreDNSBin != "" {
		resolved, err := exec.LookPath(cfg.CoreDNSBin)
		if err != nil {
			return nil, fmt.Errorf("coredns binary not found at %q: %w", cfg.CoreDNSBin, err)
		}
		cfg.CoreDNSBin = resolved
	}
	if cfg.DNSHelper != "" {
		if _, err := exec.LookPath(cfg.DNSHelper); err != nil {
			return nil, fmt.Errorf("dns helper not found at %q: %w", cfg.DNSHelper, err)
		}
	}
	if err := os.MkdirAll(cfg.StateDir, 0755); err != nil {
		return nil, fmt.Errorf("create dns state dir: %w", err)
	}
	if err := os.MkdirAll(cfg.RuntimeDir, 0755); err != nil {
		return nil, fmt.Errorf("create dns runtime dir: %w", err)
	}
	if len(cfg.Upstreams) == 0 {
		cfg.Upstreams = parseUpstreams()
	}
	return &Manager{
		cfg:     cfg,
		records: make(map[string]string),
	}, nil
}

// Start writes the Corefile and launches the CoreDNS process.
func (m *Manager) Start(ctx context.Context) error {
	if err := m.writeCorefile(); err != nil {
		return fmt.Errorf("write corefile: %w", err)
	}
	if err := m.writeHostsFile(); err != nil {
		return fmt.Errorf("write initial hosts: %w", err)
	}

	if m.cfg.CoreDNSBin == "" {
		return nil // no binary configured, skip process start
	}

	corefilePath := filepath.Join(m.cfg.StateDir, "Corefile")
	corednsArgs := []string{"-conf", corefilePath, "-dns.port", "53"}
	if m.cfg.DNSHelper != "" {
		// nexus-dns <coredns-binary> [args...]
		args := append([]string{m.cfg.CoreDNSBin}, corednsArgs...)
		m.cmd = exec.CommandContext(ctx, m.cfg.DNSHelper, args...)
	} else {
		m.cmd = exec.CommandContext(ctx, m.cfg.CoreDNSBin, corednsArgs...)
	}
	m.cmd.Stdout = os.Stderr // CoreDNS logs to stdout
	m.cmd.Stderr = os.Stderr

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("start coredns: %w", err)
	}

	// Monitor in background.
	go func() {
		if err := m.cmd.Wait(); err != nil {
			log.Warn("coredns exited", "err", err)
		}
	}()

	log.Info("coredns started", "pid", m.cmd.Process.Pid, "gateway", m.cfg.GatewayIP)
	return nil
}

// Stop gracefully shuts down CoreDNS.
func (m *Manager) Stop() error {
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	if err := m.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return nil // already exited
	}

	done := make(chan struct{})
	go func() {
		m.cmd.Process.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		m.cmd.Process.Kill()
		<-done
	}
	return nil
}

// AddRecord registers a VM name->IP mapping in the hosts file.
func (m *Manager) AddRecord(_ context.Context, name, ip string) error {
	return m.addRecord(name, ip)
}

func (m *Manager) addRecord(name, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[name] = ip
	return m.writeHostsFile()
}

// RemoveRecord removes a VM's DNS record from the hosts file.
func (m *Manager) RemoveRecord(_ context.Context, name string) error {
	return m.removeRecord(name)
}

func (m *Manager) removeRecord(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, name)
	return m.writeHostsFile()
}

// GenerateResolvConf creates a resolv.conf file for a VM and returns its path.
func (m *Manager) GenerateResolvConf(vmID string, cfg *domain.DNSConfig) (string, error) {
	servers := []string{m.cfg.GatewayIP}
	search := []string{"nexus.local"}
	if cfg != nil {
		if len(cfg.Servers) > 0 {
			servers = cfg.Servers
		}
		if len(cfg.Search) > 0 {
			search = cfg.Search
		}
	}

	var buf bytes.Buffer
	for _, s := range servers {
		fmt.Fprintf(&buf, "nameserver %s\n", s)
	}
	fmt.Fprintf(&buf, "search %s\n", strings.Join(search, " "))
	buf.WriteString("options ndots:1\n")

	path := filepath.Join(m.cfg.RuntimeDir, vmID+".resolv.conf")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("write resolv.conf for %s: %w", vmID, err)
	}
	return path, nil
}

// CleanupResolvConf removes a VM's resolv.conf file.
func (m *Manager) CleanupResolvConf(vmID string) error {
	path := filepath.Join(m.cfg.RuntimeDir, vmID+".resolv.conf")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove resolv.conf for %s: %w", vmID, err)
	}
	return nil
}

// writeHostsFile atomically writes all records to the hosts file.
// Must be called with m.mu held.
func (m *Manager) writeHostsFile() error {
	var buf bytes.Buffer
	for name, ip := range m.records {
		fmt.Fprintf(&buf, "%s %s.nexus.local %s\n", ip, name, name)
	}
	hostsPath := filepath.Join(m.cfg.StateDir, "hosts")
	tmp := hostsPath + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write hosts tmp: %w", err)
	}
	return os.Rename(tmp, hostsPath)
}

// writeCorefile generates the CoreDNS configuration file.
func (m *Manager) writeCorefile() error {
	hostsPath := filepath.Join(m.cfg.StateDir, "hosts")
	upstreams := strings.Join(m.cfg.Upstreams, " ")

	corefile := fmt.Sprintf(`nexus.local {
    bind %s
    hosts %s {
        reload 2s
        fallthrough
    }
    log
}

. {
    bind %s
    forward . %s
    log
}
`, m.cfg.GatewayIP, hostsPath, m.cfg.GatewayIP, upstreams)

	path := filepath.Join(m.cfg.StateDir, "Corefile")
	return os.WriteFile(path, []byte(corefile), 0644)
}

// parseUpstreams reads nameservers from /etc/resolv.conf.
func parseUpstreams() []string {
	return parseUpstreamsFrom("/etc/resolv.conf")
}

// parseUpstreamsFrom reads nameservers from a resolv.conf file.
func parseUpstreamsFrom(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"1.1.1.1", "8.8.8.8"}
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
			if ns != "" && ns != "127.0.0.53" { // skip systemd-resolved stub
				servers = append(servers, ns)
			}
		}
	}
	if len(servers) == 0 {
		return []string{"1.1.1.1", "8.8.8.8"}
	}
	return servers
}
