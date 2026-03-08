// SPDX-License-Identifier: GPL-2.0-or-later
package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Work-Fort/Nexus/internal/domain"
)

func TestAddAndRemoveRecord(t *testing.T) {
	stateDir := t.TempDir()
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			Domains:    []string{"nexus"},
			StateDir:   stateDir,
			RuntimeDir: runtimeDir,
		},
		records: make(map[string]string),
	}

	// Add two records
	if err := m.addRecord("web", "172.16.0.2"); err != nil {
		t.Fatalf("add web: %v", err)
	}
	if err := m.addRecord("db", "172.16.0.3"); err != nil {
		t.Fatalf("add db: %v", err)
	}

	// Verify hosts file
	data, err := os.ReadFile(filepath.Join(stateDir, "hosts"))
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "172.16.0.2 web.nexus web") {
		t.Errorf("hosts missing web entry:\n%s", content)
	}
	if !strings.Contains(content, "172.16.0.3 db.nexus db") {
		t.Errorf("hosts missing db entry:\n%s", content)
	}

	// Remove one
	if err := m.removeRecord("web"); err != nil {
		t.Fatalf("remove web: %v", err)
	}
	data, _ = os.ReadFile(filepath.Join(stateDir, "hosts"))
	content = string(data)
	if strings.Contains(content, "web") {
		t.Errorf("hosts still contains web after removal:\n%s", content)
	}
	if !strings.Contains(content, "db") {
		t.Errorf("hosts missing db after removing web:\n%s", content)
	}
}

func TestAddRecordMultiDomain(t *testing.T) {
	stateDir := t.TempDir()
	m := &Manager{
		cfg: Config{
			GatewayIP: "172.16.0.1",
			Domains:   []string{"nexus", "work-fort"},
			StateDir:  stateDir,
		},
		records: make(map[string]string),
	}
	if err := m.addRecord("web", "172.16.0.2"); err != nil {
		t.Fatalf("add web: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "hosts"))
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "172.16.0.2 web.nexus web.work-fort web") {
		t.Errorf("hosts missing multi-domain entry:\n%s", content)
	}
}

func TestGenerateResolvConfDefault(t *testing.T) {
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			Domains:    []string{"nexus"},
			RuntimeDir: runtimeDir,
		},
	}

	path, err := m.GenerateResolvConf("vm-abc", nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "nameserver 172.16.0.1") {
		t.Errorf("missing default nameserver:\n%s", content)
	}
	if !strings.Contains(content, "search nexus") {
		t.Errorf("missing default search:\n%s", content)
	}
}

func TestGenerateResolvConfCustom(t *testing.T) {
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			Domains:    []string{"nexus"},
			RuntimeDir: runtimeDir,
		},
	}

	cfg := &domain.DNSConfig{
		Servers: []string{"172.16.0.1", "8.8.8.8"},
		Search:  []string{"nexus", "example.com"},
	}
	path, err := m.GenerateResolvConf("vm-xyz", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "nameserver 172.16.0.1") {
		t.Errorf("missing first nameserver:\n%s", content)
	}
	if !strings.Contains(content, "nameserver 8.8.8.8") {
		t.Errorf("missing second nameserver:\n%s", content)
	}
	if !strings.Contains(content, "search nexus example.com") {
		t.Errorf("missing search domains:\n%s", content)
	}
}

func TestGenerateResolvConfMultiDomain(t *testing.T) {
	runtimeDir := t.TempDir()
	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			Domains:    []string{"nexus", "work-fort"},
			RuntimeDir: runtimeDir,
		},
	}
	path, err := m.GenerateResolvConf("vm-multi", nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "search nexus work-fort") {
		t.Errorf("missing multi-domain search:\n%s", content)
	}
}

func TestCleanupResolvConf(t *testing.T) {
	runtimeDir := t.TempDir()

	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			RuntimeDir: runtimeDir,
		},
	}

	path, _ := m.GenerateResolvConf("vm-cleanup", nil)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist: %v", err)
	}

	if err := m.CleanupResolvConf("vm-cleanup"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted after cleanup")
	}
}

func TestCleanupResolvConfIdempotent(t *testing.T) {
	m := &Manager{
		cfg: Config{RuntimeDir: t.TempDir()},
	}
	// Should not error even if file doesn't exist
	if err := m.CleanupResolvConf("nonexistent"); err != nil {
		t.Fatalf("cleanup nonexistent: %v", err)
	}
}

func TestWriteCorefileLoopback(t *testing.T) {
	stateDir := t.TempDir()
	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			LoopbackIP: "127.0.0.100",
			Domains:    []string{"nexus"},
			StateDir:   stateDir,
			Upstreams:  []string{"1.1.1.1", "8.8.8.8"},
		},
	}
	if err := m.writeCorefile(); err != nil {
		t.Fatalf("writeCorefile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "Corefile"))
	if err != nil {
		t.Fatalf("read corefile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "bind 127.0.0.100 172.16.0.1") {
		t.Errorf("nexus zone missing dual bind:\n%s", content)
	}
	// Verify catch-all does NOT have loopback
	lines := strings.Split(content, "\n")
	inCatchAll := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == ". {" {
			inCatchAll = true
		}
		if inCatchAll && strings.Contains(line, "bind") {
			if strings.Contains(line, "127.0.0.100") {
				t.Errorf("catch-all zone should NOT bind loopback:\n%s", content)
			}
			break
		}
	}
}

func TestWriteCorefileMultiDomain(t *testing.T) {
	stateDir := t.TempDir()
	m := &Manager{
		cfg: Config{
			GatewayIP:  "172.16.0.1",
			LoopbackIP: "127.0.0.100",
			Domains:    []string{"nexus", "work-fort"},
			StateDir:   stateDir,
			Upstreams:  []string{"1.1.1.1"},
		},
	}
	if err := m.writeCorefile(); err != nil {
		t.Fatalf("writeCorefile: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(stateDir, "Corefile"))
	content := string(data)
	if !strings.Contains(content, "nexus work-fort {") {
		t.Errorf("corefile missing multi-domain zone:\n%s", content)
	}
}

func TestWriteCorefileNoLoopback(t *testing.T) {
	stateDir := t.TempDir()
	m := &Manager{
		cfg: Config{
			GatewayIP: "172.16.0.1",
			Domains:   []string{"nexus"},
			StateDir:  stateDir,
			Upstreams: []string{"1.1.1.1"},
		},
	}
	if err := m.writeCorefile(); err != nil {
		t.Fatalf("writeCorefile: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(stateDir, "Corefile"))
	content := string(data)
	if !strings.Contains(content, "bind 172.16.0.1") {
		t.Errorf("missing gateway bind:\n%s", content)
	}
	if strings.Contains(content, "127.0.0.100") {
		t.Errorf("should not contain loopback when not configured:\n%s", content)
	}
}

func TestParseUpstreams(t *testing.T) {
	tmp := t.TempDir()
	resolvPath := filepath.Join(tmp, "resolv.conf")
	os.WriteFile(resolvPath, []byte("# comment\nnameserver 1.2.3.4\nnameserver 5.6.7.8\nsearch example.com\n"), 0644)

	got := parseUpstreamsFrom(resolvPath)
	if len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "5.6.7.8" {
		t.Errorf("parseUpstreams = %v, want [1.2.3.4 5.6.7.8]", got)
	}
}

func TestParseUpstreamsFallback(t *testing.T) {
	got := parseUpstreamsFrom("/nonexistent/resolv.conf")
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Errorf("parseUpstreams fallback = %v, want [1.1.1.1 8.8.8.8]", got)
	}
}
