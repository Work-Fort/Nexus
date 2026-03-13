// SPDX-License-Identifier: GPL-3.0-or-later

package cni

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/invoke"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// Config holds CNI adapter configuration.
type Config struct {
	BinDir     string // directory containing real CNI plugin binaries
	Subnet     string // CIDR for the bridge network (e.g. "10.88.0.0/16")
	BridgeName string // bridge interface name (default: "nexus0")
	HelperBin  string // path to the nexus-netns helper binary
	CNIExecBin string // path to the nexus-cni-exec wrapper binary
}

// netnsDir returns the directory for persistent network namespace bind-mounts.
// Uses XDG_RUNTIME_DIR (per-user tmpfs), falling back to /tmp/nexus-netns-<uid>.
func netnsDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "nexus", "netns")
	}
	return fmt.Sprintf("/tmp/nexus-netns-%d", os.Getuid())
}

// Network implements domain.Network using CNI plugins.
type Network struct {
	cni         *libcni.CNIConfig
	confList    *libcni.NetworkConfigList
	confDir     string // temp dir where we write the CNI config
	wrapperDir  string // temp dir with symlinks to nexus-cni-exec
	netnsDir    string
	helperBin   string
	bridgeName  string // name of the bridge interface (e.g. "nexus0")
	cniExecBin  string // resolved path to the nexus-cni-exec binary
	ipamDataDir string // host-local IPAM allocation directory
	cacheDir    string // CNI result cache directory
	confHash    string // SHA-256 of the conflist JSON
	hashFile    string // path to the stored config hash
}

// New creates a CNI-backed Network adapter. It creates a wrapper directory
// containing symlinks named after each CNI plugin (e.g., "bridge") that
// point to the nexus-cni-exec helper binary. When a plugin is invoked,
// it follows the symlink to nexus-cni-exec, which raises the necessary
// capabilities and execs the real plugin from the system CNI bin directory.
//
// We use containernetworking/cni/libcni directly (rather than go-cni)
// because go-cni hardcodes its result cache to /var/lib/cni, which
// requires root. libcni's NewCNIConfigWithCacheDir lets us use a
// user-writable location.
func New(cfg Config) (*Network, error) {
	if cfg.BridgeName == "" {
		cfg.BridgeName = "nexus0"
	}
	if _, err := exec.LookPath(cfg.HelperBin); err != nil {
		return nil, fmt.Errorf("netns helper not found at %q: %w", cfg.HelperBin, err)
	}

	cniExecPath, err := exec.LookPath(cfg.CNIExecBin)
	if err != nil {
		return nil, fmt.Errorf("cni exec helper not found at %q: %w", cfg.CNIExecBin, err)
	}
	cniExecAbs, err := filepath.Abs(cniExecPath)
	if err != nil {
		return nil, fmt.Errorf("resolve cni exec path: %w", err)
	}

	// Tell nexus-cni-exec where the real plugins live.
	os.Setenv("NEXUS_CNI_REAL_BIN_DIR", cfg.BinDir)

	nsDir := netnsDir()
	if err := os.MkdirAll(nsDir, 0700); err != nil {
		return nil, fmt.Errorf("create netns dir %s: %w", nsDir, err)
	}

	// Create wrapper directory with symlinks for each plugin found in
	// the real bin dir. Each symlink points to nexus-cni-exec, which
	// determines the real plugin name from argv[0].
	wrapperDir, err := os.MkdirTemp("", "nexus-cni-wrap-*")
	if err != nil {
		return nil, fmt.Errorf("create cni wrapper dir: %w", err)
	}

	entries, err := os.ReadDir(cfg.BinDir)
	if err != nil {
		os.RemoveAll(wrapperDir)
		return nil, fmt.Errorf("read cni bin dir %s: %w", cfg.BinDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Symlink(cniExecAbs, filepath.Join(wrapperDir, e.Name())); err != nil {
			os.RemoveAll(wrapperDir)
			return nil, fmt.Errorf("create cni wrapper symlink %s: %w", e.Name(), err)
		}
	}

	confDir, err := os.MkdirTemp("", "nexus-cni-*")
	if err != nil {
		os.RemoveAll(wrapperDir)
		return nil, fmt.Errorf("create cni conf dir: %w", err)
	}

	// host-local IPAM stores allocations in dataDir (default /var/lib/cni,
	// which requires root). Use a user-writable directory instead.
	ipamDataDir := filepath.Join(nsDir, ".ipam")
	if err := os.MkdirAll(ipamDataDir, 0700); err != nil {
		os.RemoveAll(confDir)
		os.RemoveAll(wrapperDir)
		return nil, fmt.Errorf("create ipam data dir: %w", err)
	}

	confJSON := fmt.Sprintf(`{
  "cniVersion": "1.0.0",
  "name": "nexus",
  "plugins": [
    {
      "type": "loopback"
    },
    {
      "type": "bridge",
      "bridge": %q,
      "isGateway": true,
      "ipMasq": true,
      "ipam": {
        "type": "host-local",
        "subnet": %q,
        "dataDir": %q,
        "routes": [{"dst": "0.0.0.0/0"}]
      }
    }
  ]
}`, cfg.BridgeName, cfg.Subnet, ipamDataDir)

	confHashVal := configHash(confJSON)
	hashFilePath := filepath.Join(nsDir, ".cni-config-hash")

	confPath := filepath.Join(confDir, "10-nexus.conflist")
	if err := os.WriteFile(confPath, []byte(confJSON), 0644); err != nil {
		os.RemoveAll(confDir)
		os.RemoveAll(wrapperDir)
		return nil, fmt.Errorf("write cni config: %w", err)
	}

	confList, err := libcni.ConfListFromBytes([]byte(confJSON))
	if err != nil {
		os.RemoveAll(confDir)
		os.RemoveAll(wrapperDir)
		return nil, fmt.Errorf("parse cni config: %w", err)
	}

	// Use a user-writable cache dir instead of the default /var/lib/cni.
	cacheDir := filepath.Join(nsDir, ".cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		os.RemoveAll(confDir)
		os.RemoveAll(wrapperDir)
		return nil, fmt.Errorf("create cni cache dir: %w", err)
	}

	cniConfig := libcni.NewCNIConfigWithCacheDir(
		[]string{wrapperDir},
		cacheDir,
		&invoke.DefaultExec{
			RawExec:       &invoke.RawExec{Stderr: os.Stderr},
			PluginDecoder: version.PluginDecoder{},
		},
	)

	// Best-effort firewall forwarding setup. Ensures the host firewall
	// (UFW, firewalld) allows FORWARD traffic for the bridge interface.
	// Non-fatal: on systems without iptables, networking may still work
	// if the host has no restrictive firewall.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, cniExecAbs, "setup-forwarding", cfg.BridgeName).CombinedOutput()
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "nexus: warning: setup forwarding: %v: %s\n", err, out)
		}
	}

	return &Network{
		cni:         cniConfig,
		confList:    confList,
		confDir:     confDir,
		wrapperDir:  wrapperDir,
		netnsDir:    nsDir,
		helperBin:   cfg.HelperBin,
		bridgeName:  cfg.BridgeName,
		cniExecBin:  cniExecAbs,
		ipamDataDir: ipamDataDir,
		cacheDir:    cacheDir,
		confHash:    confHashVal,
		hashFile:    hashFilePath,
	}, nil
}

// Close removes firewall rules and temporary directories.
func (n *Network) Close() error {
	// Best-effort firewall cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	exec.CommandContext(ctx, n.cniExecBin, "teardown-forwarding", n.bridgeName).CombinedOutput() //nolint:errcheck
	cancel()

	os.RemoveAll(n.wrapperDir)
	return os.RemoveAll(n.confDir)
}

// Setup creates a network namespace for the given VM ID, configures it
// with CNI, and returns the assigned IP/gateway.
func (n *Network) Setup(ctx context.Context, id string, opts ...domain.SetupOpt) (*domain.NetworkInfo, error) {
	nsPath := filepath.Join(n.netnsDir, id)

	out, err := exec.CommandContext(ctx, n.helperBin, "create", nsPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create netns %s: %w: %s", id, err, out)
	}

	rt := &libcni.RuntimeConf{
		ContainerID: id,
		NetNS:       nsPath,
		IfName:      "eth0",
	}

	result, err := n.cni.AddNetworkList(ctx, n.confList, rt)
	if err != nil {
		exec.CommandContext(ctx, n.helperBin, "delete", nsPath).Run() //nolint:errcheck
		return nil, fmt.Errorf("cni setup %s: %w", id, err)
	}

	info := &domain.NetworkInfo{NetNSPath: nsPath}
	if r, err := types100.GetResult(result); err == nil && len(r.IPs) > 0 {
		info.IP = r.IPs[0].Address.IP.String()
		if r.IPs[0].Gateway != nil {
			info.Gateway = r.IPs[0].Gateway.String()
		}
	}
	return info, nil
}

// Teardown removes the CNI configuration and deletes the network namespace.
func (n *Network) Teardown(ctx context.Context, id string) error {
	nsPath := filepath.Join(n.netnsDir, id)

	rt := &libcni.RuntimeConf{
		ContainerID: id,
		NetNS:       nsPath,
		IfName:      "eth0",
	}

	if err := n.cni.DelNetworkList(ctx, n.confList, rt); err != nil {
		return fmt.Errorf("cni remove %s: %w", id, err)
	}

	out, err := exec.CommandContext(ctx, n.helperBin, "delete", nsPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete netns %s: %w: %s", id, err, out)
	}

	return nil
}

// ResetNetwork deletes the bridge interface and clears IPAM/cache state.
// Idempotent: succeeds if the bridge doesn't exist.
func (n *Network) ResetNetwork(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, n.cniExecBin, "delete-bridge", n.bridgeName).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Cannot find device") {
			// Bridge already gone — idempotent success.
		} else {
			return fmt.Errorf("delete bridge %s: %w: %s", n.bridgeName, err, out)
		}
	}

	if err := clearDir(n.ipamDataDir); err != nil {
		return fmt.Errorf("clear ipam data: %w", err)
	}
	if err := clearDir(n.cacheDir); err != nil {
		return fmt.Errorf("clear cni cache: %w", err)
	}

	return nil
}

// ConfigChanged reports whether the CNI configuration has changed since the
// last call to SaveConfigHash.
func (n *Network) ConfigChanged() bool {
	return configChangedCheck(n.hashFile, n.confHash)
}

// SaveConfigHash writes the current config hash to disk so that
// ConfigChanged can detect future changes.
func (n *Network) SaveConfigHash() error {
	return writeConfigHash(n.hashFile, n.confHash)
}

// clearDir removes all entries inside dir without removing dir itself.
func clearDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
