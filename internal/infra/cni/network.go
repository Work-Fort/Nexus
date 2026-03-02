// SPDX-License-Identifier: Apache-2.0

package cni

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	gocni "github.com/containerd/go-cni"

	"github.com/Work-Fort/Nexus/internal/domain"
)

const netnsRunDir = "/var/run/netns"

// Config holds CNI adapter configuration.
type Config struct {
	BinDir    string // directory containing CNI plugin binaries
	Subnet    string // CIDR for the bridge network (e.g. "10.88.0.0/16")
	HelperBin string // path to the nexus-netns helper binary
}

// Network implements domain.Network using CNI plugins.
type Network struct {
	cni       gocni.CNI
	confDir   string // temp dir where we write the CNI config
	netnsDir  string
	helperBin string
}

// New creates a CNI-backed Network adapter. It writes a bridge CNI config
// to a temporary directory and initializes the go-cni library.
func New(cfg Config) (*Network, error) {
	if _, err := exec.LookPath(cfg.HelperBin); err != nil {
		return nil, fmt.Errorf("netns helper not found at %q: %w", cfg.HelperBin, err)
	}

	confDir, err := os.MkdirTemp("", "nexus-cni-*")
	if err != nil {
		return nil, fmt.Errorf("create cni conf dir: %w", err)
	}

	confJSON := fmt.Sprintf(`{
  "cniVersion": "1.0.0",
  "name": "nexus",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "nexus0",
      "isGateway": true,
      "ipMasq": true,
      "ipam": {
        "type": "host-local",
        "subnet": %q
      }
    }
  ]
}`, cfg.Subnet)

	confPath := filepath.Join(confDir, "10-nexus.conflist")
	if err := os.WriteFile(confPath, []byte(confJSON), 0644); err != nil {
		os.RemoveAll(confDir)
		return nil, fmt.Errorf("write cni config: %w", err)
	}

	cniLib, err := gocni.New(
		gocni.WithPluginDir([]string{cfg.BinDir}),
		gocni.WithConfListBytes([]byte(confJSON)),
	)
	if err != nil {
		os.RemoveAll(confDir)
		return nil, fmt.Errorf("init cni: %w", err)
	}

	return &Network{
		cni:       cniLib,
		confDir:   confDir,
		netnsDir:  netnsRunDir,
		helperBin: cfg.HelperBin,
	}, nil
}

// Close removes the temporary CNI config directory.
func (n *Network) Close() error {
	return os.RemoveAll(n.confDir)
}

// Setup creates a network namespace for the given VM ID, configures it
// with CNI, and returns the assigned IP/gateway.
func (n *Network) Setup(ctx context.Context, id string) (*domain.NetworkInfo, error) {
	nsPath := filepath.Join(n.netnsDir, id)

	out, err := exec.CommandContext(ctx, n.helperBin, "create", nsPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("create netns %s: %w: %s", id, err, out)
	}

	result, err := n.cni.Setup(ctx, id, nsPath)
	if err != nil {
		exec.CommandContext(ctx, n.helperBin, "delete", nsPath).Run() //nolint:errcheck
		return nil, fmt.Errorf("cni setup %s: %w", id, err)
	}

	info := &domain.NetworkInfo{NetNSPath: nsPath}
	if iface, ok := result.Interfaces["eth0"]; ok && len(iface.IPConfigs) > 0 {
		info.IP = iface.IPConfigs[0].IP.String()
		info.Gateway = iface.IPConfigs[0].Gateway.String()
	}
	return info, nil
}

// Teardown removes the CNI configuration and deletes the network namespace.
func (n *Network) Teardown(ctx context.Context, id string) error {
	nsPath := filepath.Join(n.netnsDir, id)

	if err := n.cni.Remove(ctx, id, nsPath); err != nil {
		return fmt.Errorf("cni remove %s: %w", id, err)
	}

	out, err := exec.CommandContext(ctx, n.helperBin, "delete", nsPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete netns %s: %w: %s", id, err, out)
	}

	return nil
}
