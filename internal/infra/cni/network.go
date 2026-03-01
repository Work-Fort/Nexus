// SPDX-License-Identifier: Apache-2.0

package cni

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	gocni "github.com/containerd/go-cni"
	"golang.org/x/sys/unix"

	"github.com/Work-Fort/Nexus/internal/domain"
)

const netnsRunDir = "/var/run/netns"

// Config holds CNI adapter configuration.
type Config struct {
	BinDir string // directory containing CNI plugin binaries
	Subnet string // CIDR for the bridge network (e.g. "10.88.0.0/16")
}

// Network implements domain.Network using CNI plugins.
type Network struct {
	cni       gocni.CNI
	confDir   string // temp dir where we write the CNI config
	netnsDir  string
}

// New creates a CNI-backed Network adapter. It writes a bridge CNI config
// to a temporary directory and initializes the go-cni library.
func New(cfg Config) (*Network, error) {
	confDir, err := os.MkdirTemp("", "nexus-cni-*")
	if err != nil {
		return nil, fmt.Errorf("create cni conf dir: %w", err)
	}

	confPath := filepath.Join(confDir, "10-nexus.conflist")
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

	if err := os.MkdirAll(netnsRunDir, 0755); err != nil {
		os.RemoveAll(confDir)
		return nil, fmt.Errorf("create netns dir: %w", err)
	}

	return &Network{
		cni:      cniLib,
		confDir:  confDir,
		netnsDir: netnsRunDir,
	}, nil
}

// Close removes the temporary CNI config directory.
func (n *Network) Close() error {
	return os.RemoveAll(n.confDir)
}

// Setup creates a network namespace for the given VM ID, configures it
// with CNI, and returns the assigned IP/gateway.
func (n *Network) Setup(ctx context.Context, id string) (*domain.NetworkInfo, error) {
	nsPath, err := createNetNS(n.netnsDir, id)
	if err != nil {
		return nil, fmt.Errorf("create netns %s: %w", id, err)
	}

	result, err := n.cni.Setup(ctx, id, nsPath)
	if err != nil {
		deleteNetNS(n.netnsDir, id) //nolint:errcheck // best-effort cleanup
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

	if err := deleteNetNS(n.netnsDir, id); err != nil {
		return fmt.Errorf("delete netns %s: %w", id, err)
	}

	return nil
}

// createNetNS creates a persistent network namespace at /var/run/netns/<id>.
func createNetNS(nsDir, id string) (string, error) {
	nsPath := filepath.Join(nsDir, id)

	// Create the bind-mount target file.
	f, err := os.Create(nsPath)
	if err != nil {
		return "", fmt.Errorf("create netns file: %w", err)
	}
	f.Close()

	// Create a new network namespace in a dedicated OS thread, then
	// bind-mount /proc/self/ns/net to the target so it persists.
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread — thread dies with the goroutine, preserving
		// the original thread's namespace.

		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("unshare: %w", err)
			return
		}

		src := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		if err := unix.Mount(src, nsPath, "none", unix.MS_BIND, ""); err != nil {
			errCh <- fmt.Errorf("bind mount netns: %w", err)
			return
		}

		errCh <- nil
	}()

	if err := <-errCh; err != nil {
		os.Remove(nsPath)
		return "", err
	}

	return nsPath, nil
}

// deleteNetNS unmounts and removes a persistent network namespace.
func deleteNetNS(nsDir, id string) error {
	nsPath := filepath.Join(nsDir, id)

	if err := unix.Unmount(nsPath, unix.MNT_DETACH); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("unmount netns: %w", err)
		}
	}

	if err := os.Remove(nsPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove netns file: %w", err)
	}

	return nil
}
