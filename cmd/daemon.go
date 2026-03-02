// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/config"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/cni"
	ctrd "github.com/Work-Fort/Nexus/internal/infra/containerd"
	"github.com/Work-Fort/Nexus/internal/infra/httpapi"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
	"github.com/Work-Fort/Nexus/internal/infra/storage"
	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Start the Nexus daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := viper.GetString("listen")
			dbPath := filepath.Join(config.GlobalPaths.StateDir, "nexus.db")
			socketPath := viper.GetString("containerd-socket")
			namespace := viper.GetString("namespace")

			store, err := sqlite.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer store.Close()

			runtime, err := ctrd.New(socketPath, namespace)
			if err != nil {
				return fmt.Errorf("connect to containerd: %w", err)
			}
			defer runtime.Close()

			var network domain.Network
			if viper.GetBool("network-enabled") {
				cniNet, err := cni.New(cni.Config{
					BinDir:     viper.GetString("cni-bin-dir"),
					Subnet:     viper.GetString("network-subnet"),
					HelperBin:  viper.GetString("netns-helper"),
					CNIExecBin: viper.GetString("cni-exec-bin"),
				})
				if err != nil {
					return fmt.Errorf("init cni: %w", err)
				}
				defer cniNet.Close()
				network = cniNet
			} else {
				network = &cni.NoopNetwork{}
			}

			if logFile != nil {
				defer logFile.Close()
			}

			var svcOpts []func(*app.VMService)
			svcOpts = append(svcOpts, app.WithConfig(app.VMServiceConfig{
				DefaultImage:   viper.GetString("agent-image"),
				DefaultRuntime: viper.GetString("runtime"),
			}))

			drivesDir := viper.GetString("drives-dir")
			if drivesDir == "" {
				drivesDir = filepath.Join(config.GlobalPaths.StateDir, "drives")
			}
			var storageBackend domain.Storage
			isBtrfs, _ := btrfs.IsBtrfs(filepath.Dir(drivesDir))
			if isBtrfs {
				quotaHelper := viper.GetString("quota-helper")
				if quotaHelper != "" {
					if resolved, err := exec.LookPath(quotaHelper); err != nil {
						log.Warn("quota helper not found, quota enforcement disabled", "helper", quotaHelper)
						quotaHelper = ""
					} else {
						quotaHelper = resolved
					}
				}
				bs, err := storage.NewBtrfsWithQuota(drivesDir, quotaHelper)
				if err != nil {
					return fmt.Errorf("init btrfs storage: %w", err)
				}
				storageBackend = bs
				log.Info("drives enabled", "backend", "btrfs", "dir", drivesDir, "quota", quotaHelper != "")
			} else {
				ns, err := storage.NewNoop(drivesDir)
				if err != nil {
					return fmt.Errorf("init noop storage: %w", err)
				}
				storageBackend = ns
				log.Info("drives enabled", "backend", "directory", "dir", drivesDir)
			}
			svcOpts = append(svcOpts, app.WithStorage(store, storageBackend))
			svcOpts = append(svcOpts, app.WithDeviceStore(store))

			svc := app.NewVMService(store, runtime, network, svcOpts...)

			handler := httpapi.NewHandler(svc)

			httpServer := &http.Server{
				Addr:         addr,
				Handler:      handler,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  60 * time.Second,
			}

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			errCh := make(chan error, 1)
			go func() {
				ln, err := net.Listen("tcp4", addr)
				if err != nil {
					errCh <- fmt.Errorf("listen: %w", err)
					return
				}
				fmt.Fprintf(os.Stderr, "nexusd listening on %s\n", ln.Addr())
				if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			select {
			case sig := <-sigCh:
				fmt.Fprintf(os.Stderr, "\nReceived %s, shutting down...\n", sig)
			case err := <-errCh:
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := httpServer.Shutdown(ctx); err != nil {
				log.Error("http shutdown", "err", err)
			}
			return nil
		},
	}

	cmd.Flags().String("listen", config.DefaultListenAddr, "HTTP listen address")
	cmd.Flags().String("containerd-socket", config.DefaultSocketPath, "containerd socket path")
	cmd.Flags().String("namespace", config.DefaultNamespace, "containerd namespace")
	cmd.Flags().String("runtime", config.DefaultRuntime, "Default container runtime handler")
	cmd.Flags().String("agent-image", config.DefaultAgentImage, "Default OCI image for agent VMs")
	cmd.Flags().String("cni-bin-dir", config.DefaultCNIBinDir, "Directory containing CNI plugin binaries")
	cmd.Flags().String("network-subnet", config.DefaultNetSubnet, "CIDR subnet for the VM bridge network")
	cmd.Flags().Bool("network-enabled", true, "Enable CNI networking for VMs")
	cmd.Flags().String("netns-helper", config.DefaultNetNSHelper, "Path to nexus-netns helper binary")
	cmd.Flags().String("cni-exec-bin", config.DefaultCNIExecBin, "Path to nexus-cni-exec wrapper binary")
	cmd.Flags().String("drives-dir", config.DefaultDrivesDir, "Directory for drive volumes (default: $XDG_STATE_HOME/nexus/drives)")
	cmd.Flags().String("quota-helper", config.DefaultQuotaHelper, "Path to nexus-quota helper binary (empty to disable)")

	for _, name := range []string{"listen", "containerd-socket", "namespace", "runtime", "agent-image", "cni-bin-dir", "network-subnet", "network-enabled", "netns-helper", "cni-exec-bin", "drives-dir", "quota-helper"} {
		if err := viper.BindPFlag(name, cmd.Flags().Lookup(name)); err != nil {
			panic(fmt.Sprintf("bind flag %s: %v", name, err))
		}
	}

	return cmd
}
