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
	"github.com/Work-Fort/Nexus/internal/infra/dns"
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

			snapshotter := viper.GetString("snapshotter")
			quotaHelper := viper.GetString("quota-helper")
			if quotaHelper != "" {
				if resolved, err := exec.LookPath(quotaHelper); err != nil {
					log.Warn("quota helper not found, root_size quota disabled", "helper", quotaHelper)
					quotaHelper = ""
				} else {
					quotaHelper = resolved
				}
			}

			runtime, err := ctrd.New(socketPath, namespace, snapshotter, quotaHelper)
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

			var dnsManager domain.DNSManager
			if viper.GetBool("network-enabled") && viper.GetBool("dns-enabled") {
				gatewayIP, err := cni.GatewayIP(viper.GetString("network-subnet"))
				if err != nil {
					return fmt.Errorf("derive gateway IP: %w", err)
				}

				runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
				if runtimeDir == "" {
					runtimeDir = fmt.Sprintf("/tmp/nexus-dns-%d", os.Getuid())
				}

				dnsHelper := viper.GetString("dns-helper")
				if dnsHelper != "" {
					if resolved, err := exec.LookPath(dnsHelper); err != nil {
						log.Warn("dns helper not found, CoreDNS may fail to bind port 53", "helper", dnsHelper)
						dnsHelper = ""
					} else {
						dnsHelper = resolved
					}
				}

				dm, err := dns.New(dns.Config{
					CoreDNSBin: viper.GetString("coredns-bin"),
					DNSHelper:  dnsHelper,
					GatewayIP:  gatewayIP,
					StateDir:   filepath.Join(config.GlobalPaths.StateDir, "dns"),
					RuntimeDir: filepath.Join(runtimeDir, "nexus", "dns"),
				})
				if err != nil {
					return fmt.Errorf("init dns: %w", err)
				}

				if err := dm.Start(context.Background()); err != nil {
					return fmt.Errorf("start dns: %w", err)
				}
				defer dm.Stop()
				dnsManager = dm
				log.Info("dns enabled", "gateway", gatewayIP)
			} else {
				dnsManager = &dns.NoopManager{}
			}

			if logFile != nil {
				defer logFile.Close()
			}

			var svcOpts []func(*app.VMService)
			svcOpts = append(svcOpts, app.WithConfig(app.VMServiceConfig{
				DefaultImage:   viper.GetString("agent-image"),
				DefaultRuntime: viper.GetString("runtime"),
			}))

			svcOpts = append(svcOpts, app.WithDNS(dnsManager))

			drivesDir := viper.GetString("drives-dir")
			if drivesDir == "" {
				drivesDir = filepath.Join(config.GlobalPaths.StateDir, "drives")
			}
			var storageBackend domain.Storage
			isBtrfs, _ := btrfs.IsBtrfs(filepath.Dir(drivesDir))
			if isBtrfs {
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

			if err := svc.SyncDNS(context.Background()); err != nil {
				return fmt.Errorf("sync dns: %w", err)
			}

			svc.RestoreVMs(context.Background())

			monitorCtx, monitorCancel := context.WithCancel(context.Background())
			defer monitorCancel()
			svc.StartCrashMonitor(monitorCtx)

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
				fmt.Fprintf(os.Stderr, "nexus listening on %s\n", ln.Addr())
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
	cmd.Flags().String("snapshotter", config.DefaultSnapshotter, "Containerd snapshotter (default: containerd default)")
	cmd.Flags().String("drives-dir", config.DefaultDrivesDir, "Directory for drive volumes (default: $XDG_STATE_HOME/nexus/drives)")
	cmd.Flags().String("quota-helper", config.DefaultQuotaHelper, "Path to nexus-quota helper binary (empty to disable)")
	cmd.Flags().Bool("dns-enabled", true, "Enable internal DNS for VM name resolution")
	cmd.Flags().String("coredns-bin", config.DefaultCoreDNSBin, "Path to CoreDNS binary")
	cmd.Flags().String("dns-helper", config.DefaultDNSHelper, "Path to nexus-dns helper binary (cap_net_bind_service)")

	for _, name := range []string{"listen", "containerd-socket", "namespace", "runtime", "agent-image", "cni-bin-dir", "network-subnet", "network-enabled", "netns-helper", "cni-exec-bin", "snapshotter", "drives-dir", "quota-helper", "dns-enabled", "coredns-bin", "dns-helper"} {
		if err := viper.BindPFlag(name, cmd.Flags().Lookup(name)); err != nil {
			panic(fmt.Sprintf("bind flag %s: %v", name, err))
		}
	}

	return cmd
}
