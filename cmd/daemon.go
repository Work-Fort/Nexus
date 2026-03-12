// SPDX-License-Identifier: GPL-3.0-or-later
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
	"strings"
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
	"github.com/Work-Fort/Nexus/internal/infra"
	"github.com/Work-Fort/Nexus/internal/infra/httpapi"
	"github.com/Work-Fort/Nexus/internal/infra/resolved"
	nexusmcp "github.com/Work-Fort/Nexus/internal/infra/mcp"
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
			dsn := viper.GetString("db")
			if dsn == "" {
				dsn = filepath.Join(config.GlobalPaths.StateDir, "nexus.db")
			}
			socketPath := viper.GetString("containerd-socket")
			namespace := viper.GetString("namespace")

			store, err := infra.Open(dsn)
			if err != nil {
				log.Error("failed to open database", "dsn", dsn, "err", err)
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
			btrfsHelper := viper.GetString("btrfs-helper")
			if btrfsHelper != "" {
				if resolved, err := exec.LookPath(btrfsHelper); err != nil {
					log.Warn("btrfs helper not found, export/import will use direct btrfs calls", "helper", btrfsHelper)
					btrfsHelper = ""
				} else {
					btrfsHelper = resolved
				}
			}

			runtime, err := ctrd.New(socketPath, namespace, snapshotter, quotaHelper)
			if err != nil {
				log.Error("failed to connect to containerd", "socket", socketPath, "namespace", namespace, "err", err)
				return fmt.Errorf("connect to containerd: %w", err)
			}
			defer runtime.Close()

			var network domain.Network
			if viper.GetBool("network-enabled") {
				cniCfg := cni.Config{
					BinDir:     viper.GetString("cni-bin-dir"),
					Subnet:     viper.GetString("network-subnet"),
					BridgeName: viper.GetString("bridge-name"),
					HelperBin:  viper.GetString("netns-helper"),
					CNIExecBin: viper.GetString("cni-exec-bin"),
				}
				cniNet, err := cni.New(cniCfg)
				if err != nil {
					log.Error("failed to init CNI networking", "subnet", cniCfg.Subnet, "err", err)
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

				// Parse DNS domains — ensure "nexus" is always present.
				var dnsDomains []string
				for _, d := range strings.Split(viper.GetString("dns-domains"), ",") {
					if d = strings.TrimSpace(d); d != "" {
						dnsDomains = append(dnsDomains, d)
					}
				}
				hasNexus := false
				for _, d := range dnsDomains {
					if d == "nexus" {
						hasNexus = true
						break
					}
				}
				if !hasNexus {
					dnsDomains = append([]string{"nexus"}, dnsDomains...)
				}

				dnsLoopback := viper.GetString("dns-loopback")

				dm, err := dns.New(dns.Config{
					CoreDNSBin: viper.GetString("coredns-bin"),
					DNSHelper:  dnsHelper,
					GatewayIP:  gatewayIP,
					LoopbackIP: dnsLoopback,
					Domains:    dnsDomains,
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

				// Best-effort: register split DNS with systemd-resolved
				// so the host can resolve *.nexus (and vanity domains).
				if dnsLoopback != "" {
					if err := resolved.Register("nexus0", dnsLoopback, dnsDomains); err != nil {
						log.Warn("host dns: could not register with resolved", "err", err)
					} else {
						log.Info("host dns registered", "loopback", dnsLoopback, "domains", dnsDomains)
					}
					defer func() {
						if err := resolved.Revert("nexus0"); err != nil {
							log.Warn("host dns: could not revert resolved", "err", err)
						}
					}()
				}
			} else {
				dnsManager = domain.NoopDNSManager{}
			}

			log.Info("nexus starting", "addr", addr, "db", dsn, "containerd", socketPath, "namespace", namespace)

			if logFile != nil {
				defer logFile.Close()
			}

			nodeExporterPath := viper.GetString("node-exporter-path")
			if nodeExporterPath != "" {
				if resolved, err := exec.LookPath(nodeExporterPath); err != nil {
					log.Warn("node_exporter not found, metrics disabled", "path", nodeExporterPath)
					nodeExporterPath = ""
				} else {
					nodeExporterPath = resolved
				}
			}

			var svcOpts []func(*app.VMService)
			svcOpts = append(svcOpts, app.WithConfig(app.VMServiceConfig{
				DefaultImage:   viper.GetString("agent-image"),
				DefaultRuntime: viper.GetString("runtime"),
				Metrics: app.MetricsConfig{
					NodeExporterPath: nodeExporterPath,
					ListenPort:       viper.GetInt("metrics.listen-port"),
					Collectors:       viper.GetStringSlice("metrics.collectors"),
				},
			}))

			svcOpts = append(svcOpts, app.WithDNS(dnsManager))

			drivesDir := viper.GetString("drives-dir")
			if drivesDir == "" {
				drivesDir = filepath.Join(config.GlobalPaths.StateDir, "drives")
			}
			var storageBackend domain.Storage
			isBtrfs, _ := btrfs.IsBtrfs(filepath.Dir(drivesDir))
			if isBtrfs {
				bs, err := storage.NewBtrfsWithOpts(drivesDir, quotaHelper, btrfsHelper)
				if err != nil {
					return fmt.Errorf("init btrfs storage: %w", err)
				}
				storageBackend = bs
				log.Info("drives enabled", "backend", "btrfs", "dir", drivesDir, "quota", quotaHelper != "", "btrfs-helper", btrfsHelper != "")
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
			svcOpts = append(svcOpts, app.WithTemplateStore(store))
			svcOpts = append(svcOpts, app.WithSnapshotStore(store))

			kataKernelVersion := viper.GetString("kata-kernel-version")
			var healthChecks []app.HealthCheck
			healthChecks = append(healthChecks, app.NewContainerdCheck(runtime, 15*time.Second))
			healthChecks = append(healthChecks, app.NewDiskSpaceCheck(
				[]string{config.GlobalPaths.StateDir},
				60*time.Second,
				100*1024*1024,
				10*1024*1024,
			))
			if kataKernelVersion != "" {
				healthChecks = append(healthChecks, app.NewKataKernelCheck(kataKernelVersion, 30*time.Second))
			}
			health := app.NewHealthService(healthChecks...)
			health.Start(context.Background())
			defer health.Stop()

			svcOpts = append(svcOpts, app.WithHealth(health))

			svc := app.NewVMService(store, runtime, network, svcOpts...)

			if err := svc.SyncDNS(context.Background()); err != nil {
				return fmt.Errorf("sync dns: %w", err)
			}

			svc.RestoreVMs(context.Background())

			monitorCtx, monitorCancel := context.WithCancel(context.Background())
			defer monitorCancel()
			svc.StartCrashMonitor(monitorCtx)

			mux := http.NewServeMux()
			mux.Handle("/mcp", nexusmcp.NewHandler(svc, health))
			mux.Handle("/", httpapi.NewHandler(svc, health))

			httpServer := &http.Server{
				Addr:        addr,
				Handler:     mux,
				ReadTimeout: 10 * time.Second,
				IdleTimeout: 60 * time.Second,
				// No WriteTimeout — handlers like VM creation pull images
				// that can take arbitrarily long depending on size and
				// network speed. A fixed timeout silently kills the
				// connection mid-operation.
			}

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			errCh := make(chan error, 1)
			ln, err := net.Listen("tcp4", addr)
			if err != nil {
				log.Error("failed to bind listen address", "addr", addr, "err", err)
				return fmt.Errorf("listen: %w", err)
			}

			log.Info("nexus listening", "addr", ln.Addr())
			go func() {
				if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
					errCh <- err
				}
			}()

			select {
			case sig := <-sigCh:
				log.Info("received signal, shutting down", "signal", sig)
			case err := <-errCh:
				return err
			}

			monitorCancel()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			svc.Shutdown(ctx)

			if err := httpServer.Shutdown(ctx); err != nil {
				log.Error("http shutdown", "err", err)
			}
			return nil
		},
	}

	cmd.Flags().String("db", "", "Database DSN (postgres://... or SQLite path; default: $XDG_STATE_HOME/nexus/nexus.db)")
	cmd.Flags().String("listen", config.DefaultListenAddr, "HTTP listen address")
	cmd.Flags().String("containerd-socket", config.DefaultSocketPath, "containerd socket path")
	cmd.Flags().String("namespace", config.DefaultNamespace, "containerd namespace")
	cmd.Flags().String("runtime", config.DefaultRuntime, "Default container runtime handler")
	cmd.Flags().String("agent-image", config.DefaultAgentImage, "Default OCI image for agent VMs")
	cmd.Flags().String("cni-bin-dir", config.DefaultCNIBinDir, "Directory containing CNI plugin binaries")
	cmd.Flags().String("network-subnet", config.DefaultNetSubnet, "CIDR subnet for the VM bridge network")
	cmd.Flags().String("bridge-name", config.DefaultBridgeName, "Bridge interface name for VM networking")
	cmd.Flags().Bool("network-enabled", true, "Enable CNI networking for VMs")
	cmd.Flags().String("netns-helper", config.DefaultNetNSHelper, "Path to nexus-netns helper binary")
	cmd.Flags().String("cni-exec-bin", config.DefaultCNIExecBin, "Path to nexus-cni-exec wrapper binary")
	cmd.Flags().String("snapshotter", config.DefaultSnapshotter, "Containerd snapshotter (default: containerd default)")
	cmd.Flags().String("drives-dir", config.DefaultDrivesDir, "Directory for drive volumes (default: $XDG_STATE_HOME/nexus/drives)")
	cmd.Flags().String("quota-helper", config.DefaultQuotaHelper, "Path to nexus-quota helper binary (empty to disable)")
	cmd.Flags().String("btrfs-helper", config.DefaultBtrfsHelper, "Path to nexus-btrfs helper binary for send/receive (empty to use direct btrfs calls)")
	cmd.Flags().Bool("dns-enabled", true, "Enable internal DNS for VM name resolution")
	cmd.Flags().String("coredns-bin", config.DefaultCoreDNSBin, "Path to CoreDNS binary")
	cmd.Flags().String("dns-helper", config.DefaultDNSHelper, "Path to nexus-dns helper binary (cap_net_bind_service)")
	cmd.Flags().String("dns-loopback", config.DefaultDNSLoopback, "Loopback IP for host DNS resolution (empty to disable)")
	cmd.Flags().String("dns-domains", config.DefaultDNSDomains, "Comma-separated DNS domains (nexus is always included)")
	cmd.Flags().String("node-exporter-path", config.DefaultNodeExporterPath, "Path to node_exporter binary for in-VM metrics (empty to disable)")
	cmd.Flags().String("kata-kernel-version", "", "Expected Anvil kernel version for Kata health check (empty to skip)")

	for _, name := range []string{"db", "listen", "containerd-socket", "namespace", "runtime", "agent-image", "cni-bin-dir", "network-subnet", "bridge-name", "network-enabled", "netns-helper", "cni-exec-bin", "snapshotter", "drives-dir", "quota-helper", "btrfs-helper", "dns-enabled", "coredns-bin", "dns-helper", "dns-loopback", "dns-domains", "node-exporter-path", "kata-kernel-version"} {
		if err := viper.BindPFlag(name, cmd.Flags().Lookup(name)); err != nil {
			panic(fmt.Sprintf("bind flag %s: %v", name, err))
		}
	}

	return cmd
}
