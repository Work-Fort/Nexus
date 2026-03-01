// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/config"
	ctrd "github.com/Work-Fort/Nexus/internal/infra/containerd"
	"github.com/Work-Fort/Nexus/internal/infra/httpapi"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
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

			if logFile != nil {
				defer logFile.Close()
			}

			svc := app.NewVMService(store, runtime, app.WithConfig(app.VMServiceConfig{
				DefaultImage:   viper.GetString("agent-image"),
				DefaultRuntime: viper.GetString("runtime"),
			}))

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

	for _, name := range []string{"listen", "containerd-socket", "namespace", "runtime", "agent-image"} {
		if err := viper.BindPFlag(name, cmd.Flags().Lookup(name)); err != nil {
			panic(fmt.Sprintf("bind flag %s: %v", name, err))
		}
	}

	return cmd
}
