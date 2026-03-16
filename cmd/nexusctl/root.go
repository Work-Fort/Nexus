// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Work-Fort/Nexus/client"
)

// Version is set at build time via ldflags.
var Version string

var (
	apiClient *client.Client
	jsonFlag  bool
)

var rootCmd = &cobra.Command{
	Use:   "nexusctl",
	Short: "Remote CLI for the Nexus daemon",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		timeout := viper.GetDuration("timeout")
		apiClient = client.New(viper.GetString("addr"),
			client.WithHTTPClient(&http.Client{Timeout: timeout}),
		)
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	viper.SetDefault("addr", "http://127.0.0.1:9600")
	viper.SetDefault("timeout", 10*time.Second)
	viper.SetConfigName("nexusctl")
	viper.SetConfigType("toml")

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			configHome = home + "/.config"
		}
	}
	if configHome != "" {
		viper.AddConfigPath(configHome + "/nexus")
	}

	viper.SetEnvPrefix("NEXUS")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	viper.ReadInConfig() //nolint:errcheck // config file is optional

	rootCmd.PersistentFlags().String("addr", "", "Nexus daemon address (default http://127.0.0.1:9600)")
	rootCmd.PersistentFlags().Duration("timeout", 0, "HTTP request timeout (default 10s)")
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output raw JSON")
	viper.BindPFlag("addr", rootCmd.PersistentFlags().Lookup("addr"))       //nolint:errcheck
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout")) //nolint:errcheck

	rootCmd.AddCommand(newVMCmd())
	rootCmd.AddCommand(newExecCmd())
	rootCmd.AddCommand(newConsoleCmd())
	rootCmd.AddCommand(newDriveCmd())
	rootCmd.AddCommand(newDeviceCmd())
	rootCmd.AddCommand(newTemplateCmd())
	rootCmd.AddCommand(newNetworkCmd())
	rootCmd.AddCommand(newMCPBridgeCmd())

	if Version != "" {
		rootCmd.Version = Version
	} else {
		rootCmd.Version = "dev"
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
