// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Work-Fort/Nexus/client"
)

var (
	apiClient *client.Client
	jsonFlag  bool
)

var rootCmd = &cobra.Command{
	Use:   "nexusctl",
	Short: "Remote CLI for the Nexus daemon",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		apiClient = client.New(viper.GetString("addr"))
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	viper.SetDefault("addr", "http://127.0.0.1:9600")
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
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output raw JSON")
	viper.BindPFlag("addr", rootCmd.PersistentFlags().Lookup("addr")) //nolint:errcheck

	rootCmd.AddCommand(newVMCmd())
	rootCmd.AddCommand(newExecCmd())
	rootCmd.AddCommand(newConsoleCmd())
	rootCmd.AddCommand(newDriveCmd())
	rootCmd.AddCommand(newDeviceCmd())
	rootCmd.AddCommand(newNetworkCmd())
	rootCmd.AddCommand(newMCPBridgeCmd())
	rootCmd.AddCommand(newVersionCmd())
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print nexusctl version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("nexusctl version dev")
		},
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
