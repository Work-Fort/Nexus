// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Work-Fort/Nexus/internal/config"
)

// Version is set at build time via ldflags.
var Version string

// logFile holds the log file handle for cleanup on shutdown.
var logFile *os.File

var rootCmd = &cobra.Command{
	Use:   "nexusd",
	Short: "Nexus VM lifecycle daemon",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := config.InitDirs(); err != nil {
			return err
		}
		if err := config.LoadConfig(); err != nil {
			return err
		}

		ll := viper.GetString("log-level")
		if ll == "disabled" {
			log.SetOutput(io.Discard)
			return nil
		}

		var level log.Level
		switch ll {
		case "debug":
			level = log.DebugLevel
		case "info":
			level = log.InfoLevel
		case "warn":
			level = log.WarnLevel
		case "error":
			level = log.ErrorLevel
		default:
			level = log.DebugLevel
		}

		logPath := filepath.Join(config.GlobalPaths.StateDir, "debug.log")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		logFile = f

		logger := log.NewWithOptions(f, log.Options{
			ReportTimestamp: true,
			TimeFormat:      "2006-01-02T15:04:05.000Z07:00",
			Level:           level,
			ReportCaller:    true,
			Formatter:       log.JSONFormatter,
		})
		log.SetDefault(logger)

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func init() {
	config.InitViper()

	rootCmd.PersistentFlags().StringP("log-level", "l", "debug", "Log level: disabled, debug, info, warn, error")

	if err := config.BindFlags(rootCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(newDaemonCmd())

	rootCmd.Version = Version
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
}
