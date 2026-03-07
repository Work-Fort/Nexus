// SPDX-License-Identifier: GPL-3.0-or-later
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	EnvPrefix         = "NEXUS"
	ConfigFileName    = "config"
	ConfigType        = "yaml"
	DefaultListenAddr = "127.0.0.1:9600"
	DefaultSocketPath = "/run/containerd/containerd.sock"
	DefaultRuntime    = "io.containerd.runc.v2"
	DefaultNamespace  = "nexus"
	DefaultAgentImage  = "docker.io/library/alpine:latest"
	DefaultCNIBinDir    = "/opt/cni/bin"
	DefaultNetSubnet    = "172.16.0.0/12"
	DefaultNetNSHelper  = "nexus-netns"
	DefaultCNIExecBin   = "nexus-cni-exec"
	DefaultDrivesDir    = "" // empty = auto-detect ($XDG_STATE_HOME/nexus/drives)
	DefaultQuotaHelper  = "nexus-quota"
	DefaultBtrfsHelper  = "nexus-btrfs"
	DefaultSnapshotter  = "" // empty = containerd default (overlayfs)
	DefaultCoreDNSBin       = "coredns"
	DefaultDNSHelper        = "nexus-dns"
	DefaultNodeExporterPath = "node_exporter" // resolved via PATH; install:local puts it in ~/.local/bin
	DefaultMetricsPort      = 9100
)

// Paths holds XDG-compliant directory paths.
type Paths struct {
	ConfigDir string
	StateDir  string
}

var GlobalPaths *Paths

func init() {
	GlobalPaths = GetPaths()
}

// GetPaths returns XDG-compliant directory paths.
func GetPaths() *Paths {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get home directory: %v\n", err)
			os.Exit(1)
		}
		configHome = filepath.Join(home, ".config")
	}

	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get home directory: %v\n", err)
			os.Exit(1)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}

	return &Paths{
		ConfigDir: filepath.Join(configHome, "nexus"),
		StateDir:  filepath.Join(stateHome, "nexus"),
	}
}

// InitDirs creates all necessary directories.
func InitDirs() error {
	dirs := []string{
		GlobalPaths.ConfigDir,
		GlobalPaths.StateDir,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}

// InitViper sets up viper defaults and config file search paths.
func InitViper() {
	viper.SetDefault("listen", DefaultListenAddr)
	viper.SetDefault("log-level", "debug")
	viper.SetDefault("containerd-socket", DefaultSocketPath)
	viper.SetDefault("runtime", DefaultRuntime)
	viper.SetDefault("namespace", DefaultNamespace)
	viper.SetDefault("agent-image", DefaultAgentImage)
	viper.SetDefault("cni-bin-dir", DefaultCNIBinDir)
	viper.SetDefault("network-subnet", DefaultNetSubnet)
	viper.SetDefault("network-enabled", true)
	viper.SetDefault("netns-helper", DefaultNetNSHelper)
	viper.SetDefault("cni-exec-bin", DefaultCNIExecBin)
	viper.SetDefault("snapshotter", DefaultSnapshotter)
	viper.SetDefault("drives-dir", DefaultDrivesDir)
	viper.SetDefault("quota-helper", DefaultQuotaHelper)
	viper.SetDefault("btrfs-helper", DefaultBtrfsHelper)
	viper.SetDefault("dns-enabled", true)
	viper.SetDefault("coredns-bin", DefaultCoreDNSBin)
	viper.SetDefault("dns-helper", DefaultDNSHelper)
	viper.SetDefault("node-exporter-path", DefaultNodeExporterPath)
	viper.SetDefault("metrics.listen-port", DefaultMetricsPort)
	viper.SetDefault("metrics.collectors", []string{
		"cpu", "meminfo", "diskstats", "filesystem", "loadavg", "netdev",
	})

	viper.SetConfigName(ConfigFileName)
	viper.SetConfigType(ConfigType)
	viper.AddConfigPath(GlobalPaths.ConfigDir)

	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

// LoadConfig reads the config file if present.
func LoadConfig() error {
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("read config: %w", err)
	}
	return nil
}

// BindFlags binds cobra flags to viper.
func BindFlags(flags *pflag.FlagSet) error {
	flagsToBind := []string{"log-level"}
	for _, name := range flagsToBind {
		if err := viper.BindPFlag(name, flags.Lookup(name)); err != nil {
			return fmt.Errorf("bind flag %s: %w", name, err)
		}
	}
	return nil
}
