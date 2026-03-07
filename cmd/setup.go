// SPDX-License-Identifier: GPL-3.0-or-later
package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Work-Fort/Nexus/internal/config"
	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

func newSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Privileged setup commands (run with sudo)",
		// Override PersistentPreRunE to skip InitDirs — running as root
		// would create XDG directories with wrong ownership.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return config.LoadConfig()
		},
	}

	cmd.AddCommand(newSetupBtrfsQuotasCmd())
	return cmd
}

func newSetupBtrfsQuotasCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "btrfs-quotas",
		Short: "Enable btrfs quotas on the drives filesystem",
		Long: `Enables btrfs qgroup quotas on the filesystem containing the drives
directory. This is a one-time setup step that requires root.

The drives directory is determined from --drives-dir or the config file.
Quotas are idempotent — safe to run multiple times.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			drivesDir := viper.GetString("drives-dir")
			if drivesDir == "" {
				sudoUser := os.Getenv("SUDO_USER")
				if !dryRun && os.Getuid() == 0 && (sudoUser == "" || sudoUser == "root") {
					return fmt.Errorf("cannot determine target user; run with sudo from a non-root user or pass --drives-dir explicitly")
				}
				drivesDir = resolveDrivesDir()
			}

			// Walk up to find an existing directory (drives dir may not
			// exist yet on first run).
			target := drivesDir
			for {
				info, err := os.Stat(target)
				if err == nil && info.IsDir() {
					break
				}
				parent := filepath.Dir(target)
				if parent == target {
					return fmt.Errorf("no existing parent directory found for %s", drivesDir)
				}
				target = parent
			}

			isBtrfs, err := btrfs.IsBtrfs(target)
			if err != nil {
				return fmt.Errorf("check filesystem: %w", err)
			}
			if !isBtrfs {
				return fmt.Errorf("%s is not on a btrfs filesystem", drivesDir)
			}

			fmt.Fprintf(os.Stderr, "drives dir: %s\n", drivesDir)
			fmt.Fprintf(os.Stderr, "btrfs path: %s\n", target)

			if dryRun {
				fmt.Fprintf(os.Stderr, "dry run: would enable btrfs quotas on %s\n", target)
				return nil
			}

			if os.Getuid() != 0 {
				return fmt.Errorf("must be run as root (sudo nexus setup btrfs-quotas)")
			}

			if err := btrfs.EnableQuota(target); err != nil {
				return fmt.Errorf("enable quotas: %w", err)
			}

			fmt.Fprintf(os.Stderr, "btrfs quotas enabled on %s\n", target)
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.Flags().String("drives-dir", config.DefaultDrivesDir, "Directory for drive volumes")
	if err := viper.BindPFlag("drives-dir", cmd.Flags().Lookup("drives-dir")); err != nil {
		panic(fmt.Sprintf("bind flag drives-dir: %v", err))
	}

	return cmd
}

// resolveDrivesDir returns the default drives directory, using SUDO_USER
// to resolve the invoking user's home when running under sudo.
func resolveDrivesDir() string {
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home := sudoUserHome()
		stateHome = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(stateHome, "nexus", "drives")
}

// sudoUserHome returns the home directory of the invoking user. When
// running under sudo, it looks up SUDO_USER to get the real user's
// home rather than root's.
func sudoUserHome() string {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			return u.HomeDir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp"
	}
	return home
}
