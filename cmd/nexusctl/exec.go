// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec <vm> -- <cmd...>",
		Short: "Execute a command in a VM",
		Long:  "Execute a command inside a running VM. Output is streamed to the terminal as it arrives.",
		Args:  cobra.MinimumNArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			vmRef := args[0]

			// Everything after the first arg is the command to run.
			// Cobra handles "--" by stripping it and passing the rest in args.
			cmdArgs := args[1:]
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified; use -- <cmd...>")
			}

			exitCode, err := apiClient.ExecStreamVM(cmd.Context(), vmRef, cmdArgs, os.Stdout, os.Stderr)
			if err != nil {
				return err
			}
			os.Exit(exitCode)
			return nil // unreachable
		},
	}
}
