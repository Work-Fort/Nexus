// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newExecCmd() *cobra.Command {
	var stream bool
	cmd := &cobra.Command{
		Use:   "exec <vm> [--stream] -- <cmd...>",
		Short: "Execute a command in a VM",
		Long: `Execute a command inside a running VM.

By default the command runs in buffered mode: stdout and stderr are collected
and printed after the command completes, and nexusctl exits with the command's
exit code.

With --stream, output is streamed to the terminal as it arrives via SSE.`,
		Args:                  cobra.MinimumNArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			vmRef := args[0]

			// Everything after the first arg is the command to run.
			// Cobra handles "--" by stripping it and passing the rest in args.
			cmdArgs := args[1:]
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified; use -- <cmd...>")
			}

			if stream {
				exitCode, err := apiClient.ExecStreamVM(cmd.Context(), vmRef, cmdArgs, os.Stdout, os.Stderr)
				if err != nil {
					return err
				}
				os.Exit(exitCode)
			}

			result, err := apiClient.ExecVM(cmd.Context(), vmRef, cmdArgs)
			if err != nil {
				return err
			}
			if result.Stdout != "" {
				fmt.Fprint(os.Stdout, result.Stdout)
			}
			if result.Stderr != "" {
				fmt.Fprint(os.Stderr, result.Stderr)
			}
			os.Exit(result.ExitCode)
			return nil // unreachable
		},
	}
	cmd.Flags().BoolVar(&stream, "stream", false, "Stream output via SSE instead of buffering")
	return cmd
}
