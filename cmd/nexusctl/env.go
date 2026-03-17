// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newEnvCmd() *cobra.Command {
	var clearFlag bool

	cmd := &cobra.Command{
		Use:   "env <vm> [KEY=VALUE ...]",
		Short: "Get or set VM environment variables",
		Long:  "Show current env vars, set new ones (replaces all), or clear them.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			vmRef := args[0]

			if clearFlag {
				vm, err := apiClient.UpdateEnv(ctx, vmRef, map[string]string{})
				if err != nil {
					return err
				}
				if jsonFlag {
					printJSON(vm)
					return nil
				}
				fmt.Println("Environment cleared")
				return nil
			}

			if len(args) == 1 {
				// Get mode — show current env vars.
				vm, err := apiClient.GetVM(ctx, vmRef)
				if err != nil {
					return err
				}
				if jsonFlag {
					printJSON(vm.Env)
					return nil
				}
				if len(vm.Env) == 0 {
					fmt.Println("No environment variables set")
					return nil
				}
				for k, v := range vm.Env {
					fmt.Printf("%s=%s\n", k, v)
				}
				return nil
			}

			// Set mode — parse KEY=VALUE pairs.
			env := make(map[string]string)
			for _, arg := range args[1:] {
				parts := strings.SplitN(arg, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid env var %q (expected KEY=VALUE)", arg)
				}
				env[parts[0]] = parts[1]
			}

			vm, err := apiClient.UpdateEnv(ctx, vmRef, env)
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(vm)
				return nil
			}
			for k, v := range vm.Env {
				fmt.Printf("%s=%s\n", k, v)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&clearFlag, "clear", false, "Remove all environment variables")
	return cmd
}
