// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage networking",
	}
	cmd.AddCommand(newNetworkResetCmd())
	return cmd
}

func newNetworkResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset network bridge and CNI state",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.ResetNetwork(cmd.Context()); err != nil {
				return err
			}
			fmt.Println("Network reset")
			return nil
		},
	}
}
