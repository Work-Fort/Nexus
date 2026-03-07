// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Work-Fort/Nexus/client"
)

func newVMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Manage VMs",
	}
	cmd.AddCommand(
		newVMListCmd(),
		newVMGetCmd(),
		newVMCreateCmd(),
		newVMDeleteCmd(),
		newVMStartCmd(),
		newVMStopCmd(),
		newVMExportCmd(),
		newVMImportCmd(),
	)
	return cmd
}

func newVMListCmd() *cobra.Command {
	var role string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List VMs",
		RunE: func(cmd *cobra.Command, args []string) error {
			vms, err := apiClient.ListVMs(cmd.Context(), client.ListVMsFilter{Role: role})
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(vms)
				return nil
			}
			w := newTabWriter()
			fmt.Fprintln(w, "ID\tNAME\tROLE\tSTATE\tIP")
			for _, vm := range vms {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", vm.ID, vm.Name, vm.Role, vm.State, vm.IP)
			}
			flushTabWriter(w)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "Filter by role")
	return cmd
}

func newVMGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get VM details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vm, err := apiClient.GetVM(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(vm)
				return nil
			}
			w := newTabWriter()
			printVMDetail(w, vm)
			flushTabWriter(w)
			return nil
		},
	}
}

func newVMCreateCmd() *cobra.Command {
	var params client.CreateVMParams
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Name = args[0]
			vm, err := apiClient.CreateVM(cmd.Context(), params)
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(vm)
				return nil
			}
			fmt.Printf("Created VM %s (%s)\n", vm.Name, vm.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&params.Role, "role", "", "VM role (agent or service)")
	cmd.Flags().StringVar(&params.Image, "image", "", "OCI image")
	cmd.Flags().StringVar(&params.RootSize, "root-size", "", "Root filesystem size limit")
	cmd.Flags().StringVar(&params.RestartPolicy, "restart-policy", "", "Restart policy")
	cmd.MarkFlagRequired("role") //nolint:errcheck
	return cmd
}

func newVMDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.DeleteVM(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Deleted")
			return nil
		},
	}
}

func newVMStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <id>",
		Short: "Start a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.StartVM(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Started")
			return nil
		},
	}
}

func newVMStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <id>",
		Short: "Stop a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.StopVM(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Stopped")
			return nil
		},
	}
}

func printVMDetail(w *tabwriter.Writer, vm *client.VM) {
	fmt.Fprintf(w, "ID:\t%s\n", vm.ID)
	fmt.Fprintf(w, "Name:\t%s\n", vm.Name)
	fmt.Fprintf(w, "Role:\t%s\n", vm.Role)
	fmt.Fprintf(w, "State:\t%s\n", vm.State)
	fmt.Fprintf(w, "Image:\t%s\n", vm.Image)
	fmt.Fprintf(w, "IP:\t%s\n", vm.IP)
	if vm.RootSize != nil {
		fmt.Fprintf(w, "Root Size:\t%s\n", *vm.RootSize)
	}
	fmt.Fprintf(w, "Restart Policy:\t%s\n", vm.RestartPolicy)
	fmt.Fprintf(w, "Created:\t%s\n", vm.CreatedAt)
}
