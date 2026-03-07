// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Work-Fort/Nexus/client"
)

func newDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Manage host device mappings",
	}
	cmd.AddCommand(
		newDeviceListCmd(),
		newDeviceGetCmd(),
		newDeviceCreateCmd(),
		newDeviceDeleteCmd(),
		newDeviceAttachCmd(),
		newDeviceDetachCmd(),
	)
	return cmd
}

func newDeviceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			devices, err := apiClient.ListDevices(cmd.Context())
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(devices)
				return nil
			}
			w := newTabWriter()
			fmt.Fprintln(w, "ID\tNAME\tHOST_PATH\tCONTAINER_PATH\tPERMS\tVM")
			for _, d := range devices {
				vmID := ""
				if d.VMID != nil {
					vmID = *d.VMID
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					d.ID, d.Name, d.HostPath, d.ContainerPath, d.Permissions, vmID)
			}
			flushTabWriter(w)
			return nil
		},
	}
}

func newDeviceGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get device details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := apiClient.GetDevice(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(d)
				return nil
			}
			w := newTabWriter()
			fmt.Fprintf(w, "ID:\t%s\n", d.ID)
			fmt.Fprintf(w, "Name:\t%s\n", d.Name)
			fmt.Fprintf(w, "Host Path:\t%s\n", d.HostPath)
			fmt.Fprintf(w, "Container Path:\t%s\n", d.ContainerPath)
			fmt.Fprintf(w, "Permissions:\t%s\n", d.Permissions)
			fmt.Fprintf(w, "GID:\t%d\n", d.GID)
			vmID := ""
			if d.VMID != nil {
				vmID = *d.VMID
			}
			fmt.Fprintf(w, "VM:\t%s\n", vmID)
			fmt.Fprintf(w, "Created:\t%s\n", d.CreatedAt)
			flushTabWriter(w)
			return nil
		},
	}
}

func newDeviceCreateCmd() *cobra.Command {
	var params client.CreateDeviceParams
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a device mapping",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Name = args[0]
			d, err := apiClient.CreateDevice(cmd.Context(), params)
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(d)
				return nil
			}
			fmt.Printf("Created device %s (%s)\n", d.Name, d.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&params.HostPath, "host-path", "", "Path on the host")
	cmd.Flags().StringVar(&params.ContainerPath, "container-path", "", "Path inside the VM container")
	cmd.Flags().StringVar(&params.Permissions, "permissions", "", "Device permissions (e.g. rwm)")
	cmd.Flags().Uint32Var(&params.GID, "gid", 0, "Group ID for the device")
	cmd.MarkFlagRequired("host-path")       //nolint:errcheck
	cmd.MarkFlagRequired("container-path")  //nolint:errcheck
	cmd.MarkFlagRequired("permissions")     //nolint:errcheck
	return cmd
}

func newDeviceDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.DeleteDevice(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Deleted")
			return nil
		},
	}
}

func newDeviceAttachCmd() *cobra.Command {
	var vmRef string
	cmd := &cobra.Command{
		Use:   "attach <id>",
		Short: "Attach a device to a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.AttachDevice(cmd.Context(), args[0], vmRef); err != nil {
				return err
			}
			fmt.Println("Attached")
			return nil
		},
	}
	cmd.Flags().StringVar(&vmRef, "vm", "", "VM ID or name")
	cmd.MarkFlagRequired("vm") //nolint:errcheck
	return cmd
}

func newDeviceDetachCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detach <id>",
		Short: "Detach a device from its VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.DetachDevice(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Detached")
			return nil
		},
	}
}
