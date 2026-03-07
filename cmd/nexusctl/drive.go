// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Work-Fort/Nexus/client"
)

func newDriveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drive",
		Short: "Manage persistent data drives",
	}
	cmd.AddCommand(
		newDriveListCmd(),
		newDriveGetCmd(),
		newDriveCreateCmd(),
		newDriveDeleteCmd(),
		newDriveAttachCmd(),
		newDriveDetachCmd(),
	)
	return cmd
}

func newDriveListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List drives",
		RunE: func(cmd *cobra.Command, args []string) error {
			drives, err := apiClient.ListDrives(cmd.Context())
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(drives)
				return nil
			}
			w := newTabWriter()
			fmt.Fprintln(w, "ID\tNAME\tSIZE\tMOUNT_PATH\tVM")
			for _, d := range drives {
				vmID := ""
				if d.VMID != nil {
					vmID = *d.VMID
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					d.ID, d.Name, formatBytes(d.SizeBytes), d.MountPath, vmID)
			}
			flushTabWriter(w)
			return nil
		},
	}
}

func newDriveGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get drive details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := apiClient.GetDrive(cmd.Context(), args[0])
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
			fmt.Fprintf(w, "Size:\t%s\n", formatBytes(d.SizeBytes))
			fmt.Fprintf(w, "Mount Path:\t%s\n", d.MountPath)
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

func newDriveCreateCmd() *cobra.Command {
	var params client.CreateDriveParams
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a drive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Name = args[0]
			d, err := apiClient.CreateDrive(cmd.Context(), params)
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(d)
				return nil
			}
			fmt.Printf("Created drive %s (%s)\n", d.Name, d.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&params.Size, "size", "", "Drive size (e.g. 1G, 500M)")
	cmd.Flags().StringVar(&params.MountPath, "mount-path", "", "Mount path inside VM")
	cmd.MarkFlagRequired("size")       //nolint:errcheck
	cmd.MarkFlagRequired("mount-path") //nolint:errcheck
	return cmd
}

func newDriveDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a drive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.DeleteDrive(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Deleted")
			return nil
		},
	}
}

func newDriveAttachCmd() *cobra.Command {
	var vmRef string
	cmd := &cobra.Command{
		Use:   "attach <id>",
		Short: "Attach a drive to a VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.AttachDrive(cmd.Context(), args[0], vmRef); err != nil {
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

func newDriveDetachCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detach <id>",
		Short: "Detach a drive from its VM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.DetachDrive(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Detached")
			return nil
		},
	}
}
