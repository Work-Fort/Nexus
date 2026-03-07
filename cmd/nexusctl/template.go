// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Work-Fort/Nexus/client"
)

func newTemplateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Manage provisioning templates",
	}
	cmd.AddCommand(
		newTemplateListCmd(),
		newTemplateGetCmd(),
		newTemplateCreateCmd(),
		newTemplateUpdateCmd(),
		newTemplateDeleteCmd(),
	)
	return cmd
}

func newTemplateListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List templates",
		RunE: func(cmd *cobra.Command, args []string) error {
			templates, err := apiClient.ListTemplates(cmd.Context())
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(templates)
				return nil
			}
			w := newTabWriter()
			fmt.Fprintln(w, "ID\tNAME\tDISTRO")
			for _, t := range templates {
				fmt.Fprintf(w, "%s\t%s\t%s\n", t.ID, t.Name, t.Distro)
			}
			flushTabWriter(w)
			return nil
		},
	}
}

func newTemplateGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get template details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := apiClient.GetTemplate(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(t)
				return nil
			}
			w := newTabWriter()
			fmt.Fprintf(w, "ID:\t%s\n", t.ID)
			fmt.Fprintf(w, "Name:\t%s\n", t.Name)
			fmt.Fprintf(w, "Distro:\t%s\n", t.Distro)
			fmt.Fprintf(w, "Created:\t%s\n", t.CreatedAt)
			fmt.Fprintf(w, "Updated:\t%s\n", t.UpdatedAt)
			fmt.Fprintf(w, "Script:\t%s\n", t.Script)
			flushTabWriter(w)
			return nil
		},
	}
}

func newTemplateCreateCmd() *cobra.Command {
	var params client.CreateTemplateParams
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Name = args[0]
			t, err := apiClient.CreateTemplate(cmd.Context(), params)
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(t)
				return nil
			}
			fmt.Printf("Created template %s (%s)\n", t.Name, t.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&params.Distro, "distro", "", "Target distro (matches /etc/os-release ID)")
	cmd.Flags().StringVar(&params.Script, "script", "", "Provisioning script content")
	cmd.MarkFlagRequired("distro") //nolint:errcheck
	cmd.MarkFlagRequired("script") //nolint:errcheck
	return cmd
}

func newTemplateUpdateCmd() *cobra.Command {
	var params client.UpdateTemplateParams
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := apiClient.UpdateTemplate(cmd.Context(), args[0], params)
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(t)
				return nil
			}
			fmt.Printf("Updated template %s (%s)\n", t.Name, t.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&params.Name, "name", "", "Template name")
	cmd.Flags().StringVar(&params.Distro, "distro", "", "Target distro")
	cmd.Flags().StringVar(&params.Script, "script", "", "Provisioning script content")
	return cmd
}

func newTemplateDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiClient.DeleteTemplate(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Println("Deleted")
			return nil
		},
	}
}
