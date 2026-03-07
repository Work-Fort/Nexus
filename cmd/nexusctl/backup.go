// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newVMExportCmd() *cobra.Command {
	var (
		includeDevices bool
		outputFile     string
	)
	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export a VM to a backup archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer f.Close()

			if err := apiClient.ExportVM(cmd.Context(), args[0], includeDevices, f); err != nil {
				os.Remove(outputFile) // clean up partial file
				return err
			}
			fmt.Printf("Exported VM %s to %s\n", args[0], outputFile)
			return nil
		},
	}
	cmd.Flags().BoolVar(&includeDevices, "include-devices", false, "Include device mappings in export")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	cmd.MarkFlagRequired("output") //nolint:errcheck
	return cmd
}

func newVMImportCmd() *cobra.Command {
	var strictDevices bool
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import a VM from a backup archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("open archive: %w", err)
			}
			defer f.Close()

			result, err := apiClient.ImportVM(cmd.Context(), f, strictDevices)
			if err != nil {
				return err
			}
			if jsonFlag {
				printJSON(result)
				return nil
			}
			fmt.Printf("Imported VM %s (%s)\n", result.VM.Name, result.VM.ID)
			for _, w := range result.Warnings {
				fmt.Printf("Warning: %s\n", w)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&strictDevices, "strict-devices", false, "Fail if device mappings cannot be restored")
	return cmd
}
