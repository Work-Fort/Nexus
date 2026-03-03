// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newExportCmd() *cobra.Command {
	var output string
	var includeDevices bool

	cmd := &cobra.Command{
		Use:   "export <vm-id-or-name>",
		Short: "Export a VM as a backup archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := viper.GetString("listen")
			vmRef := args[0]

			u := fmt.Sprintf("http://%s/v1/vms/%s/export?include_devices=%t",
				addr, url.PathEscape(vmRef), includeDevices)

			resp, err := http.Post(u, "", nil)
			if err != nil {
				return fmt.Errorf("export request: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("export failed (%d): %s", resp.StatusCode, body)
			}

			f, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer f.Close()

			n, err := io.Copy(f, resp.Body)
			if err != nil {
				return fmt.Errorf("write archive: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Exported to %s (%d bytes)\n", output, n)
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "backup.tar.zst", "Output file path")
	cmd.Flags().BoolVar(&includeDevices, "include-devices", false, "Include device mappings")

	return cmd
}
