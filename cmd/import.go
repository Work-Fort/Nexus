// SPDX-License-Identifier: GPL-3.0-or-later
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newImportCmd() *cobra.Command {
	var strictDevices bool

	cmd := &cobra.Command{
		Use:   "import <archive.tar.zst>",
		Short: "Import a VM from a backup archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := viper.GetString("listen")
			archivePath := args[0]

			f, err := os.Open(archivePath)
			if err != nil {
				return fmt.Errorf("open archive: %w", err)
			}
			defer f.Close()

			u := fmt.Sprintf("http://%s/v1/vms/import?strict_devices=%t",
				addr, strictDevices)

			resp, err := http.Post(u, "application/zstd", f)
			if err != nil {
				return fmt.Errorf("import request: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("import failed (%d): %s", resp.StatusCode, body)
			}

			fmt.Fprintf(os.Stderr, "Imported: %s\n", body)
			return nil
		},
	}

	cmd.Flags().BoolVar(&strictDevices, "strict-devices", false, "Error on missing host devices")

	return cmd
}
