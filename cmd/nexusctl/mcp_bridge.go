// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func newMCPBridgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp-bridge",
		Short: "Transparent stdio-to-HTTP proxy for MCP JSON-RPC",
		Long:  "Reads newline-delimited JSON-RPC from stdin, POSTs each line to the daemon's /mcp endpoint, and writes the response to stdout.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPBridge()
		},
	}
}

func runMCPBridge() error {
	endpoint := apiClient.BaseURL() + "/mcp"
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB max line

	for scanner.Scan() {
		line := scanner.Bytes()
		resp, err := http.Post(endpoint, "application/json", bytes.NewReader(line)) //nolint:gosec
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-bridge: POST error: %v\n", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		os.Stdout.Write(body)                //nolint:errcheck
		os.Stdout.Write([]byte{'\n'})        //nolint:errcheck
	}
	return scanner.Err()
}
