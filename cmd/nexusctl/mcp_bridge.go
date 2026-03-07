// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
	hc := apiClient.HTTPClient()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB max line

	// StreamableHTTP is session-based. The server returns a session ID in
	// the Mcp-Session-Id response header on initialize; all subsequent
	// requests must echo it back.
	var sessionID string

	for scanner.Scan() {
		line := scanner.Bytes()

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(line))
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-bridge: request error: %v\n", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}

		resp, err := hc.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-bridge: POST error: %v\n", err)
			continue
		}

		// Capture session ID from response (set on initialize).
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			sessionID = sid
		}

		// Notifications return 202 Accepted with no body.
		if resp.StatusCode == http.StatusAccepted {
			resp.Body.Close()
			continue
		}

		ct := resp.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "text/event-stream") {
			// SSE response — extract JSON-RPC messages from data: lines.
			sseScanner := bufio.NewScanner(resp.Body)
			sseScanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
			for sseScanner.Scan() {
				sseLine := sseScanner.Text()
				if strings.HasPrefix(sseLine, "data: ") {
					payload := sseLine[len("data: "):]
					os.Stdout.WriteString(payload) //nolint:errcheck
					os.Stdout.Write([]byte{'\n'})  //nolint:errcheck
				}
			}
			resp.Body.Close()
		} else {
			// Direct JSON response — pass through as-is.
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			os.Stdout.Write(body)         //nolint:errcheck
			os.Stdout.Write([]byte{'\n'}) //nolint:errcheck
		}
	}
	return scanner.Err()
}
