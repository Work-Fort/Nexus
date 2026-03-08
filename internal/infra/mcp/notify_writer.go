// SPDX-License-Identifier: GPL-3.0-or-later

package mcp

import (
	"bytes"
	"context"

	"github.com/mark3labs/mcp-go/server"
)

// notifyWriter is an io.Writer that sends each write as a JSON-RPC
// notification via the MCP server, and also accumulates the data in
// a buffer for the final tool result.
type notifyWriter struct {
	srv    *server.MCPServer
	ctx    context.Context
	method string // "run_command.stdout" or "run_command.stderr"
	buf    *bytes.Buffer
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	if w.srv != nil && w.ctx != nil {
		_ = w.srv.SendNotificationToClient(w.ctx, w.method, map[string]any{
			"chunk": string(p),
		})
	}
	return len(p), nil
}
