// SPDX-License-Identifier: GPL-3.0-or-later
package mcp_test

import (
	"testing"

	nexusmcp "github.com/Work-Fort/Nexus/internal/infra/mcp"
)

func TestNewHandlerNonNil(t *testing.T) {
	// Smoke test: verifying NewHandler creates a non-nil handler.
	// Tool invocation tests are in E2E since they need a real VMService.
	handler := nexusmcp.NewHandler(nil)
	if handler == nil {
		t.Fatal("NewHandler returned nil")
	}
}
