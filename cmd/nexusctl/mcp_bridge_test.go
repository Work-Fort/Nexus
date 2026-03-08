// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"testing"
)

func TestHandleStreamingNotification_Stdout(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"run_command.stdout","params":{"chunk":"hello\n"}}`
	if !handleStreamingNotification(payload) {
		t.Fatal("expected true for run_command.stdout")
	}
}

func TestHandleStreamingNotification_Stderr(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"run_command.stderr","params":{"chunk":"warn\n"}}`
	if !handleStreamingNotification(payload) {
		t.Fatal("expected true for run_command.stderr")
	}
}

func TestHandleStreamingNotification_OtherMethod(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`
	if handleStreamingNotification(payload) {
		t.Fatal("expected false for non-streaming notification")
	}
}

func TestHandleStreamingNotification_InvalidJSON(t *testing.T) {
	if handleStreamingNotification("not json") {
		t.Fatal("expected false for invalid JSON")
	}
}

func TestHandleStreamingNotification_ToolResult(t *testing.T) {
	payload := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`
	if handleStreamingNotification(payload) {
		t.Fatal("expected false for tool result (no method field)")
	}
}
