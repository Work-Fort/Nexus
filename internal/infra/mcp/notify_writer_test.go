// SPDX-License-Identifier: GPL-3.0-or-later

package mcp

import (
	"bytes"
	"testing"
)

func TestNotifyWriter_Write(t *testing.T) {
	var buf bytes.Buffer
	w := &notifyWriter{buf: &buf}
	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5, got %d", n)
	}
	if buf.String() != "hello" {
		t.Fatalf("expected 'hello', got %q", buf.String())
	}
}

func TestNotifyWriter_MultipleWrites(t *testing.T) {
	var buf bytes.Buffer
	w := &notifyWriter{buf: &buf}
	w.Write([]byte("hello "))
	w.Write([]byte("world"))
	if buf.String() != "hello world" {
		t.Fatalf("expected 'hello world', got %q", buf.String())
	}
}
