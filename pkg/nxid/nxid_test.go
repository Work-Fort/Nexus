// SPDX-License-Identifier: GPL-3.0-or-later
package nxid

import (
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	id := New()
	if id == "" {
		t.Fatal("New() returned empty string")
	}
	if len(id) != 13 {
		t.Fatalf("New() returned %d chars, want 13: %q", len(id), id)
	}

	id2 := New()
	if id == id2 {
		t.Fatalf("two calls to New() returned the same value: %q", id)
	}
}

func TestIsNxID(t *testing.T) {
	// A generated ID must be valid.
	id := New()
	if !IsNxID(id) {
		t.Fatalf("IsNxID(%q) = false, want true", id)
	}

	// Names with dashes are not valid IDs.
	if IsNxID("my-vm") {
		t.Fatal("IsNxID(\"my-vm\") = true, want false")
	}

	// Wrong length.
	if IsNxID("abc") {
		t.Fatal("IsNxID(\"abc\") = true, want false")
	}

	// Empty string.
	if IsNxID("") {
		t.Fatal("IsNxID(\"\") = true, want false")
	}
}

func TestValidateName(t *testing.T) {
	valid := []string{
		"my-vm",
		"a",
		"a-b-c",
		"vm1",
		strings.Repeat("a", 24), // 24 chars
	}
	for _, name := range valid {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}

	invalidFormat := []struct {
		name string
		desc string
	}{
		{"", "empty"},
		{strings.Repeat("a", 25), "too long (25 chars)"},
		{"-abc", "starts with dash"},
		{"abc-", "ends with dash"},
		{"MyVM", "uppercase"},
		{"my_vm", "underscore"},
		{"my.vm", "dot"},
	}
	for _, tc := range invalidFormat {
		if err := ValidateName(tc.name); err == nil {
			t.Errorf("ValidateName(%q) [%s] = nil, want error", tc.name, tc.desc)
		}
	}

	// A generated nxid must be rejected as a name (base32 collision).
	id := New()
	err := ValidateName(id)
	if err == nil {
		t.Fatalf("ValidateName(%q) = nil, want error about resource ID", id)
	}
	if !strings.Contains(err.Error(), "cannot be a valid resource ID") {
		t.Fatalf("ValidateName(%q) error = %q, want 'cannot be a valid resource ID'", id, err.Error())
	}
}
