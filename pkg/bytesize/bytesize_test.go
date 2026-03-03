// SPDX-License-Identifier: Apache-2.0
package bytesize_test

import (
	"testing"

	"github.com/Work-Fort/Nexus/pkg/bytesize"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{"1024", 1024},
		{"0.5G", 500_000_000},

		// SI suffixes
		{"1K", 1_000},
		{"500M", 500_000_000},
		{"1G", 1_000_000_000},
		{"2T", 2_000_000_000_000},

		// IEC suffixes
		{"1Ki", 1024},
		{"1Mi", 1 << 20},
		{"1Gi", 1 << 30},
		{"1Ti", 1 << 40},
		{"512Mi", 512 * (1 << 20)},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := bytesize.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{512, "512"},
		{1_000_000_000, "1G"},
		{2_000_000_000_000, "2T"},
		{500_000_000, "500M"},
		{1_500_000_000, "1.5G"},
		{1_000_000, "1M"},
		{1_000, "1K"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := bytesize.Format(tt.input)
			if got != tt.want {
				t.Errorf("Format(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []string{
		"",
		"abc",
		"-1G",
		"0G",
		"1X",
		"1GiB",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := bytesize.Parse(input)
			if err == nil {
				t.Errorf("Parse(%q) expected error", input)
			}
		})
	}
}
