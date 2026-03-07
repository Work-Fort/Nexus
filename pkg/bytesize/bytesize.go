// SPDX-License-Identifier: GPL-3.0-or-later

// Package bytesize parses human-readable byte size strings (e.g. "1G", "500Mi")
// into uint64 byte counts. Supports both SI (K, M, G, T) and IEC (Ki, Mi, Gi, Ti)
// suffixes, matching Kubernetes resource quantity syntax.
package bytesize

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Parse converts a size string to bytes. Accepted formats:
//   - Plain integer: "1024" → 1024 bytes
//   - SI suffixes: "1K" (1000), "1M" (10⁶), "1G" (10⁹), "1T" (10¹²)
//   - IEC suffixes: "1Ki" (1024), "1Mi" (2²⁰), "1Gi" (2³⁰), "1Ti" (2⁴⁰)
func Parse(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("bytesize: empty string")
	}

	// Find where the numeric part ends.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("bytesize: invalid format %q", s)
	}

	numStr := s[:i]
	suffix := s[i:]

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("bytesize: parse number %q: %w", numStr, err)
	}
	if num <= 0 {
		return 0, fmt.Errorf("bytesize: size must be positive, got %q", s)
	}

	var multiplier float64
	switch suffix {
	case "":
		multiplier = 1
	case "K":
		multiplier = 1e3
	case "M":
		multiplier = 1e6
	case "G":
		multiplier = 1e9
	case "T":
		multiplier = 1e12
	case "Ki":
		multiplier = 1 << 10
	case "Mi":
		multiplier = 1 << 20
	case "Gi":
		multiplier = 1 << 30
	case "Ti":
		multiplier = 1 << 40
	default:
		return 0, fmt.Errorf("bytesize: unknown suffix %q in %q", suffix, s)
	}

	result := num * multiplier
	if result > math.MaxUint64 || math.IsInf(result, 0) || math.IsNaN(result) {
		return 0, fmt.Errorf("bytesize: overflow %q", s)
	}

	return uint64(result), nil
}

// Format converts bytes to a human-readable size string using SI suffixes.
// Uses the largest whole suffix that divides evenly, falling back to one
// decimal place if needed. Zero returns "0".
func Format(n uint64) string {
	if n == 0 {
		return "0"
	}

	type unit struct {
		suffix string
		size   uint64
	}
	units := []unit{
		{"T", 1_000_000_000_000},
		{"G", 1_000_000_000},
		{"M", 1_000_000},
		{"K", 1_000},
	}

	for _, u := range units {
		if n >= u.size {
			if n%u.size == 0 {
				return fmt.Sprintf("%d%s", n/u.size, u.suffix)
			}
			val := float64(n) / float64(u.size)
			return fmt.Sprintf("%.1f%s", val, u.suffix)
		}
	}
	return fmt.Sprintf("%d", n)
}
