// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
)

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal("encode JSON: %v", err)
	}
}

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func flushTabWriter(w *tabwriter.Writer) {
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush: %v\n", err)
	}
}

// formatBytes formats a byte count as a human-readable string (e.g. "1.5 GiB").
func formatBytes(b uint64) string {
	const (
		kib = 1024
		mib = kib * 1024
		gib = mib * 1024
		tib = gib * 1024
	)
	switch {
	case b >= tib:
		return fmt.Sprintf("%.1f TiB", float64(b)/float64(tib))
	case b >= gib:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
