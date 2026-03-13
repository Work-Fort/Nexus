// SPDX-License-Identifier: GPL-3.0-or-later

package cni

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFingerprint(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, ".cni-config-hash")

	// Two different configs produce different hashes.
	h1 := configHash(`{"plugins":[{"type":"bridge"}]}`)
	h2 := configHash(`{"plugins":[{"type":"loopback"},{"type":"bridge"}]}`)
	if h1 == h2 {
		t.Fatal("different configs produced same hash")
	}

	// Same config produces same hash.
	h3 := configHash(`{"plugins":[{"type":"bridge"}]}`)
	if h1 != h3 {
		t.Fatal("same config produced different hash")
	}

	// Write and read back.
	if err := writeConfigHash(hashFile, h1); err != nil {
		t.Fatal(err)
	}
	stored, err := readConfigHash(hashFile)
	if err != nil {
		t.Fatal(err)
	}
	if stored != h1 {
		t.Fatalf("stored=%s, want=%s", stored, h1)
	}
}

func TestConfigFingerprintMissing(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, ".cni-config-hash")

	_, err := readConfigHash(hashFile)
	if !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestConfigChanged(t *testing.T) {
	dir := t.TempDir()
	hashFile := filepath.Join(dir, ".cni-config-hash")

	h1 := configHash(`{"plugins":[{"type":"bridge"}]}`)
	if err := writeConfigHash(hashFile, h1); err != nil {
		t.Fatal(err)
	}

	// Same config -- not changed.
	if configChangedCheck(hashFile, h1) {
		t.Fatal("expected no change for same hash")
	}

	// Different config -- changed.
	h2 := configHash(`{"plugins":[{"type":"loopback"},{"type":"bridge"}]}`)
	if !configChangedCheck(hashFile, h2) {
		t.Fatal("expected change for different hash")
	}

	// Missing file -- treated as changed.
	if !configChangedCheck(filepath.Join(dir, "nonexistent"), h1) {
		t.Fatal("expected changed=true for missing file")
	}
}
