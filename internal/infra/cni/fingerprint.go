// SPDX-License-Identifier: GPL-3.0-or-later

package cni

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// configHash returns the SHA-256 hex digest of a CNI config string.
func configHash(confJSON string) string {
	h := sha256.Sum256([]byte(confJSON))
	return fmt.Sprintf("%x", h)
}

// writeConfigHash writes a hash string to the given file path.
func writeConfigHash(path, hash string) error {
	return os.WriteFile(path, []byte(hash), 0o600)
}

// readConfigHash reads a hash string from the given file path.
// Returns os.ErrNotExist if the file does not exist.
func readConfigHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// configChangedCheck returns true if the stored hash differs from current.
// Returns true if the hash file is missing (safe default for upgrades).
func configChangedCheck(hashFile, currentHash string) bool {
	stored, err := readConfigHash(hashFile)
	if err != nil {
		return true // missing file = changed
	}
	return stored != currentHash
}
