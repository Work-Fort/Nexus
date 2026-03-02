// SPDX-License-Identifier: Apache-2.0
package nxid

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"regexp"
)

// encoding is lowercase RFC 4648 base32 without padding.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// nameRe matches valid resource names: 1-24 lowercase alphanumeric chars and dashes,
// must start and end with a letter or digit.
var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,22}[a-z0-9])?$`)

// New generates a random uint64 and returns it as a 13-char lowercase base32 string.
func New() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("nxid: crypto/rand failed: " + err.Error())
	}
	return encoding.EncodeToString(buf[:])
}

// IsNxID returns true if s is a valid base32-encoded nxid (exactly 8 bytes decoded).
func IsNxID(s string) bool {
	b, err := encoding.DecodeString(s)
	return err == nil && len(b) == 8
}

// ValidateName checks that name follows the naming rules:
//   - 1-24 characters
//   - starts and ends with [a-z0-9]
//   - body contains only [a-z0-9-]
//   - must NOT be a valid base32 ID (to avoid ambiguity)
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name must be 1-24 chars, start/end with a-z0-9, contain only a-z0-9 and dashes")
	}
	if IsNxID(name) {
		return fmt.Errorf("name cannot be a valid resource ID")
	}
	return nil
}
