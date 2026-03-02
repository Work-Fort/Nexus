// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// NoopStorage implements domain.Storage using plain directories.
// Used in tests and when the drives directory is not on btrfs.
type NoopStorage struct {
	basePath string
}

// NewNoop creates a NoopStorage rooted at basePath.
func NewNoop(basePath string) (*NoopStorage, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("create drives dir %s: %w", basePath, err)
	}
	return &NoopStorage{basePath: basePath}, nil
}

func (s *NoopStorage) CreateVolume(_ context.Context, name string, _ uint64) (string, error) {
	path := filepath.Join(s.basePath, name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", fmt.Errorf("create volume dir %s: %w", name, err)
	}
	return path, nil
}

func (s *NoopStorage) DeleteVolume(_ context.Context, name string) error {
	path := filepath.Join(s.basePath, name)
	return os.RemoveAll(path)
}

func (s *NoopStorage) VolumePath(name string) string {
	return filepath.Join(s.basePath, name)
}
