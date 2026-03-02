// SPDX-License-Identifier: Apache-2.0

// Package storage implements domain.Storage for persistent data volumes.
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

// BtrfsStorage implements domain.Storage using btrfs subvolumes.
type BtrfsStorage struct {
	basePath string
}

// NewBtrfs creates a BtrfsStorage rooted at basePath.
// basePath must be on a btrfs filesystem.
func NewBtrfs(basePath string) (*BtrfsStorage, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("create drives dir %s: %w", basePath, err)
	}
	ok, err := btrfs.IsBtrfs(basePath)
	if err != nil {
		return nil, fmt.Errorf("check btrfs %s: %w", basePath, err)
	}
	if !ok {
		return nil, fmt.Errorf("drives dir %s is not on a btrfs filesystem", basePath)
	}
	return &BtrfsStorage{basePath: basePath}, nil
}

func (s *BtrfsStorage) CreateVolume(_ context.Context, name string, _ uint64) (string, error) {
	path := filepath.Join(s.basePath, name)
	if err := btrfs.CreateSubvolume(path); err != nil {
		return "", fmt.Errorf("create volume %s: %w", name, err)
	}
	return path, nil
}

func (s *BtrfsStorage) DeleteVolume(_ context.Context, name string) error {
	path := filepath.Join(s.basePath, name)
	if err := btrfs.DeleteSubvolume(path); err != nil {
		return fmt.Errorf("delete volume %s: %w", name, err)
	}
	return nil
}

func (s *BtrfsStorage) VolumePath(name string) string {
	return filepath.Join(s.basePath, name)
}
