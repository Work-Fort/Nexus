// SPDX-License-Identifier: GPL-3.0-or-later
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Work-Fort/Nexus/internal/domain"
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

func (s *NoopStorage) SendVolume(_ context.Context, name string, _ io.Writer) error {
	return fmt.Errorf("send volume: not supported on noop storage")
}

func (s *NoopStorage) ReceiveVolume(_ context.Context, name string, _ io.Reader) error {
	return fmt.Errorf("receive volume: not supported on noop storage")
}

func (s *NoopStorage) SnapshotVolume(_ context.Context, _, _ string) error {
	return domain.ErrSnapshotNotSupported
}

func (s *NoopStorage) RestoreVolume(_ context.Context, _, _ string) error {
	return domain.ErrSnapshotNotSupported
}

func (s *NoopStorage) CloneVolume(_ context.Context, _, _ string) error {
	return domain.ErrSnapshotNotSupported
}

func (s *NoopStorage) DeleteVolumeSnapshot(_ context.Context, _ string) error {
	return domain.ErrSnapshotNotSupported
}

func (s *NoopStorage) SendVolumeSnapshot(_ context.Context, _ string, _ io.Writer) error {
	return domain.ErrSnapshotNotSupported
}
