// SPDX-License-Identifier: GPL-3.0-or-later

// Package storage implements domain.Storage for persistent data volumes.
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/Work-Fort/Nexus/pkg/btrfs"
)

// BtrfsStorage implements domain.Storage using btrfs subvolumes.
type BtrfsStorage struct {
	basePath    string
	quotaHelper string // path to nexus-quota binary; empty = no enforcement
}

// NewBtrfs creates a BtrfsStorage without quota enforcement.
func NewBtrfs(basePath string) (*BtrfsStorage, error) {
	return NewBtrfsWithQuota(basePath, "")
}

// NewBtrfsWithQuota creates a BtrfsStorage with optional quota enforcement.
// If quotaHelper is non-empty, CreateVolume calls it to set quota limits.
func NewBtrfsWithQuota(basePath, quotaHelper string) (*BtrfsStorage, error) {
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
	return &BtrfsStorage{basePath: basePath, quotaHelper: quotaHelper}, nil
}

func (s *BtrfsStorage) CreateVolume(ctx context.Context, name string, sizeBytes uint64) (string, error) {
	path := filepath.Join(s.basePath, name)
	if err := btrfs.CreateSubvolume(path); err != nil {
		return "", fmt.Errorf("create volume %s: %w", name, err)
	}

	if s.quotaHelper != "" && sizeBytes > 0 {
		out, err := exec.CommandContext(ctx, s.quotaHelper, "set-limit", path,
			strconv.FormatUint(sizeBytes, 10)).CombinedOutput()
		if err != nil {
			btrfs.DeleteSubvolume(path) //nolint:errcheck // rollback best-effort
			return "", fmt.Errorf("set quota on %s: %w: %s", name, err, out)
		}
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

// SendVolume creates a read-only snapshot of the named volume and writes a
// btrfs send stream to w. The temporary snapshot is cleaned up after sending.
func (s *BtrfsStorage) SendVolume(_ context.Context, name string, w io.Writer) error {
	srcPath := filepath.Join(s.basePath, name)
	snapPath := srcPath + ".export-snap"

	if err := btrfs.CreateSnapshot(srcPath, snapPath, true); err != nil {
		return fmt.Errorf("create export snapshot %s: %w", name, err)
	}
	defer btrfs.DeleteSubvolume(snapPath) //nolint:errcheck

	return btrfs.Send(snapPath, w)
}

// ReceiveVolume reads a btrfs send stream from r and receives it as a new
// volume named name. The received subvolume is created under basePath.
func (s *BtrfsStorage) ReceiveVolume(_ context.Context, name string, r io.Reader) error {
	if err := btrfs.Receive(s.basePath, r); err != nil {
		return fmt.Errorf("receive volume %s: %w", name, err)
	}
	// btrfs receive creates the subvolume with the original snapshot name.
	// Rename to the desired name if different.
	receivedPath := filepath.Join(s.basePath, name+".export-snap")
	targetPath := filepath.Join(s.basePath, name)

	if err := os.Rename(receivedPath, targetPath); err != nil {
		return fmt.Errorf("rename received volume: %w", err)
	}

	return btrfs.SetReadOnly(targetPath, false)
}
