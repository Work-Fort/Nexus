// SPDX-License-Identifier: GPL-3.0-or-later

// Package storage implements domain.Storage for persistent data volumes.
package storage

import (
	"bytes"
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
	btrfsHelper string // path to nexus-btrfs binary; empty = direct btrfs calls
}

// NewBtrfs creates a BtrfsStorage without quota enforcement.
func NewBtrfs(basePath string) (*BtrfsStorage, error) {
	return NewBtrfsWithOpts(basePath, "", "")
}

// NewBtrfsWithQuota creates a BtrfsStorage with optional quota enforcement.
// If quotaHelper is non-empty, CreateVolume calls it to set quota limits.
func NewBtrfsWithQuota(basePath, quotaHelper string) (*BtrfsStorage, error) {
	return NewBtrfsWithOpts(basePath, quotaHelper, "")
}

// NewBtrfsWithOpts creates a BtrfsStorage with optional helpers.
func NewBtrfsWithOpts(basePath, quotaHelper, btrfsHelper string) (*BtrfsStorage, error) {
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
	return &BtrfsStorage{basePath: basePath, quotaHelper: quotaHelper, btrfsHelper: btrfsHelper}, nil
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
func (s *BtrfsStorage) SendVolume(ctx context.Context, name string, w io.Writer) error {
	srcPath := filepath.Join(s.basePath, name)
	snapPath := srcPath + ".export-snap"

	if err := btrfs.CreateSnapshot(srcPath, snapPath, true); err != nil {
		return fmt.Errorf("create export snapshot %s: %w", name, err)
	}
	defer btrfs.DeleteSubvolume(snapPath) //nolint:errcheck

	return s.sendStream(ctx, snapPath, w)
}

// ReceiveVolume reads a btrfs send stream from r and receives it as a new
// volume named name. The received subvolume is created under basePath.
func (s *BtrfsStorage) ReceiveVolume(ctx context.Context, name string, r io.Reader) error {
	if err := s.receiveStream(ctx, s.basePath, r); err != nil {
		return fmt.Errorf("receive volume %s: %w", name, err)
	}
	// btrfs receive creates the subvolume with the original snapshot name.
	// Rename to the desired name if different.
	receivedPath := filepath.Join(s.basePath, name+".export-snap")
	targetPath := filepath.Join(s.basePath, name)

	if err := os.Rename(receivedPath, targetPath); err != nil {
		return fmt.Errorf("rename received volume: %w", err)
	}

	return s.setReadOnly(ctx, targetPath, false)
}

// sendStream writes a btrfs send stream, using the helper if configured.
func (s *BtrfsStorage) sendStream(ctx context.Context, snapPath string, w io.Writer) error {
	if s.btrfsHelper != "" {
		cmd := exec.CommandContext(ctx, s.btrfsHelper, "send", snapPath)
		cmd.Stdout = w
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("btrfs send %s: %w: %s", snapPath, err, stderr.String())
		}
		return nil
	}
	return btrfs.Send(snapPath, w)
}

// receiveStream reads a btrfs send stream, using the helper if configured.
func (s *BtrfsStorage) receiveStream(ctx context.Context, destDir string, r io.Reader) error {
	if s.btrfsHelper != "" {
		cmd := exec.CommandContext(ctx, s.btrfsHelper, "receive", destDir)
		cmd.Stdin = r
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("btrfs receive %s: %w: %s", destDir, err, stderr.String())
		}
		return nil
	}
	return btrfs.Receive(destDir, r)
}

// setReadOnly sets the read-only flag using the ioctl interface directly.
// This does not require the btrfs helper because BTRFS_IOC_SUBVOL_SETFLAGS
// works for user-owned subvolumes. It also avoids the CLI's safety check
// that rejects clearing read-only on received subvolumes without -f.
func (s *BtrfsStorage) setReadOnly(_ context.Context, path string, ro bool) error {
	return btrfs.SetReadOnly(path, ro)
}

// SnapshotVolume creates a read-only btrfs snapshot of the named volume.
// Snapshot is stored at basePath/.snapshots/<snapshotName>.
func (s *BtrfsStorage) SnapshotVolume(_ context.Context, volumeName, snapshotName string) error {
	snapshotsDir := filepath.Join(s.basePath, ".snapshots")
	if err := os.MkdirAll(snapshotsDir, 0755); err != nil {
		return fmt.Errorf("create snapshots dir: %w", err)
	}
	src := filepath.Join(s.basePath, volumeName)
	dest := filepath.Join(snapshotsDir, snapshotName)
	if err := btrfs.CreateSnapshot(src, dest, true); err != nil {
		return fmt.Errorf("snapshot volume %s: %w", volumeName, err)
	}
	return nil
}

// RestoreVolume replaces the named volume with a writable copy of the snapshot.
func (s *BtrfsStorage) RestoreVolume(_ context.Context, snapshotName, volumeName string) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	volPath := filepath.Join(s.basePath, volumeName)
	if err := btrfs.DeleteSubvolume(volPath); err != nil {
		return fmt.Errorf("delete volume for restore: %w", err)
	}
	if err := btrfs.CreateSnapshot(snapPath, volPath, false); err != nil {
		return fmt.Errorf("restore volume from snapshot: %w", err)
	}
	return nil
}

// CloneVolume materialises a writable copy of the named snapshot at a
// brand-new volume path. Fails if the destination already exists.
// Unlike RestoreVolume, this is non-destructive — it is the primitive
// behind CSI clone-from-snapshot semantics, where the "data source"
// is a snapshot and the resulting PVC is a fresh volume.
func (s *BtrfsStorage) CloneVolume(_ context.Context, snapshotName, newVolumeName string) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	volPath := filepath.Join(s.basePath, newVolumeName)
	if _, err := os.Stat(volPath); err == nil {
		return fmt.Errorf("clone target %s: %w", newVolumeName, os.ErrExist)
	}
	if err := btrfs.CreateSnapshot(snapPath, volPath, false); err != nil {
		return fmt.Errorf("clone volume %s from %s: %w", newVolumeName, snapshotName, err)
	}
	return nil
}

// DeleteVolumeSnapshot removes a read-only volume snapshot.
func (s *BtrfsStorage) DeleteVolumeSnapshot(_ context.Context, snapshotName string) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	if err := btrfs.DeleteSubvolume(snapPath); err != nil {
		return fmt.Errorf("delete volume snapshot %s: %w", snapshotName, err)
	}
	return nil
}

// SendVolumeSnapshot writes a btrfs send stream of the named snapshot.
func (s *BtrfsStorage) SendVolumeSnapshot(ctx context.Context, snapshotName string, w io.Writer) error {
	snapPath := filepath.Join(s.basePath, ".snapshots", snapshotName)
	return s.sendStream(ctx, snapPath, w)
}
