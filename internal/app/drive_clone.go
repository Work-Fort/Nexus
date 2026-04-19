// SPDX-License-Identifier: GPL-3.0-or-later
package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/nxid"
)

// snapshotNameMax is the maximum allowed length of a generated
// intermediate snapshot name. Btrfs caps subvolume names at 255 bytes
// (BTRFS_SUBVOL_NAME_MAX) — pkg/btrfs.CreateSnapshot enforces this.
// We pick 240 to leave headroom for the "@clone-" prefix and a 26-byte
// nxid suffix without ever provoking ErrNameTooLong from the kernel.
const snapshotNameMax = 240

// CloneDriveParams is the CSI-shaped input for cloning a drive from a
// source volume reference. Maps 1:1 to a k8s PVC-from-VolumeSnapshot
// dataSource:
//
//	apiVersion: v1
//	kind: PersistentVolumeClaim
//	spec:
//	  dataSource:
//	    kind: VolumeSnapshot          // implicit; intermediate
//	    name: <SnapshotName>          // optional; auto-generated when empty
//	  resources:
//	    requests:
//	      storage: <inherited from source>
//
// SourceVolumeRef is the existing drive name or ID to clone from.
// Name is the new drive's name (must be unique; nxid.ValidateName).
// MountPath is OPTIONAL; if empty, the clone inherits the source's
// MountPath. CSI separates volume creation from mount-target
// declaration — Nexus stores MountPath per drive only because the
// attach step uses it.
// SnapshotName is the name of the intermediate VolumeSnapshot. If
// empty, an ephemeral snapshot is created and deleted after the clone.
// If non-empty, the snapshot is retained under that name (CSI
// semantics — caller owns its lifecycle).
type CloneDriveParams struct {
	SourceVolumeRef string
	Name            string
	MountPath       string // optional
	SnapshotName    string // optional
}

// CloneDrive creates a new drive that is a copy-on-write clone of an
// existing source drive. The source must not be attached to a VM. The
// new drive is unattached.
//
// Implementation: SnapshotVolume(src, intermediate) ->
// CloneVolume(intermediate, new) -> [optional] DeleteVolumeSnapshot.
func (s *VMService) CloneDrive(ctx context.Context, params CloneDriveParams) (*domain.Drive, error) {
	if s.storage == nil || s.driveStore == nil {
		return nil, fmt.Errorf("drives not enabled: %w", domain.ErrValidation)
	}
	if params.SourceVolumeRef == "" {
		return nil, fmt.Errorf("source_volume_ref is required: %w", domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(params.Name); err != nil {
		return nil, fmt.Errorf("invalid name: %v: %w", err, domain.ErrValidation)
	}

	src, err := s.driveStore.ResolveDrive(ctx, params.SourceVolumeRef)
	if err != nil {
		return nil, err // store wraps with ErrNotFound
	}
	if src.VMID != "" {
		return nil, fmt.Errorf("source drive %q is attached to VM %s: %w",
			src.Name, src.VMID, domain.ErrInvalidState)
	}

	if existing, err := s.driveStore.GetDriveByName(ctx, params.Name); err == nil && existing != nil {
		return nil, fmt.Errorf("drive name %q: %w", params.Name, domain.ErrAlreadyExists)
	}

	mountPath := params.MountPath
	if mountPath == "" {
		mountPath = src.MountPath
	}

	snapName := params.SnapshotName
	retainSnapshot := snapName != ""
	if !retainSnapshot {
		snapName = generateEphemeralSnapName(src.Name)
	}

	if err := s.storage.SnapshotVolume(ctx, src.Name, snapName); err != nil {
		return nil, fmt.Errorf("snapshot source %s: %w", src.Name, err)
	}

	if err := s.storage.CloneVolume(ctx, snapName, params.Name); err != nil {
		_ = s.storage.DeleteVolumeSnapshot(ctx, snapName)
		return nil, fmt.Errorf("clone into %s: %w", params.Name, err)
	}

	d := &domain.Drive{
		ID:        nxid.New(),
		Name:      params.Name,
		SizeBytes: src.SizeBytes,
		MountPath: mountPath,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.driveStore.CreateDrive(ctx, d); err != nil {
		_ = s.storage.DeleteVolume(ctx, params.Name)
		_ = s.storage.DeleteVolumeSnapshot(ctx, snapName)
		return nil, fmt.Errorf("persist cloned drive: %w", err)
	}

	if !retainSnapshot {
		if err := s.storage.DeleteVolumeSnapshot(ctx, snapName); err != nil {
			// Non-fatal: the clone succeeded. The orphan snapshot will
			// be cleaned up on next btrfs compaction.
			log.Warn("clone: failed to delete intermediate snapshot",
				"snapshot", snapName, "err", err)
		}
	}

	log.Info("drive cloned",
		"id", d.ID, "name", d.Name, "source", src.Name,
		"snapshot_retained", retainSnapshot)
	return d, nil
}

// generateEphemeralSnapName builds an intermediate snapshot name that
// stays inside btrfs's subvolume name cap. Format: "<src>@clone-<nxid>",
// truncating <src> from the right when the total would exceed
// snapshotNameMax. Truncation only affects internal naming — the
// generated name is opaque to callers.
func generateEphemeralSnapName(srcName string) string {
	suffix := "@clone-" + nxid.New()
	maxSrc := snapshotNameMax - len(suffix)
	if maxSrc < 1 {
		// nxid alone exceeds cap; should be unreachable but guard anyway.
		return strings.TrimPrefix(suffix, "@")
	}
	if len(srcName) > maxSrc {
		srcName = srcName[:maxSrc]
	}
	return srcName + suffix
}
