// SPDX-License-Identifier: GPL-3.0-or-later
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/nxid"
)

// CreateSnapshot creates a point-in-time snapshot of the VM's rootfs and all
// attached drives. The VM may be running (crash-consistent) or stopped.
func (s *VMService) CreateSnapshot(ctx context.Context, vmRef, name string) (*domain.Snapshot, error) {
	if s.snapshotStore == nil {
		return nil, fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(name); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrValidation, err)
	}

	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return nil, err
	}

	snap := &domain.Snapshot{
		ID:        nxid.New(),
		VMID:      vm.ID,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}

	// Snapshot rootfs.
	rootfsSnapName := vm.ID + "@" + name
	if err := s.runtime.SnapshotRootfs(ctx, vm.ID, rootfsSnapName); err != nil {
		return nil, fmt.Errorf("snapshot rootfs: %w", err)
	}

	// Snapshot attached drives.
	if s.driveStore != nil && s.storage != nil {
		drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
			return nil, fmt.Errorf("get drives: %w", err)
		}
		for _, d := range drives {
			driveSnapName := d.Name + "@" + name
			if err := s.storage.SnapshotVolume(ctx, d.Name, driveSnapName); err != nil {
				s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
				s.cleanupDriveSnapshots(ctx, drives, name)
				return nil, fmt.Errorf("snapshot drive %s: %w", d.Name, err)
			}
		}
	}

	// Persist metadata.
	if err := s.snapshotStore.CreateSnapshot(ctx, snap); err != nil {
		s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck
		s.cleanupAllSnapshots(ctx, vm.ID, name)
		return nil, fmt.Errorf("persist snapshot: %w", err)
	}

	return snap, nil
}

// ListSnapshots returns all snapshots for a VM.
func (s *VMService) ListSnapshots(ctx context.Context, vmRef string) ([]*domain.Snapshot, error) {
	if s.snapshotStore == nil {
		return nil, fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return nil, err
	}
	return s.snapshotStore.ListSnapshots(ctx, vm.ID)
}

// DeleteSnapshot removes a snapshot and its on-disk data.
func (s *VMService) DeleteSnapshot(ctx context.Context, vmRef, snapRef string) error {
	if s.snapshotStore == nil {
		return fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return err
	}
	snap, err := s.resolveSnapshot(ctx, vm.ID, snapRef)
	if err != nil {
		return err
	}

	// Delete rootfs snapshot.
	rootfsSnapName := vm.ID + "@" + snap.Name
	s.runtime.DeleteRootfsSnapshot(ctx, rootfsSnapName) //nolint:errcheck

	// Delete drive snapshots.
	s.cleanupAllSnapshots(ctx, vm.ID, snap.Name)

	// Delete metadata.
	return s.snapshotStore.DeleteSnapshot(ctx, snap.ID)
}

// RestoreSnapshot rolls back a stopped VM to a previous snapshot.
func (s *VMService) RestoreSnapshot(ctx context.Context, vmRef, snapRef string) error {
	if s.snapshotStore == nil {
		return fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("stop VM before restore: %w", domain.ErrInvalidState)
	}
	snap, err := s.resolveSnapshot(ctx, vm.ID, snapRef)
	if err != nil {
		return err
	}

	// Restore rootfs.
	rootfsSnapName := vm.ID + "@" + snap.Name
	if err := s.runtime.RestoreRootfs(ctx, rootfsSnapName, vm.ID); err != nil {
		return fmt.Errorf("restore rootfs: %w", err)
	}

	// Restore drives.
	if s.driveStore != nil && s.storage != nil {
		drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			return fmt.Errorf("get drives: %w", err)
		}
		for _, d := range drives {
			driveSnapName := d.Name + "@" + snap.Name
			if err := s.storage.RestoreVolume(ctx, driveSnapName, d.Name); err != nil {
				return fmt.Errorf("restore drive %s: %w", d.Name, err)
			}
		}
	}

	return nil
}

// CloneSnapshot creates a new VM from a snapshot with new identity and network.
func (s *VMService) CloneSnapshot(ctx context.Context, vmRef, snapRef, newName string) (*domain.VM, error) {
	if s.snapshotStore == nil {
		return nil, fmt.Errorf("snapshots not configured: %w", domain.ErrValidation)
	}
	if err := nxid.ValidateName(newName); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrValidation, err)
	}

	vm, err := s.store.Resolve(ctx, vmRef)
	if err != nil {
		return nil, err
	}
	snap, err := s.resolveSnapshot(ctx, vm.ID, snapRef)
	if err != nil {
		return nil, err
	}

	// Check name conflict.
	if _, err := s.store.GetByName(ctx, newName); err == nil {
		return nil, fmt.Errorf("VM name %q: %w", newName, domain.ErrAlreadyExists)
	}

	newID := nxid.New()

	// Network setup for new VM.
	netInfo, err := s.network.Setup(ctx, newID)
	if err != nil {
		return nil, fmt.Errorf("setup network: %w", err)
	}

	// Create containerd container (pulls image, gets fresh snapshot layer).
	createOpts := []domain.CreateOpt{}
	if netInfo.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(netInfo.NetNSPath))
	}
	if err := s.runtime.Create(ctx, newID, vm.Image, vm.Runtime, createOpts...); err != nil {
		s.network.Teardown(ctx, newID) //nolint:errcheck
		return nil, fmt.Errorf("create container: %w", err)
	}

	// Replace rootfs with snapshot data.
	rootfsSnapName := vm.ID + "@" + snap.Name
	if err := s.runtime.RestoreRootfs(ctx, rootfsSnapName, newID); err != nil {
		s.runtime.Delete(ctx, newID)   //nolint:errcheck
		s.network.Teardown(ctx, newID) //nolint:errcheck
		return nil, fmt.Errorf("restore rootfs for clone: %w", err)
	}

	// Clone drives.
	var clonedDrives []*domain.Drive
	if s.driveStore != nil && s.storage != nil {
		srcDrives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			s.runtime.Delete(ctx, newID)   //nolint:errcheck
			s.network.Teardown(ctx, newID) //nolint:errcheck
			return nil, fmt.Errorf("get source drives: %w", err)
		}
		for _, d := range srcDrives {
			newDriveName := newName + "-" + d.Name
			driveSnapName := d.Name + "@" + snap.Name
			if err := s.storage.RestoreVolume(ctx, driveSnapName, newDriveName); err != nil {
				for _, cd := range clonedDrives {
					s.storage.DeleteVolume(ctx, cd.Name) //nolint:errcheck
				}
				s.runtime.Delete(ctx, newID)   //nolint:errcheck
				s.network.Teardown(ctx, newID) //nolint:errcheck
				return nil, fmt.Errorf("clone drive %s: %w", d.Name, err)
			}
			newDrive := &domain.Drive{
				ID:        nxid.New(),
				Name:      newDriveName,
				SizeBytes: d.SizeBytes,
				MountPath: d.MountPath,
				VMID:      newID,
				CreatedAt: time.Now().UTC(),
			}
			if err := s.driveStore.CreateDrive(ctx, newDrive); err != nil {
				s.storage.DeleteVolume(ctx, newDriveName) //nolint:errcheck
				for _, cd := range clonedDrives {
					s.storage.DeleteVolume(ctx, cd.Name) //nolint:errcheck
				}
				s.runtime.Delete(ctx, newID)   //nolint:errcheck
				s.network.Teardown(ctx, newID) //nolint:errcheck
				return nil, fmt.Errorf("persist cloned drive: %w", err)
			}
			clonedDrives = append(clonedDrives, newDrive)
		}
	}

	// Create VM record.
	newVM := &domain.VM{
		ID:              newID,
		Name:            newName,
		Image:           vm.Image,
		Runtime:         vm.Runtime,
		State:           domain.VMStateCreated,
		RootSize:        vm.RootSize,
		Shell:           vm.Shell,
		RestartPolicy:   vm.RestartPolicy,
		RestartStrategy: vm.RestartStrategy,
		Init:            vm.Init,
		TemplateID:      vm.TemplateID,
		CreatedAt:       time.Now().UTC(),
	}
	if netInfo.IP != "" {
		newVM.IP = netInfo.IP
		newVM.Gateway = netInfo.Gateway
		newVM.NetNSPath = netInfo.NetNSPath
	}

	if err := s.store.Create(ctx, newVM); err != nil {
		for _, cd := range clonedDrives {
			s.storage.DeleteVolume(ctx, cd.Name) //nolint:errcheck
		}
		s.runtime.Delete(ctx, newID)   //nolint:errcheck
		s.network.Teardown(ctx, newID) //nolint:errcheck
		return nil, fmt.Errorf("persist cloned VM: %w", err)
	}

	// Recreate container with drives mounted.
	if len(clonedDrives) > 0 {
		if err := s.recreateContainer(ctx, newVM); err != nil {
			return newVM, fmt.Errorf("recreate container with drives: %w", err)
		}
	}

	// DNS record for clone.
	if s.dns != nil && newVM.IP != "" {
		s.dns.AddRecord(ctx, newVM.Name, newVM.IP) //nolint:errcheck
	}

	return newVM, nil
}

// resolveSnapshot finds a snapshot by ID or name within a VM.
func (s *VMService) resolveSnapshot(ctx context.Context, vmID, ref string) (*domain.Snapshot, error) {
	// Try by ID first.
	snap, err := s.snapshotStore.GetSnapshot(ctx, ref)
	if err == nil && snap.VMID == vmID {
		return snap, nil
	}
	// Try by name.
	snap, err = s.snapshotStore.GetSnapshotByName(ctx, vmID, ref)
	if err != nil {
		return nil, fmt.Errorf("snapshot %q: %w", ref, domain.ErrNotFound)
	}
	return snap, nil
}

// cleanupDriveSnapshots removes drive snapshots for drives that were already
// snapshotted. Used for rollback during CreateSnapshot.
func (s *VMService) cleanupDriveSnapshots(ctx context.Context, drives []*domain.Drive, snapName string) {
	if s.storage == nil {
		return
	}
	for _, d := range drives {
		driveSnapName := d.Name + "@" + snapName
		s.storage.DeleteVolumeSnapshot(ctx, driveSnapName) //nolint:errcheck
	}
}

// cleanupAllSnapshots removes all drive snapshots for a VM snapshot name.
func (s *VMService) cleanupAllSnapshots(ctx context.Context, vmID, snapName string) {
	if s.driveStore == nil || s.storage == nil {
		return
	}
	drives, err := s.driveStore.GetDrivesByVM(ctx, vmID)
	if err != nil {
		return
	}
	s.cleanupDriveSnapshots(ctx, drives, snapName)
}
