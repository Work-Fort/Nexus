// SPDX-License-Identifier: Apache-2.0
package app

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/bytesize"
)

const manifestVersion = 1

// ExportManifest describes the contents of a Nexus backup archive.
type ExportManifest struct {
	Version int              `json:"version"`
	VM      ManifestVM       `json:"vm"`
	Drives  []ManifestDrive  `json:"drives,omitempty"`
	Devices []ManifestDevice `json:"devices,omitempty"`
}

type ManifestVM struct {
	Name     string       `json:"name"`
	Role     string       `json:"role"`
	Image    string       `json:"image"`
	Runtime  string       `json:"runtime"`
	RootSize string       `json:"root_size,omitempty"`
	DNS      *ManifestDNS `json:"dns,omitempty"`
}

type ManifestDNS struct {
	Servers []string `json:"servers,omitempty"`
	Search  []string `json:"search,omitempty"`
}

type ManifestDrive struct {
	Name      string `json:"name"`
	Size      string `json:"size"`
	MountPath string `json:"mount_path"`
}

type ManifestDevice struct {
	Name          string `json:"name"`
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Permissions   string `json:"permissions"`
	GID           uint32 `json:"gid,omitempty"`
}

// Validate checks that the manifest has all required fields.
func (m *ExportManifest) Validate() error {
	if m.Version < 1 {
		return fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if m.VM.Name == "" {
		return fmt.Errorf("manifest: vm.name is required")
	}
	if m.VM.Role == "" {
		return fmt.Errorf("manifest: vm.role is required")
	}
	if m.VM.Image == "" {
		return fmt.Errorf("manifest: vm.image is required")
	}
	return nil
}

// ExportVM writes a tar.zst archive of the stopped VM and its drives to w.
// If includeDevices is true, device mappings are included in the manifest.
func (s *VMService) ExportVM(ctx context.Context, ref string, includeDevices bool, w io.Writer) error {
	vm, err := s.store.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return fmt.Errorf("VM %s is running, stop it before export: %w", vm.Name, domain.ErrInvalidState)
	}
	if s.storage == nil {
		return fmt.Errorf("storage backend not configured: %w", domain.ErrValidation)
	}

	// Build manifest.
	manifest := ExportManifest{
		Version: manifestVersion,
		VM: ManifestVM{
			Name:    vm.Name,
			Role:    string(vm.Role),
			Image:   vm.Image,
			Runtime: vm.Runtime,
		},
	}
	if vm.RootSize > 0 {
		manifest.VM.RootSize = bytesize.Format(uint64(vm.RootSize))
	}
	if vm.DNSConfig != nil {
		manifest.VM.DNS = &ManifestDNS{
			Servers: vm.DNSConfig.Servers,
			Search:  vm.DNSConfig.Search,
		}
	}

	// Drives.
	if s.driveStore != nil {
		drives, err := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		if err != nil {
			return fmt.Errorf("get drives: %w", err)
		}
		for _, d := range drives {
			manifest.Drives = append(manifest.Drives, ManifestDrive{
				Name:      d.Name,
				Size:      bytesize.Format(d.SizeBytes),
				MountPath: d.MountPath,
			})
		}
	}

	// Devices.
	if includeDevices && s.deviceStore != nil {
		devices, err := s.deviceStore.GetDevicesByVM(ctx, vm.ID)
		if err != nil {
			return fmt.Errorf("get devices: %w", err)
		}
		for _, d := range devices {
			manifest.Devices = append(manifest.Devices, ManifestDevice{
				Name:          d.Name,
				HostPath:      d.HostPath,
				ContainerPath: d.ContainerPath,
				Permissions:   d.Permissions,
				GID:           d.GID,
			})
		}
	}

	// Create tar.zst writer.
	zw, err := zstd.NewWriter(w)
	if err != nil {
		return fmt.Errorf("create zstd writer: %w", err)
	}
	defer zw.Close()
	tw := tar.NewWriter(zw)
	defer tw.Close()

	// Write manifest.json.
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: "manifest.json",
		Mode: 0644,
		Size: int64(len(manifestData)),
	}); err != nil {
		return err
	}
	if _, err := tw.Write(manifestData); err != nil {
		return err
	}

	// Write OCI image.
	var imgBuf bytes.Buffer
	if err := s.runtime.ExportImage(ctx, vm.Image, &imgBuf); err != nil {
		return fmt.Errorf("export image: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: "image.tar",
		Mode: 0644,
		Size: int64(imgBuf.Len()),
	}); err != nil {
		return err
	}
	if _, err := tw.Write(imgBuf.Bytes()); err != nil {
		return err
	}

	// Write drive btrfs send streams.
	for _, d := range manifest.Drives {
		var driveBuf bytes.Buffer
		if err := s.storage.SendVolume(ctx, d.Name, &driveBuf); err != nil {
			return fmt.Errorf("send drive %s: %w", d.Name, err)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: "drives/" + d.Name + ".btrfs",
			Mode: 0644,
			Size: int64(driveBuf.Len()),
		}); err != nil {
			return err
		}
		if _, err := tw.Write(driveBuf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}
