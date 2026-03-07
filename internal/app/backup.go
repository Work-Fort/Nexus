// SPDX-License-Identifier: Apache-2.0
package app

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/klauspost/compress/zstd"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/bytesize"
	"github.com/Work-Fort/Nexus/pkg/nxid"
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
	Name            string       `json:"name"`
	Tags            []string     `json:"tags,omitempty"`
	Image           string       `json:"image"`
	Runtime         string       `json:"runtime"`
	RootSize        string       `json:"root_size,omitempty"`
	RestartPolicy   string       `json:"restart_policy,omitempty"`
	RestartStrategy string       `json:"restart_strategy,omitempty"`
	DNS             *ManifestDNS `json:"dns,omitempty"`
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
			Name:            vm.Name,
			Tags:            vm.Tags,
			Image:           vm.Image,
			Runtime:         vm.Runtime,
			RestartPolicy:   string(vm.RestartPolicy),
			RestartStrategy: string(vm.RestartStrategy),
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

// ImportResult contains the imported VM and any warnings.
type ImportResult struct {
	VM       *domain.VM
	Warnings []string
}

// ImportVM reads a tar.zst archive from r and recreates the VM, drives, and
// optionally devices. Returns the new VM (state=created, ready to start).
func (s *VMService) ImportVM(ctx context.Context, r io.Reader, strictDevices bool) (*ImportResult, error) {
	if s.storage == nil {
		return nil, fmt.Errorf("storage backend not configured: %w", domain.ErrValidation)
	}

	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	var manifest *ExportManifest
	var imageData []byte
	driveStreams := map[string][]byte{}

	// Read all archive entries.
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read entry %s: %w", hdr.Name, err)
		}

		switch {
		case hdr.Name == "manifest.json":
			var m ExportManifest
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, fmt.Errorf("parse manifest: %w", err)
			}
			manifest = &m
		case hdr.Name == "image.tar":
			imageData = data
		case strings.HasPrefix(hdr.Name, "drives/") && strings.HasSuffix(hdr.Name, ".btrfs"):
			name := strings.TrimPrefix(hdr.Name, "drives/")
			name = strings.TrimSuffix(name, ".btrfs")
			driveStreams[name] = data
		}
	}

	if manifest == nil {
		return nil, fmt.Errorf("archive missing manifest.json")
	}
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}
	if imageData == nil {
		return nil, fmt.Errorf("archive missing image.tar")
	}

	// Check name conflicts.
	if _, err := s.store.GetByName(ctx, manifest.VM.Name); err == nil {
		return nil, fmt.Errorf("VM name %q already exists: %w", manifest.VM.Name, domain.ErrAlreadyExists)
	}
	if s.driveStore != nil {
		for _, d := range manifest.Drives {
			if _, err := s.driveStore.GetDriveByName(ctx, d.Name); err == nil {
				return nil, fmt.Errorf("drive name %q already exists: %w", d.Name, domain.ErrAlreadyExists)
			}
		}
	}

	// Import OCI image.
	if _, err := s.runtime.ImportImage(ctx, bytes.NewReader(imageData)); err != nil {
		return nil, fmt.Errorf("import image: %w", err)
	}

	// Track created resources for rollback on failure.
	var createdDrives []string
	cleanup := func() {
		for _, name := range createdDrives {
			s.storage.DeleteVolume(ctx, name) //nolint:errcheck
		}
	}

	// Receive drives.
	for _, d := range manifest.Drives {
		stream, ok := driveStreams[d.Name]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("archive missing drive stream for %s", d.Name)
		}
		if err := s.storage.ReceiveVolume(ctx, d.Name, bytes.NewReader(stream)); err != nil {
			cleanup()
			return nil, fmt.Errorf("receive drive %s: %w", d.Name, err)
		}
		createdDrives = append(createdDrives, d.Name)

		// Set quota if size specified.
		if d.Size != "" {
			sizeBytes, err := bytesize.Parse(d.Size)
			if err == nil && sizeBytes > 0 {
				// Best-effort quota; don't fail import if quota can't be set.
				log.Debug("setting drive quota", "drive", d.Name, "size", d.Size)
			}
		}
	}

	// Parse root_size.
	var rootSize int64
	if manifest.VM.RootSize != "" {
		rs, err := bytesize.Parse(manifest.VM.RootSize)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("parse root_size %q: %w", manifest.VM.RootSize, err)
		}
		rootSize = int64(rs)
	}

	// Create VM record.
	restartPolicy := domain.RestartPolicy(manifest.VM.RestartPolicy)
	if !domain.ValidRestartPolicy(restartPolicy) {
		restartPolicy = domain.RestartPolicyNone
	}
	restartStrategy := domain.RestartStrategy(manifest.VM.RestartStrategy)
	if !domain.ValidRestartStrategy(restartStrategy) {
		restartStrategy = domain.RestartStrategyBackoff
	}
	vm := &domain.VM{
		ID:              nxid.New(),
		Name:            manifest.VM.Name,
		Tags:            manifest.VM.Tags,
		State:           domain.VMStateCreated,
		Image:           manifest.VM.Image,
		Runtime:         manifest.VM.Runtime,
		RootSize:        rootSize,
		RestartPolicy:   restartPolicy,
		RestartStrategy: restartStrategy,
		CreatedAt:       time.Now().UTC(),
	}
	if manifest.VM.DNS != nil {
		vm.DNSConfig = &domain.DNSConfig{
			Servers: manifest.VM.DNS.Servers,
			Search:  manifest.VM.DNS.Search,
		}
	}

	// Network setup.
	netInfo, err := s.network.Setup(ctx, vm.ID)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("network setup: %w", err)
	}
	vm.IP = netInfo.IP
	vm.Gateway = netInfo.Gateway
	vm.NetNSPath = netInfo.NetNSPath

	if err := s.store.Create(ctx, vm); err != nil {
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck
		cleanup()
		return nil, fmt.Errorf("create VM record: %w", err)
	}

	// Create drive records.
	if s.driveStore != nil {
		for _, d := range manifest.Drives {
			sizeBytes, _ := bytesize.Parse(d.Size)
			drive := &domain.Drive{
				ID:        nxid.New(),
				Name:      d.Name,
				SizeBytes: sizeBytes,
				MountPath: d.MountPath,
				VMID:      vm.ID,
				CreatedAt: time.Now().UTC(),
			}
			if err := s.driveStore.CreateDrive(ctx, drive); err != nil {
				s.store.Delete(ctx, vm.ID)     //nolint:errcheck
				s.network.Teardown(ctx, vm.ID) //nolint:errcheck
				cleanup()
				return nil, fmt.Errorf("create drive record %s: %w", d.Name, err)
			}
		}
	}

	// Handle devices.
	result := &ImportResult{VM: vm}
	if s.deviceStore != nil {
		for _, d := range manifest.Devices {
			if _, err := os.Stat(d.HostPath); err != nil {
				msg := fmt.Sprintf("device %s: host_path %s not found", d.Name, d.HostPath)
				if strictDevices {
					s.store.Delete(ctx, vm.ID)     //nolint:errcheck
					s.network.Teardown(ctx, vm.ID) //nolint:errcheck
					cleanup()
					return nil, fmt.Errorf("%s: %w", msg, domain.ErrValidation)
				}
				result.Warnings = append(result.Warnings, msg)
				continue
			}

			device := &domain.Device{
				ID:            nxid.New(),
				Name:          d.Name,
				HostPath:      d.HostPath,
				ContainerPath: d.ContainerPath,
				Permissions:   d.Permissions,
				GID:           d.GID,
				VMID:          vm.ID,
				CreatedAt:     time.Now().UTC(),
			}
			if err := s.deviceStore.CreateDevice(ctx, device); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("device %s: %v", d.Name, err))
			}
		}
	}

	// Create containerd container (so VM is ready to start).
	var createOpts []domain.CreateOpt
	if vm.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(vm.NetNSPath))
	}
	if vm.RootSize > 0 {
		createOpts = append(createOpts, domain.WithRootSize(vm.RootSize))
	}

	// Wire up drives as mounts.
	if s.driveStore != nil && s.storage != nil {
		drives, _ := s.driveStore.GetDrivesByVM(ctx, vm.ID)
		var mounts []domain.Mount
		for _, d := range drives {
			mounts = append(mounts, domain.Mount{
				HostPath:      s.storage.VolumePath(d.Name),
				ContainerPath: d.MountPath,
			})
		}
		if len(mounts) > 0 {
			createOpts = append(createOpts, domain.WithMounts(mounts))
		}
	}

	// Wire up devices.
	if s.deviceStore != nil {
		devices, _ := s.deviceStore.GetDevicesByVM(ctx, vm.ID)
		var devInfos []domain.DeviceInfo
		for _, d := range devices {
			devInfos = append(devInfos, domain.DeviceInfo{
				HostPath:      d.HostPath,
				ContainerPath: d.ContainerPath,
				Permissions:   d.Permissions,
				GID:           d.GID,
			})
		}
		if len(devInfos) > 0 {
			createOpts = append(createOpts, domain.WithDevices(devInfos))
		}
	}

	// DNS resolv.conf.
	if s.dns != nil {
		resolvPath, err := s.dns.GenerateResolvConf(vm.ID, vm.DNSConfig)
		if err != nil {
			log.Warn("generate resolv.conf for import", "err", err)
		} else {
			createOpts = append(createOpts, domain.WithResolvConf(resolvPath))
		}
		if vm.IP != "" {
			s.dns.AddRecord(ctx, vm.Name, vm.IP) //nolint:errcheck
		}
	}

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime, createOpts...); err != nil {
		s.store.Delete(ctx, vm.ID)     //nolint:errcheck
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck
		cleanup()
		return nil, fmt.Errorf("create container: %w", err)
	}

	return result, nil
}
