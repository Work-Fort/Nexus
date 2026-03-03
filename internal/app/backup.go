// SPDX-License-Identifier: Apache-2.0
package app

import "fmt"

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
