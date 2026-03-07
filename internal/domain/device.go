// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import "time"

// Device represents a host device mapping that can be attached to a VM.
type Device struct {
	ID            string
	Name          string // user-chosen name for the device mapping
	HostPath      string // e.g. "/dev/vfio/42", "/dev/dri/renderD128"
	ContainerPath string // path inside the container
	Permissions   string // cgroup device access: "rwm", "rw", "r"
	GID           uint32 // GID for device node inside container (0 = root)
	VMID          string // attached VM ID, empty = unattached
	CreatedAt     time.Time
}

// CreateDeviceParams holds parameters for registering a new device mapping.
type CreateDeviceParams struct {
	Name          string
	HostPath      string
	ContainerPath string
	Permissions   string
	GID           uint32
}
