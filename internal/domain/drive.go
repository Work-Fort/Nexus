// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import "time"

// Drive represents a persistent data volume backed by a btrfs subvolume.
type Drive struct {
	ID        string
	Name      string
	SizeBytes uint64
	MountPath string // where it mounts inside the VM
	VMID      string // attached VM ID, empty if detached
	CreatedAt time.Time
}

// CreateDriveParams holds parameters for creating a new drive.
type CreateDriveParams struct {
	Name      string // unique name
	Size      string // "1G", "500Mi", or raw bytes
	MountPath string // e.g. "/data"
}
