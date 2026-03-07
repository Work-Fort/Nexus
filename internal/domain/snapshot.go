// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import "time"

// Snapshot represents a point-in-time snapshot of a VM's rootfs and drives.
// Snapshots are immutable once created.
type Snapshot struct {
	ID        string
	VMID      string
	Name      string // unique per VM
	CreatedAt time.Time
}
