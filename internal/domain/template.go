// SPDX-License-Identifier: Apache-2.0
package domain

import "time"

// Template is a reusable provisioning script for bootstrapping VMs.
type Template struct {
	ID        string
	Name      string
	Distro    string // matches /etc/os-release ID field
	Script    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateTemplateParams holds parameters for creating a template.
type CreateTemplateParams struct {
	Name   string
	Distro string
	Script string
}
