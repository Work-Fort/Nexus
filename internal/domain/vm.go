// SPDX-License-Identifier: Apache-2.0

// Package domain defines the core types and port interfaces for Nexus.
// This package has zero dependencies on infrastructure — it defines
// what the system does, not how.
package domain

import (
	"errors"
	"time"
)

// VMRole identifies what kind of workload runs in the VM.
type VMRole string

const (
	VMRoleAgent   VMRole = "agent"
	VMRoleService VMRole = "service"
)

// ValidRole returns true if r is a recognized VM role.
func ValidRole(r VMRole) bool {
	return r == VMRoleAgent || r == VMRoleService
}

// VMState represents the lifecycle state of a VM.
type VMState string

const (
	VMStateCreated VMState = "created"
	VMStateRunning VMState = "running"
	VMStateStopped VMState = "stopped"
)

// VM represents a managed virtual machine / container.
type VM struct {
	ID        string
	Name      string
	Role      VMRole
	State     VMState
	Image     string
	Runtime   string
	CreatedAt time.Time
	StartedAt *time.Time
	StoppedAt *time.Time
}

// CreateVMParams holds parameters for creating a new VM.
type CreateVMParams struct {
	Name    string
	Role    VMRole
	Image   string
	Runtime string
}

// ExecResult holds the output of a command executed inside a VM.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// VMFilter constrains VM list queries.
type VMFilter struct {
	Role *VMRole
}

// Sentinel errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidState  = errors.New("invalid state transition")
	ErrValidation    = errors.New("validation error")
)
