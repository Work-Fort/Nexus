// SPDX-License-Identifier: Apache-2.0

// Package domain defines the core types and port interfaces for Nexus.
// This package has zero dependencies on infrastructure — it defines
// what the system does, not how.
package domain

import (
	"errors"
	"time"
)

// VMState represents the lifecycle state of a VM.
type VMState string

const (
	VMStateCreated VMState = "created"
	VMStateRunning VMState = "running"
	VMStateStopped VMState = "stopped"
)

// RestartPolicy controls when a VM is automatically (re)started.
type RestartPolicy string

const (
	RestartPolicyNone   RestartPolicy = "none"
	RestartPolicyOnBoot RestartPolicy = "on-boot"
	RestartPolicyAlways RestartPolicy = "always"
)

// ValidRestartPolicy returns true if p is a recognized restart policy.
func ValidRestartPolicy(p RestartPolicy) bool {
	return p == RestartPolicyNone || p == RestartPolicyOnBoot || p == RestartPolicyAlways
}

// RestartStrategy controls the timing of automatic restarts.
type RestartStrategy string

const (
	RestartStrategyImmediate RestartStrategy = "immediate"
	RestartStrategyBackoff   RestartStrategy = "backoff"
	RestartStrategyFixed     RestartStrategy = "fixed"
)

// ValidRestartStrategy returns true if s is a recognized restart strategy.
func ValidRestartStrategy(s RestartStrategy) bool {
	return s == RestartStrategyImmediate || s == RestartStrategyBackoff || s == RestartStrategyFixed
}

// VM represents a managed virtual machine / container.
type VM struct {
	ID        string
	Name      string
	Tags      []string
	State     VMState
	Image     string
	Runtime   string
	IP        string
	Gateway   string
	NetNSPath string
	DNSConfig *DNSConfig
	RootSize        int64  // bytes, 0 = unlimited
	Shell           string // default shell for console, empty = /bin/sh
	RestartPolicy   RestartPolicy
	RestartStrategy RestartStrategy
	CreatedAt       time.Time
	StartedAt *time.Time
	StoppedAt *time.Time
}

// CreateVMParams holds parameters for creating a new VM.
type CreateVMParams struct {
	Name      string
	Tags      []string
	Image     string
	Runtime   string
	DNSConfig *DNSConfig
	RootSize        int64  // bytes, 0 = unlimited
	Shell           string // default shell for console, empty = /bin/sh
	RestartPolicy   RestartPolicy
	RestartStrategy RestartStrategy
}

// ExecResult holds the output of a command executed inside a VM.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// VMFilter constrains VM list queries.
type VMFilter struct {
	Tags     []string // tags to match
	TagMatch string   // "all" (default, AND) or "any" (OR)
}

// Sentinel errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidState  = errors.New("invalid state transition")
	ErrValidation    = errors.New("validation error")
)
