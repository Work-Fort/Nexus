// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

// DiskSpaceCheck monitors free disk space across one or more filesystem paths.
type DiskSpaceCheck struct {
	paths        []string
	interval     time.Duration
	warnBytes    uint64
	criticalBytes uint64
}

// NewDiskSpaceCheck returns a health check that monitors free disk space on the
// given paths. It reports degraded when free space drops below warnBytes and
// unhealthy when it drops below criticalBytes.
func NewDiskSpaceCheck(paths []string, interval time.Duration, warnBytes, criticalBytes uint64) *DiskSpaceCheck {
	return &DiskSpaceCheck{
		paths:         paths,
		interval:      interval,
		warnBytes:     warnBytes,
		criticalBytes: criticalBytes,
	}
}

// Name returns the health check identifier.
func (d *DiskSpaceCheck) Name() string { return "disk-space" }

// Interval returns how often the check should run.
func (d *DiskSpaceCheck) Interval() time.Duration { return d.interval }

// Check inspects free disk space on all configured paths and returns the
// result based on the lowest free space found.
func (d *DiskSpaceCheck) Check(_ context.Context) CheckResult {
	var lowestFree uint64 = math.MaxUint64
	var statErr error

	for _, path := range d.paths {
		var stat unix.Statfs_t
		if err := unix.Statfs(path, &stat); err != nil {
			statErr = fmt.Errorf("statfs %s: %w", path, err)
			continue
		}
		free := stat.Bavail * uint64(stat.Bsize)
		if free < lowestFree {
			lowestFree = free
		}
	}

	// If no path could be stat'd, report degraded.
	if lowestFree == math.MaxUint64 {
		msg := "no paths available"
		if statErr != nil {
			msg = statErr.Error()
		}
		return CheckResult{
			Status:  StatusDegraded,
			Message: msg,
		}
	}

	// If any path failed to stat but we got at least one, still report but note it.
	if statErr != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("stat error (%v); lowest free: %s", statErr, formatBytes(lowestFree)),
		}
	}

	if lowestFree < d.criticalBytes {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("critically low: %s free", formatBytes(lowestFree)),
		}
	}

	if lowestFree < d.warnBytes {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("low: %s free", formatBytes(lowestFree)),
		}
	}

	return CheckResult{
		Status:  StatusHealthy,
		Message: fmt.Sprintf("%s free", formatBytes(lowestFree)),
	}
}

// formatBytes formats a byte count as a human-readable string with one decimal
// place, using GB, MB, or KB units as appropriate.
func formatBytes(b uint64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)

	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	default:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	}
}
