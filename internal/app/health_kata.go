// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

type hypervisorConfig struct {
	Kernel string `toml:"kernel"`
}

type kataConfig struct {
	Hypervisor struct {
		QEMU        hypervisorConfig `toml:"qemu"`
		Firecracker hypervisorConfig `toml:"firecracker"`
	} `toml:"hypervisor"`
}

// KataKernelCheck validates that a Kata Containers kernel is present and
// matches the expected Anvil version.
type KataKernelCheck struct {
	expectedVersion string
	interval        time.Duration
	configPaths     []string
}

// NewKataKernelCheck returns a health check that verifies the Kata kernel
// configuration. If no configPaths are provided, it defaults to the standard
// Kata configuration locations.
func NewKataKernelCheck(expectedVersion string, interval time.Duration, configPaths ...string) *KataKernelCheck {
	if len(configPaths) == 0 {
		configPaths = []string{
			"/etc/kata-containers/configuration.toml",
			"/opt/kata/share/defaults/kata-containers/configuration.toml",
		}
	}
	return &KataKernelCheck{
		expectedVersion: expectedVersion,
		interval:        interval,
		configPaths:     configPaths,
	}
}

// Name returns the health check identifier.
func (k *KataKernelCheck) Name() string { return "kata-kernel" }

// Interval returns how often the check should run.
func (k *KataKernelCheck) Interval() time.Duration { return k.interval }

// Check inspects the Kata configuration to verify the kernel is present and
// matches the expected version.
func (k *KataKernelCheck) Check(_ context.Context) CheckResult {
	// Find the first existing config file.
	var configPath string
	for _, p := range k.configPaths {
		if _, err := os.Stat(p); err == nil {
			configPath = p
			break
		}
	}
	if configPath == "" {
		return CheckResult{
			Status:  StatusDegraded,
			Message: "no Kata configuration found",
		}
	}

	// Read and parse the TOML config.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("failed to read config %s: %v", configPath, err),
		}
	}

	var cfg kataConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("failed to parse config %s: %v", configPath, err),
		}
	}

	// Extract kernel path: prefer QEMU, fall back to Firecracker.
	kernelPath := cfg.Hypervisor.QEMU.Kernel
	if kernelPath == "" {
		kernelPath = cfg.Hypervisor.Firecracker.Kernel
	}
	if kernelPath == "" {
		return CheckResult{
			Status:  StatusDegraded,
			Message: "no kernel path configured",
		}
	}

	// Check the kernel file exists.
	if _, err := os.Stat(kernelPath); err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("kernel not found: %s", kernelPath),
		}
	}

	// Verify the kernel path contains the expected version.
	if !strings.Contains(kernelPath, k.expectedVersion) {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("kernel %s does not match expected version %s", kernelPath, k.expectedVersion),
		}
	}

	return CheckResult{
		Status:  StatusHealthy,
		Message: fmt.Sprintf("Anvil kernel %s configured", kernelPath),
	}
}
