// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

// linuxVersionRe matches the "Linux version X.Y.Z" string embedded in kernel binaries.
var linuxVersionRe = regexp.MustCompile(`Linux version (\S+)`)

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

	// Read the kernel binary and extract the embedded version string.
	data, err = os.ReadFile(kernelPath)
	if err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("kernel not found: %s", kernelPath),
		}
	}

	match := linuxVersionRe.FindSubmatch(data)
	if match == nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("could not extract version from kernel %s", kernelPath),
		}
	}

	foundVersion := string(match[1])
	if !versionAtLeast(foundVersion, k.expectedVersion) {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("kernel %s has version %s, minimum required %s", kernelPath, foundVersion, k.expectedVersion),
		}
	}

	return CheckResult{
		Status:  StatusHealthy,
		Message: fmt.Sprintf("Anvil kernel %s (%s)", kernelPath, foundVersion),
	}
}

// versionAtLeast returns true if version >= minimum, comparing numeric
// components (e.g. "6.19.7" >= "6.19.6"). Suffixes like "-anvil" are
// stripped before comparison.
func versionAtLeast(version, minimum string) bool {
	parse := func(s string) []int {
		// Strip any suffix after the numeric part (e.g. "6.19.6-anvil" → "6.19.6").
		if idx := strings.IndexFunc(s, func(r rune) bool {
			return r != '.' && (r < '0' || r > '9')
		}); idx > 0 {
			s = s[:idx]
		}
		var parts []int
		for _, p := range strings.Split(s, ".") {
			n, _ := strconv.Atoi(p)
			parts = append(parts, n)
		}
		return parts
	}

	v := parse(version)
	m := parse(minimum)

	for i := 0; i < len(m); i++ {
		vi := 0
		if i < len(v) {
			vi = v[i]
		}
		if vi < m[i] {
			return false
		}
		if vi > m[i] {
			return true
		}
	}
	return true
}
