# Health Service Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a global health service that runs periodic background checks (Kata kernel, containerd, disk space), exposes `GET /health` (200/218/503), and gates VM creation on runtime health.

**Architecture:** A `HealthService` in `internal/app/` holds a registry of `HealthCheck` implementations. Each check runs in its own background goroutine at a configurable interval, caching results behind a `sync.RWMutex`. VM creation consults cached state to block requests for unhealthy runtimes. The HTTP handler reads cached state for `GET /health`.

**Tech Stack:** Go stdlib (`sync`, `syscall`, `time`), `pelletier/go-toml/v2` (already indirect dep via viper), containerd client `Version()` for liveness.

---

### Task 1: Health domain types and HealthService core

**Files:**
- Create: `internal/app/health.go`
- Create: `internal/app/health_test.go`

**Step 1: Write the failing test**

```go
// internal/app/health_test.go
package app

import (
	"context"
	"sync"
	"testing"
	"time"
)

type stubCheck struct {
	name     string
	interval time.Duration
	result   CheckResult
	mu       sync.Mutex
}

func (s *stubCheck) Name() string            { return s.name }
func (s *stubCheck) Interval() time.Duration  { return s.interval }
func (s *stubCheck) Check(context.Context) CheckResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result
}
func (s *stubCheck) setResult(r CheckResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = r
}

func TestHealthServiceStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	check := &stubCheck{
		name:     "test-check",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusHealthy, Message: "ok"},
	}

	hs := NewHealthService(check)
	hs.Start(ctx)
	defer hs.Stop()

	// Wait for initial check to run.
	time.Sleep(100 * time.Millisecond)

	status := hs.Status()
	if status.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s", status.Status)
	}
	if len(status.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(status.Checks))
	}
	if status.Checks["test-check"].Status != StatusHealthy {
		t.Fatalf("expected test-check healthy, got %s", status.Checks["test-check"].Status)
	}
}

func TestHealthServiceDegraded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	healthy := &stubCheck{
		name:     "healthy-check",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusHealthy, Message: "ok"},
	}
	degraded := &stubCheck{
		name:     "degraded-check",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusDegraded, Message: "warning"},
	}

	hs := NewHealthService(healthy, degraded)
	hs.Start(ctx)
	defer hs.Stop()

	time.Sleep(100 * time.Millisecond)

	status := hs.Status()
	if status.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s", status.Status)
	}
}

func TestHealthServiceUnhealthy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	degraded := &stubCheck{
		name:     "degraded",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusDegraded, Message: "warning"},
	}
	unhealthy := &stubCheck{
		name:     "unhealthy",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusUnhealthy, Message: "down"},
	}

	hs := NewHealthService(degraded, unhealthy)
	hs.Start(ctx)
	defer hs.Stop()

	time.Sleep(100 * time.Millisecond)

	status := hs.Status()
	if status.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy, got %s", status.Status)
	}
}

func TestHealthServicePeriodicUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	check := &stubCheck{
		name:     "flapping",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusHealthy, Message: "ok"},
	}

	hs := NewHealthService(check)
	hs.Start(ctx)
	defer hs.Stop()

	time.Sleep(100 * time.Millisecond)
	if hs.Status().Status != StatusHealthy {
		t.Fatal("expected healthy initially")
	}

	check.setResult(CheckResult{Status: StatusDegraded, Message: "oops"})
	time.Sleep(100 * time.Millisecond)

	if hs.Status().Status != StatusDegraded {
		t.Fatal("expected degraded after update")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/app && go test -run TestHealthService -v -count=1`
Expected: FAIL — types and functions don't exist yet.

**Step 3: Write minimal implementation**

```go
// internal/app/health.go
package app

import (
	"context"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

// HealthStatus represents the status of a health check.
type HealthStatus string

const (
	StatusHealthy   HealthStatus = "healthy"
	StatusDegraded  HealthStatus = "degraded"
	StatusUnhealthy HealthStatus = "unhealthy"
)

// CheckResult is the result of a single health check.
type CheckResult struct {
	Status  HealthStatus `json:"status"`
	Message string       `json:"message"`
}

// HealthCheck is the interface that individual health checks implement.
type HealthCheck interface {
	Name() string
	Interval() time.Duration
	Check(ctx context.Context) CheckResult
}

// HealthReport is the aggregate health status with per-check results.
type HealthReport struct {
	Status HealthStatus           `json:"status"`
	Checks map[string]CheckResult `json:"checks"`
}

// HealthService runs health checks periodically and caches results.
type HealthService struct {
	checks  []HealthCheck
	results map[string]CheckResult
	mu      sync.RWMutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewHealthService creates a HealthService with the given checks.
func NewHealthService(checks ...HealthCheck) *HealthService {
	results := make(map[string]CheckResult, len(checks))
	for _, c := range checks {
		results[c.Name()] = CheckResult{Status: StatusHealthy, Message: "pending"}
	}
	return &HealthService{
		checks:  checks,
		results: results,
	}
}

// Start runs all health checks immediately, then starts periodic background goroutines.
func (h *HealthService) Start(ctx context.Context) {
	ctx, h.cancel = context.WithCancel(ctx)

	// Run all checks once synchronously at startup.
	for _, c := range h.checks {
		result := c.Check(ctx)
		h.mu.Lock()
		h.results[c.Name()] = result
		h.mu.Unlock()
		log.Info("health check", "name", c.Name(), "status", result.Status, "message", result.Message)
	}

	// Start periodic goroutines.
	for _, c := range h.checks {
		h.wg.Add(1)
		go h.runCheck(ctx, c)
	}
}

// Stop cancels all background checks and waits for them to finish.
func (h *HealthService) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
	h.wg.Wait()
}

// Status returns the aggregate health report from cached results.
func (h *HealthService) Status() HealthReport {
	h.mu.RLock()
	defer h.mu.RUnlock()

	checks := make(map[string]CheckResult, len(h.results))
	aggregate := StatusHealthy
	for name, result := range h.results {
		checks[name] = result
		if result.Status == StatusUnhealthy {
			aggregate = StatusUnhealthy
		} else if result.Status == StatusDegraded && aggregate != StatusUnhealthy {
			aggregate = StatusDegraded
		}
	}
	return HealthReport{Status: aggregate, Checks: checks}
}

func (h *HealthService) runCheck(ctx context.Context, c HealthCheck) {
	defer h.wg.Done()
	ticker := time.NewTicker(c.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result := c.Check(ctx)
			h.mu.Lock()
			prev := h.results[c.Name()]
			h.results[c.Name()] = result
			h.mu.Unlock()
			if prev.Status != result.Status {
				log.Info("health check changed", "name", c.Name(), "status", result.Status, "message", result.Message)
			}
		}
	}
}
```

**Step 4: Run test to verify it passes**

Run: `cd internal/app && go test -run TestHealthService -v -count=1`
Expected: PASS — all 4 tests pass.

**Step 5: Commit**

```bash
git add internal/app/health.go internal/app/health_test.go
git commit -m "feat: add HealthService core with periodic background checks"
```

---

### Task 2: Kata kernel health check

**Files:**
- Create: `internal/app/health_kata.go`
- Create: `internal/app/health_kata_test.go`

**Context:** The Kata kernel check parses Kata's TOML config to extract the `kernel` path, then verifies the file exists and the filename contains the expected Anvil kernel version. Kata reads `/etc/kata-containers/configuration.toml` first, falling back to `/opt/kata/share/defaults/kata-containers/configuration.toml`.

**Step 1: Write the failing test**

```go
// internal/app/health_kata_test.go
package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKataKernelCheckHealthy(t *testing.T) {
	// Create a temp dir with a fake Kata config and kernel file.
	dir := t.TempDir()
	kernelPath := filepath.Join(dir, "vmlinux-6.19.6-x86_64")
	if err := os.WriteFile(kernelPath, []byte("fake-kernel"), 0644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "configuration.toml")
	configContent := `[hypervisor.qemu]
kernel = "` + kernelPath + `"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	check := NewKataKernelCheck("6.19.6", 30*time.Second, configPath)
	result := check.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
}

func TestKataKernelCheckDegradedWrongVersion(t *testing.T) {
	dir := t.TempDir()
	kernelPath := filepath.Join(dir, "vmlinux.container")
	if err := os.WriteFile(kernelPath, []byte("stock-kernel"), 0644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "configuration.toml")
	configContent := `[hypervisor.qemu]
kernel = "` + kernelPath + `"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	check := NewKataKernelCheck("6.19.6", 30*time.Second, configPath)
	result := check.Check(context.Background())

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
}

func TestKataKernelCheckDegradedMissingFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "configuration.toml")
	configContent := `[hypervisor.qemu]
kernel = "/nonexistent/vmlinux-6.19.6-x86_64"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	check := NewKataKernelCheck("6.19.6", 30*time.Second, configPath)
	result := check.Check(context.Background())

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
}

func TestKataKernelCheckDegradedNoConfig(t *testing.T) {
	check := NewKataKernelCheck("6.19.6", 30*time.Second, "/nonexistent/config.toml")
	result := check.Check(context.Background())

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
}

func TestKataKernelCheckFirecrackerHypervisor(t *testing.T) {
	dir := t.TempDir()
	kernelPath := filepath.Join(dir, "vmlinux-6.19.6-x86_64")
	if err := os.WriteFile(kernelPath, []byte("fake-kernel"), 0644); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "configuration.toml")
	configContent := `[hypervisor.firecracker]
kernel = "` + kernelPath + `"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	check := NewKataKernelCheck("6.19.6", 30*time.Second, configPath)
	result := check.Check(context.Background())

	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/app && go test -run TestKataKernelCheck -v -count=1`
Expected: FAIL — `NewKataKernelCheck` doesn't exist.

**Step 3: Write minimal implementation**

```go
// internal/app/health_kata.go
package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

// kataConfig is the minimal structure for parsing Kata's configuration.toml.
type kataConfig struct {
	Hypervisor struct {
		QEMU        hypervisorConfig `toml:"qemu"`
		Firecracker hypervisorConfig `toml:"firecracker"`
	} `toml:"hypervisor"`
}

type hypervisorConfig struct {
	Kernel string `toml:"kernel"`
}

// KataKernelCheck validates that Kata is configured with the expected Anvil kernel.
type KataKernelCheck struct {
	expectedVersion string
	interval        time.Duration
	configPaths     []string // ordered: first found wins
}

// NewKataKernelCheck creates a Kata kernel health check. configPaths are tried
// in order; the first existing file is used. If no paths are provided, the
// standard Kata config locations are used.
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

func (k *KataKernelCheck) Name() string            { return "kata-kernel" }
func (k *KataKernelCheck) Interval() time.Duration  { return k.interval }

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

	data, err := os.ReadFile(configPath)
	if err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("cannot read %s: %v", configPath, err),
		}
	}

	var cfg kataConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("cannot parse %s: %v", configPath, err),
		}
	}

	// Check QEMU first, then Firecracker.
	kernelPath := cfg.Hypervisor.QEMU.Kernel
	if kernelPath == "" {
		kernelPath = cfg.Hypervisor.Firecracker.Kernel
	}
	if kernelPath == "" {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("no kernel path in %s", configPath),
		}
	}

	// Check that the kernel file exists.
	if _, err := os.Stat(kernelPath); err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("kernel not found: %s", kernelPath),
		}
	}

	// Check that the kernel path contains the expected version.
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
```

**Step 4: Run test to verify it passes**

Run: `cd internal/app && go test -run TestKataKernelCheck -v -count=1`
Expected: PASS — all 5 tests pass.

**Step 5: Commit**

```bash
git add internal/app/health_kata.go internal/app/health_kata_test.go
git commit -m "feat: add Kata kernel health check"
```

---

### Task 3: Containerd health check

**Files:**
- Create: `internal/app/health_containerd.go`
- Create: `internal/app/health_containerd_test.go`

**Context:** The containerd check calls `Version()` on the containerd client to verify it's reachable. The `Runtime` interface in `domain/ports.go` doesn't expose a health method, so we need a narrow interface for this check. The containerd `Runtime` struct at `internal/infra/containerd/runtime.go` holds the client — we expose a `Ping` method on it.

**Step 1: Write the failing test**

```go
// internal/app/health_containerd_test.go
package app

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubPinger struct {
	err error
}

func (s *stubPinger) Ping(ctx context.Context) error {
	return s.err
}

func TestContainerdCheckHealthy(t *testing.T) {
	check := NewContainerdCheck(&stubPinger{err: nil}, 15*time.Second)
	result := check.Check(context.Background())
	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
}

func TestContainerdCheckUnhealthy(t *testing.T) {
	check := NewContainerdCheck(&stubPinger{err: errors.New("connection refused")}, 15*time.Second)
	result := check.Check(context.Background())
	if result.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy, got %s: %s", result.Status, result.Message)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/app && go test -run TestContainerdCheck -v -count=1`
Expected: FAIL — `NewContainerdCheck` doesn't exist.

**Step 3: Write minimal implementation**

```go
// internal/app/health_containerd.go
package app

import (
	"context"
	"fmt"
	"time"
)

// Pinger is a narrow interface for checking containerd connectivity.
type Pinger interface {
	Ping(ctx context.Context) error
}

// ContainerdCheck verifies containerd is reachable.
type ContainerdCheck struct {
	pinger   Pinger
	interval time.Duration
}

// NewContainerdCheck creates a containerd health check.
func NewContainerdCheck(pinger Pinger, interval time.Duration) *ContainerdCheck {
	return &ContainerdCheck{pinger: pinger, interval: interval}
}

func (c *ContainerdCheck) Name() string            { return "containerd" }
func (c *ContainerdCheck) Interval() time.Duration  { return c.interval }

func (c *ContainerdCheck) Check(ctx context.Context) CheckResult {
	if err := c.pinger.Ping(ctx); err != nil {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("containerd unreachable: %v", err),
		}
	}
	return CheckResult{
		Status:  StatusHealthy,
		Message: "connected",
	}
}
```

**Step 4: Add Ping method to containerd Runtime**

Modify: `internal/infra/containerd/runtime.go` — add after `Close()` (after line 65):

```go
// Ping verifies that containerd is reachable by calling Version().
func (r *Runtime) Ping(ctx context.Context) error {
	_, err := r.client.Version(r.nsCtx(ctx))
	return err
}
```

**Step 5: Run test to verify it passes**

Run: `cd internal/app && go test -run TestContainerdCheck -v -count=1`
Expected: PASS — both tests pass.

**Step 6: Commit**

```bash
git add internal/app/health_containerd.go internal/app/health_containerd_test.go \
       internal/infra/containerd/runtime.go
git commit -m "feat: add containerd health check with Ping method"
```

---

### Task 4: Disk space health check

**Files:**
- Create: `internal/app/health_disk.go`
- Create: `internal/app/health_disk_test.go`

**Step 1: Write the failing test**

```go
// internal/app/health_disk_test.go
package app

import (
	"context"
	"testing"
	"time"
)

func TestDiskCheckHealthy(t *testing.T) {
	// Use temp dir — should have plenty of space.
	dir := t.TempDir()
	check := NewDiskSpaceCheck([]string{dir}, 60*time.Second, 100*1024*1024, 10*1024*1024)
	result := check.Check(context.Background())
	if result.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s: %s", result.Status, result.Message)
	}
}

func TestDiskCheckDegraded(t *testing.T) {
	dir := t.TempDir()
	// Set warning threshold absurdly high so any disk looks low.
	check := NewDiskSpaceCheck([]string{dir}, 60*time.Second, 999*1024*1024*1024*1024, 10*1024*1024)
	result := check.Check(context.Background())
	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %s: %s", result.Status, result.Message)
	}
}

func TestDiskCheckUnhealthy(t *testing.T) {
	dir := t.TempDir()
	// Set critical threshold absurdly high.
	check := NewDiskSpaceCheck([]string{dir}, 60*time.Second, 999*1024*1024*1024*1024, 999*1024*1024*1024*1024)
	result := check.Check(context.Background())
	if result.Status != StatusUnhealthy {
		t.Fatalf("expected unhealthy, got %s: %s", result.Status, result.Message)
	}
}

func TestDiskCheckNonexistentPath(t *testing.T) {
	check := NewDiskSpaceCheck([]string{"/nonexistent/path"}, 60*time.Second, 100*1024*1024, 10*1024*1024)
	result := check.Check(context.Background())
	// Should degrade gracefully, not crash.
	if result.Status == StatusHealthy {
		t.Fatal("expected non-healthy for nonexistent path")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/app && go test -run TestDiskCheck -v -count=1`
Expected: FAIL — `NewDiskSpaceCheck` doesn't exist.

**Step 3: Write minimal implementation**

```go
// internal/app/health_disk.go
package app

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// DiskSpaceCheck verifies sufficient free disk space on configured paths.
type DiskSpaceCheck struct {
	paths         []string
	interval      time.Duration
	warnBytes     uint64 // free space below this = degraded
	criticalBytes uint64 // free space below this = unhealthy
}

// NewDiskSpaceCheck creates a disk space health check. It checks all paths
// and reports the worst status found.
func NewDiskSpaceCheck(paths []string, interval time.Duration, warnBytes, criticalBytes uint64) *DiskSpaceCheck {
	return &DiskSpaceCheck{
		paths:         paths,
		interval:      interval,
		warnBytes:     warnBytes,
		criticalBytes: criticalBytes,
	}
}

func (d *DiskSpaceCheck) Name() string            { return "disk-space" }
func (d *DiskSpaceCheck) Interval() time.Duration  { return d.interval }

func (d *DiskSpaceCheck) Check(_ context.Context) CheckResult {
	var worstStatus HealthStatus = StatusHealthy
	var worstMessage string
	var lowestFree uint64 = ^uint64(0) // max uint64

	for _, path := range d.paths {
		var stat unix.Statfs_t
		if err := unix.Statfs(path, &stat); err != nil {
			return CheckResult{
				Status:  StatusDegraded,
				Message: fmt.Sprintf("cannot stat %s: %v", path, err),
			}
		}

		freeBytes := stat.Bavail * uint64(stat.Bsize)
		if freeBytes < lowestFree {
			lowestFree = freeBytes
		}
	}

	if lowestFree < d.criticalBytes {
		worstStatus = StatusUnhealthy
		worstMessage = fmt.Sprintf("critically low: %s free", formatBytes(lowestFree))
	} else if lowestFree < d.warnBytes {
		worstStatus = StatusDegraded
		worstMessage = fmt.Sprintf("low: %s free", formatBytes(lowestFree))
	} else {
		worstMessage = fmt.Sprintf("%s free", formatBytes(lowestFree))
	}

	return CheckResult{Status: worstStatus, Message: worstMessage}
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%d KB", b/1024)
	}
}
```

**Step 4: Run test to verify it passes**

Run: `cd internal/app && go test -run TestDiskCheck -v -count=1`
Expected: PASS — all 4 tests pass.

**Step 5: Commit**

```bash
git add internal/app/health_disk.go internal/app/health_disk_test.go
git commit -m "feat: add disk space health check"
```

---

### Task 5: RuntimeHealthy method and VM creation gating

**Files:**
- Modify: `internal/app/health.go`
- Modify: `internal/app/health_test.go`
- Modify: `internal/app/vm_service.go:122` (CreateVM)

**Context:** The health service needs a `RuntimeHealthy(runtime string)` method that VMService calls at creation time. If the Kata kernel check is degraded, Kata and Firecracker runtimes should be blocked. Containerd unhealthy blocks all runtimes.

**Step 1: Write the failing test for RuntimeHealthy**

Add to `internal/app/health_test.go`:

```go
func TestRuntimeHealthyKataDegraded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kata := &stubCheck{
		name:     "kata-kernel",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusDegraded, Message: "wrong kernel"},
	}
	ctrd := &stubCheck{
		name:     "containerd",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusHealthy, Message: "ok"},
	}

	hs := NewHealthService(kata, ctrd)
	hs.Start(ctx)
	defer hs.Stop()
	time.Sleep(100 * time.Millisecond)

	// runc should work.
	if err := hs.RuntimeHealthy("io.containerd.runc.v2"); err != nil {
		t.Fatalf("expected runc healthy, got %v", err)
	}
	// Kata should fail.
	if err := hs.RuntimeHealthy("io.containerd.kata.v2"); err == nil {
		t.Fatal("expected kata to be blocked")
	}
}

func TestRuntimeHealthyContainerdUnhealthy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctrd := &stubCheck{
		name:     "containerd",
		interval: 50 * time.Millisecond,
		result:   CheckResult{Status: StatusUnhealthy, Message: "down"},
	}

	hs := NewHealthService(ctrd)
	hs.Start(ctx)
	defer hs.Stop()
	time.Sleep(100 * time.Millisecond)

	// All runtimes should fail.
	if err := hs.RuntimeHealthy("io.containerd.runc.v2"); err == nil {
		t.Fatal("expected runc to fail when containerd unhealthy")
	}
	if err := hs.RuntimeHealthy("io.containerd.kata.v2"); err == nil {
		t.Fatal("expected kata to fail when containerd unhealthy")
	}
}

func TestRuntimeHealthyAllHealthy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hs := NewHealthService(
		&stubCheck{name: "kata-kernel", interval: 50 * time.Millisecond, result: CheckResult{Status: StatusHealthy, Message: "ok"}},
		&stubCheck{name: "containerd", interval: 50 * time.Millisecond, result: CheckResult{Status: StatusHealthy, Message: "ok"}},
	)
	hs.Start(ctx)
	defer hs.Stop()
	time.Sleep(100 * time.Millisecond)

	if err := hs.RuntimeHealthy("io.containerd.kata.v2"); err != nil {
		t.Fatalf("expected kata healthy, got %v", err)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd internal/app && go test -run TestRuntimeHealthy -v -count=1`
Expected: FAIL — `RuntimeHealthy` method doesn't exist.

**Step 3: Add RuntimeHealthy to HealthService**

Add to `internal/app/health.go`:

```go
// RuntimeHealthy returns nil if the given runtime can be used, or an error
// describing why it's unavailable.
func (h *HealthService) RuntimeHealthy(runtime string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// If containerd is unhealthy, nothing works.
	if r, ok := h.results["containerd"]; ok && r.Status == StatusUnhealthy {
		return fmt.Errorf("containerd unavailable: %s", r.Message)
	}

	// If Kata kernel is degraded, block Kata runtimes.
	if strings.Contains(runtime, "kata") {
		if r, ok := h.results["kata-kernel"]; ok && r.Status != StatusHealthy {
			return fmt.Errorf("runtime %s unavailable: %s", runtime, r.Message)
		}
	}

	return nil
}
```

Add `"fmt"` and `"strings"` to the import block in `health.go`.

**Step 4: Run test to verify it passes**

Run: `cd internal/app && go test -run TestRuntimeHealthy -v -count=1`
Expected: PASS — all 3 tests pass.

**Step 5: Wire into VMService**

Add a `health` field to `VMService` in `internal/app/vm_service.go`:

After line 46 (`config VMServiceConfig`), add:
```go
	health *HealthService
```

Add a `WithHealth` option after `WithSnapshotStore` (after line 108):
```go
// WithHealth enables runtime health gating.
func WithHealth(h *HealthService) func(*VMService) {
	return func(s *VMService) {
		s.health = h
	}
}
```

In `CreateVM` (line 141, after `params.Runtime` is set), add the health gate:
```go
	if s.health != nil {
		if err := s.health.RuntimeHealthy(params.Runtime); err != nil {
			return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
		}
	}
```

Add `ErrUnavailable` to `internal/domain/errors.go` (or `vm.go` — wherever domain errors are defined). Search for `ErrValidation` to find the right file:

```go
// ErrUnavailable indicates a requested resource/runtime is temporarily unavailable.
var ErrUnavailable = errors.New("service unavailable")
```

**Step 6: Run all app tests**

Run: `cd internal/app && go test -v -count=1`
Expected: PASS — all existing tests still pass (health is nil in existing tests, so the check is skipped).

**Step 7: Commit**

```bash
git add internal/app/health.go internal/app/health_test.go \
       internal/app/vm_service.go internal/domain/
git commit -m "feat: add RuntimeHealthy gating for VM creation"
```

---

### Task 6: GET /health HTTP endpoint

**Files:**
- Modify: `internal/infra/httpapi/handler.go`
- Modify: `cmd/daemon.go`

**Context:** The health endpoint reads cached state from the HealthService. It returns 200/218/503 based on aggregate status. The handler needs access to HealthService — we pass it alongside VMService to `NewHandler`. Huma doesn't support custom status codes conditionally, so we register this as a raw `HandleFunc` on the mux.

**Step 1: Add health endpoint to httpapi**

Modify `internal/infra/httpapi/handler.go`:

Change `NewHandler` signature (line 404) to accept HealthService:

```go
func NewHandler(svc *app.VMService, health *app.HealthService) http.Handler {
```

Add after the `mux.HandleFunc` for console (after line 419):

```go
	// Health endpoint — raw handler for custom status codes.
	mux.HandleFunc("GET /health", handleHealth(health))
```

Add the handler function (at the end of the file, before the closing brace or after `registerSnapshotRoutes`):

```go
func handleHealth(health *app.HealthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := health.Status()

		var statusCode int
		switch report.Status {
		case app.StatusHealthy:
			statusCode = http.StatusOK
		case app.StatusDegraded:
			statusCode = 218 // "This is fine" — degraded but functional
		default:
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(report) //nolint:errcheck
	}
}
```

Add `"encoding/json"` to the import block.

**Step 2: Update daemon.go to create and wire HealthService**

Modify `cmd/daemon.go`. After `svc := app.NewVMService(...)` (line 237), add:

```go
	// Health checks.
	kataKernelVersion := viper.GetString("kata-kernel-version")
	healthChecks := []app.HealthCheck{
		app.NewContainerdCheck(runtime, 15*time.Second),
		app.NewDiskSpaceCheck(
			[]string{config.GlobalPaths.StateDir},
			60*time.Second,
			100*1024*1024,  // 100 MB warning
			10*1024*1024,   // 10 MB critical
		),
	}
	if kataKernelVersion != "" {
		healthChecks = append(healthChecks, app.NewKataKernelCheck(kataKernelVersion, 30*time.Second))
	}
	health := app.NewHealthService(healthChecks...)
	health.Start(context.Background())
	defer health.Stop()
```

Update `svcOpts` to include health — add before line 237 (before `svc :=`):

```go
	svcOpts = append(svcOpts, app.WithHealth(health))
```

Update the `NewHandler` call (line 250) to pass health:

```go
	mux.Handle("/", httpapi.NewHandler(svc, health))
```

Add the `--kata-kernel-version` flag after the other flags (around line 320):

```go
	cmd.Flags().String("kata-kernel-version", "", "Expected Anvil kernel version for Kata health check (empty to skip)")
```

Add it to the viper bind loop (line 322):

Add `"kata-kernel-version"` to the list of flag names.

Add the config default in `internal/config/config.go`:

```go
	DefaultKataKernelVersion = "6.19.6"
```

And the viper default in `InitViper`:

```go
	viper.SetDefault("kata-kernel-version", DefaultKataKernelVersion)
```

**Step 3: Update httpapi handler_test.go**

The test helper creates a handler — update it to pass a nil-safe or stub HealthService. Find where `NewHandler` is called in tests and add a health parameter.

Search for `NewHandler` in handler_test.go and update each call:

```go
// Create a minimal health service for tests.
health := app.NewHealthService()
health.Start(context.Background())
defer health.Stop()
handler := httpapi.NewHandler(svc, health)
```

**Step 4: Map ErrUnavailable in httpapi**

Find `mapDomainError` in `handler.go` and add a case:

```go
	if errors.Is(err, domain.ErrUnavailable) {
		return huma.NewError(http.StatusServiceUnavailable, err.Error())
	}
```

**Step 5: Build and run tests**

Run: `mise run build && mise run test`
Expected: PASS — everything compiles and tests pass.

**Step 6: Commit**

```bash
git add internal/infra/httpapi/handler.go internal/infra/httpapi/handler_test.go \
       internal/config/config.go cmd/daemon.go
git commit -m "feat: add GET /health endpoint with 200/218/503 status codes"
```

---

### Task 7: AUR package — ship Anvil kernel and Kata config override

**Files:**
- Modify: `aur/PKGBUILD`
- Create: `dist/kata-configuration.toml`
- Modify: `aur/nexus-virt.install`

**Context:** The AUR package needs to download the Anvil kernel from a GitHub release and install a Kata config override. The node_exporter pattern in PKGBUILD shows how to download arch-specific release assets.

**Step 1: Create the Kata config override template**

Create `dist/kata-configuration.toml` — this is a minimal override pointing to the Anvil kernel. Copy the current `/etc/kata-containers/configuration.toml` content but with `kernel` pointing to the package install path. This should be the stock Kata QEMU config with only the kernel path changed:

```bash
# Copy current system config as base.
cp /opt/kata/share/defaults/kata-containers/configuration.toml dist/kata-configuration.toml
```

Then edit `dist/kata-configuration.toml` — change the `kernel` line:

```toml
kernel = "/usr/share/nexus/vmlinux"
```

**Step 2: Update PKGBUILD**

Add Anvil kernel version and source (placeholder checksum):

```bash
_anvil_kernel_ver=6.19.6
```

Add to `source_x86_64`:

```bash
"https://github.com/Work-Fort/Anvil/releases/download/v${_anvil_kernel_ver}/vmlinux-${_anvil_kernel_ver}-x86_64"
```

Add to `source_aarch64`:

```bash
"https://github.com/Work-Fort/Anvil/releases/download/v${_anvil_kernel_ver}/vmlinux-${_anvil_kernel_ver}-aarch64"
```

Add placeholder checksums (`'SKIP'` until real releases exist).

Add to `package()`:

```bash
    # Anvil guest kernel for Kata Containers.
    install -Dm644 "${srcdir}/vmlinux-${_anvil_kernel_ver}-${CARCH}" "${pkgdir}/usr/share/nexus/vmlinux"

    # Kata config override pointing to the Anvil kernel.
    install -Dm644 "${startdir}/../dist/kata-configuration.toml" "${pkgdir}/etc/kata-containers/configuration.toml"
```

Mark the config as a backup file (pacman preserves user modifications):

```bash
backup=('etc/kata-containers/configuration.toml')
```

**Step 3: Update nexus-virt.install**

No changes needed — the config is a regular file, not a capability-requiring binary.

**Step 4: Update aur:test mise task**

Modify `.mise/tasks/aur/test` to include the Anvil kernel in the test build. The test build uses local source, so it won't download from GitHub. Instead, copy the local kernel:

In the test `package()` function, add:

```bash
    # Use local kernel for test build.
    if [ -f "/tmp/vmlinux-${_anvil_kernel_ver}-x86_64" ]; then
        install -Dm644 "/tmp/vmlinux-${_anvil_kernel_ver}-x86_64" "${pkgdir}/usr/share/nexus/vmlinux"
    fi
    install -Dm644 "$_projroot/dist/kata-configuration.toml" "${pkgdir}/etc/kata-containers/configuration.toml"
```

**Step 5: Commit**

```bash
git add aur/PKGBUILD dist/kata-configuration.toml .mise/tasks/aur/test
git commit -m "feat(aur): ship Anvil kernel and Kata config override"
```

---

### Task 8: MCP health tool

**Files:**
- Modify: `internal/infra/mcp/handler.go`

**Context:** The MCP handler should expose a `health` tool so Claude Code can check Nexus health status. This is a read-only tool that returns the same data as `GET /health`.

**Step 1: Update MCP handler to accept HealthService**

The MCP `NewHandler` function needs access to the HealthService. Check its current signature and update it.

Modify `internal/infra/mcp/handler.go`:

Update `NewHandler` to accept `*app.HealthService` and register a `health` tool:

```go
func registerHealthTools(s *server.MCPServer, health *app.HealthService) {
	s.AddTool(mcp.Tool{
		Name:        "health",
		Description: "Get Nexus health status",
	}, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		report := health.Status()
		return jsonResult(report)
	})
}
```

Call it from `NewHandler` and update the MCP handler construction.

**Step 2: Update daemon.go MCP handler call**

Update the `/mcp` handler in `cmd/daemon.go` to pass health.

**Step 3: Build and verify**

Run: `mise run build`
Expected: Compiles without errors.

**Step 4: Commit**

```bash
git add internal/infra/mcp/handler.go cmd/daemon.go
git commit -m "feat(mcp): add health tool"
```

---

### Task 9: QA — manual and automated verification

**Step 1: Run all tests**

Run: `mise run test && mise run e2e`
Expected: All tests pass.

**Step 2: Manual health endpoint test**

```bash
mise run run &
sleep 2
curl -sf http://127.0.0.1:9600/health | jq .
```

Expected: JSON response with status, checks for kata-kernel, containerd, disk-space. Status code should be 200 (if all healthy) or 218 (if Kata kernel is misconfigured).

**Step 3: Test VM creation gating**

If the Kata kernel check is degraded:

```bash
# Try to create a Kata VM — should fail with 503.
curl -sf -X POST http://127.0.0.1:9600/v1/vms \
  -d '{"name":"test-kata","runtime":"io.containerd.kata.v2"}' | jq .

# Try to create a runc VM — should succeed.
curl -sf -X POST http://127.0.0.1:9600/v1/vms \
  -d '{"name":"test-runc"}' | jq .
```

**Step 4: Test MCP health tool**

Via nexusctl or MCP, call the `health` tool and verify it returns the same data.

**Step 5: Clean up test VMs**

```bash
curl -sf -X DELETE http://127.0.0.1:9600/v1/vms/test-runc
```
