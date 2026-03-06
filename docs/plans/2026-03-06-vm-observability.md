# VM Observability Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bind-mount node_exporter into every VM, exec-start it after boot, and expose a Prometheus HTTP service discovery endpoint so Prometheus can scrape VM metrics directly.

**Architecture:** VMService gains a `MetricsConfig` that controls node_exporter provisioning. `CreateVM` adds a bind mount for the binary. `StartVM` fires a background goroutine to exec node_exporter inside the VM. A new `GET /v1/prometheus/targets` endpoint returns running VMs in Prometheus HTTP SD format with tag labels.

**Tech Stack:** Go, huma v2, viper config, Prometheus HTTP SD JSON format

**Depends on:** Feature #10 (VM Tags) for tag labels in HTTP SD responses. The HTTP SD endpoint works without tags — it just won't emit tag labels until #10 is implemented.

---

### Task 1: Add Metrics Config

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/app/vm_service.go`

**Step 1: Add viper defaults for metrics config**

In `internal/config/config.go`, add constants after `DefaultDNSHelper` (line 31):

```go
DefaultNodeExporterPath = "/opt/nexus/bin/node_exporter"
DefaultMetricsPort      = 9100
```

In `InitViper()`, add after the `dns-helper` default (line 106):

```go
viper.SetDefault("metrics.node-exporter-path", DefaultNodeExporterPath)
viper.SetDefault("metrics.listen-port", DefaultMetricsPort)
viper.SetDefault("metrics.collectors", []string{
    "cpu", "meminfo", "diskstats", "filesystem", "loadavg", "netdev",
})
```

**Step 2: Add MetricsConfig to VMServiceConfig**

In `internal/app/vm_service.go`, update the `VMServiceConfig` struct (line 22):

```go
type VMServiceConfig struct {
	DefaultImage   string
	DefaultRuntime string
	Metrics        MetricsConfig
}

// MetricsConfig controls in-VM node_exporter provisioning.
type MetricsConfig struct {
	NodeExporterPath string   // host path to node_exporter binary, empty = disabled
	ListenPort       int      // port node_exporter listens on inside VMs
	Collectors       []string // enabled collector names
}
```

**Step 3: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/config/config.go internal/app/vm_service.go
git commit -m "feat(config): add metrics config for node_exporter provisioning"
```

---

### Task 2: Wire Metrics Config in Daemon

**Files:**
- Modify: `cmd/daemon.go`

**Step 1: Build MetricsConfig from viper and pass to VMService**

In `cmd/daemon.go`, find where `VMServiceConfig` is built (look for
`app.WithConfig` or where `DefaultImage`/`DefaultRuntime` are set). Add
metrics config construction.

If `app.WithConfig` is already called, add the `Metrics` field. If config
is built inline, add it there. The key logic:

```go
nodeExporterPath := viper.GetString("metrics.node-exporter-path")
if nodeExporterPath != "" {
    if _, err := os.Stat(nodeExporterPath); err != nil {
        log.Warn("node_exporter not found, metrics disabled", "path", nodeExporterPath)
        nodeExporterPath = ""
    }
}

svcConfig := app.VMServiceConfig{
    DefaultImage:   viper.GetString("agent-image"),
    DefaultRuntime: viper.GetString("runtime"),
    Metrics: app.MetricsConfig{
        NodeExporterPath: nodeExporterPath,
        ListenPort:       viper.GetInt("metrics.listen-port"),
        Collectors:       viper.GetStringSlice("metrics.collectors"),
    },
}
```

Pass `svcConfig` via `app.WithConfig(svcConfig)` in the `svcOpts` slice.

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 3: Commit**

```bash
git add cmd/daemon.go
git commit -m "feat(daemon): wire metrics config from viper into VMService"
```

---

### Task 3: Add Node Exporter Bind Mount to CreateVM

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`

**Step 1: Write the failing test**

Add to `internal/app/vm_service_test.go`:

```go
func TestCreateVM_MetricsBindMount(t *testing.T) {
	t.Run("adds bind mount when node_exporter path set", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
			app.WithConfig(app.VMServiceConfig{
				DefaultImage:   "alpine:latest",
				DefaultRuntime: "io.containerd.runc.v2",
				Metrics: app.MetricsConfig{
					NodeExporterPath: "/opt/nexus/bin/node_exporter",
					ListenPort:       9100,
					Collectors:       []string{"cpu", "meminfo"},
				},
			}),
		)

		vm, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name: "metrics-test",
			Role: domain.VMRoleAgent,
		})
		if err != nil {
			t.Fatalf("CreateVM: %v", err)
		}

		// Verify the runtime received a mount for node_exporter.
		// We need to check the create opts passed to the mock runtime.
		if !rt.lastCreateHasMount("/usr/local/bin/node_exporter") {
			t.Error("expected node_exporter bind mount in create opts")
		}
		_ = vm
	})

	t.Run("skips bind mount when node_exporter path empty", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
			app.WithConfig(app.VMServiceConfig{
				DefaultImage:   "alpine:latest",
				DefaultRuntime: "io.containerd.runc.v2",
			}),
		)

		_, err := svc.CreateVM(context.Background(), domain.CreateVMParams{
			Name: "no-metrics",
			Role: domain.VMRoleAgent,
		})
		if err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		if rt.lastCreateHasMount("/usr/local/bin/node_exporter") {
			t.Error("unexpected node_exporter bind mount")
		}
	})
}
```

**Step 2: Update mockRuntime to track create opts**

Add mount tracking to `mockRuntime`:

```go
type mockRuntime struct {
	containers map[string]bool
	execResult *domain.ExecResult
	execErr    error
	lastMounts []domain.Mount // tracks mounts from last Create call
}

func (m *mockRuntime) Create(_ context.Context, id, image, runtime string, opts ...domain.CreateOpt) error {
	cfg := &domain.CreateConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	m.lastMounts = cfg.Mounts
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) lastCreateHasMount(containerPath string) bool {
	for _, mount := range m.lastMounts {
		if mount.ContainerPath == containerPath {
			return true
		}
	}
	return false
}
```

**Step 3: Run tests to verify they fail**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestCreateVM_MetricsBindMount -v`
Expected: FAIL — CreateVM doesn't add the mount yet.

**Step 4: Add node_exporter mount to CreateVM**

In `internal/app/vm_service.go`, in `CreateVM`, after building the initial
`createOpts` slice (around line 170, after the `WithRootSize` block), add:

```go
	if s.config.Metrics.NodeExporterPath != "" {
		createOpts = append(createOpts, domain.WithMounts([]domain.Mount{
			{
				HostPath:      s.config.Metrics.NodeExporterPath,
				ContainerPath: "/usr/local/bin/node_exporter",
			},
		}))
	}
```

**Important:** If there are already drive mounts from `WithMounts`, the
`WithMounts` functional option *replaces* `c.Mounts`. Check how `WithMounts`
works in `internal/domain/ports.go`. If it replaces, you need to combine
drive mounts and the node_exporter mount into a single `WithMounts` call.
If it appends, separate calls are fine.

Looking at the current code, `CreateVM` doesn't call `WithMounts` (drives
are only mounted in `recreateContainer`, not initial create). So a separate
`WithMounts` call here is safe.

**Step 5: Also add the mount to recreateContainer**

In `recreateContainer` (line 729), after the drive mounts loop builds
the `mounts` slice, append the node_exporter mount:

```go
	if s.config.Metrics.NodeExporterPath != "" {
		mounts = append(mounts, domain.Mount{
			HostPath:      s.config.Metrics.NodeExporterPath,
			ContainerPath: "/usr/local/bin/node_exporter",
		})
	}
```

This ensures node_exporter survives container recreation (e.g. drive
attach/detach triggers recreateContainer).

**Step 6: Run tests to verify they pass**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestCreateVM_MetricsBindMount -v`
Expected: PASS

**Step 7: Run all app tests for regressions**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -v`
Expected: PASS

**Step 8: Commit**

```bash
git add internal/app/vm_service.go internal/app/vm_service_test.go
git commit -m "feat(app): bind-mount node_exporter into VMs when metrics enabled"
```

---

### Task 4: Exec-Start Node Exporter After VM Boot

**Files:**
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`

**Step 1: Write the failing test**

Add to `internal/app/vm_service_test.go`:

```go
func TestStartVM_MetricsExec(t *testing.T) {
	t.Run("execs node_exporter when metrics enabled", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{},
			app.WithConfig(app.VMServiceConfig{
				DefaultImage:   "alpine:latest",
				DefaultRuntime: "io.containerd.runc.v2",
				Metrics: app.MetricsConfig{
					NodeExporterPath: "/opt/nexus/bin/node_exporter",
					ListenPort:       9100,
					Collectors:       []string{"cpu", "meminfo"},
				},
			}),
		)

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-1"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		// Give the background goroutine a moment to fire.
		time.Sleep(100 * time.Millisecond)

		if !rt.execCalled {
			t.Error("expected exec to be called for node_exporter")
		}
		if rt.lastExecCmd[0] != "/usr/local/bin/node_exporter" {
			t.Errorf("exec cmd = %v, want node_exporter", rt.lastExecCmd)
		}
	})

	t.Run("skips exec when metrics disabled", func(t *testing.T) {
		store := newMockStore()
		rt := newMockRuntime()
		svc := app.NewVMService(store, rt, &cni.NoopNetwork{})

		vm := &domain.VM{
			ID: "vm-1", Name: "test", State: domain.VMStateStopped,
		}
		store.vms[vm.ID] = vm
		rt.containers[vm.ID] = false

		if err := svc.StartVM(context.Background(), "vm-1"); err != nil {
			t.Fatalf("StartVM: %v", err)
		}

		time.Sleep(100 * time.Millisecond)

		if rt.execCalled {
			t.Error("exec should not be called when metrics disabled")
		}
	})
}
```

**Step 2: Update mockRuntime to track exec calls**

Add to the `mockRuntime` struct:

```go
type mockRuntime struct {
	containers  map[string]bool
	execResult  *domain.ExecResult
	execErr     error
	lastMounts  []domain.Mount
	execCalled  bool
	lastExecCmd []string
}

func (m *mockRuntime) Exec(_ context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	m.execCalled = true
	m.lastExecCmd = cmd
	if m.execErr != nil {
		return nil, m.execErr
	}
	return m.execResult, nil
}
```

**Step 3: Run tests to verify they fail**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestStartVM_MetricsExec -v`
Expected: FAIL — StartVM doesn't exec node_exporter yet.

**Step 4: Add metrics exec to StartVM**

In `internal/app/vm_service.go`, in `StartVM`, after the state update and
log line (around line 220), add:

```go
	if s.config.Metrics.NodeExporterPath != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := []string{
				"/usr/local/bin/node_exporter",
				fmt.Sprintf("--web.listen-address=:%d", s.config.Metrics.ListenPort),
				"--collector.disable-defaults",
			}
			for _, c := range s.config.Metrics.Collectors {
				cmd = append(cmd, "--collector."+c)
			}

			if _, err := s.runtime.Exec(ctx, vm.ID, cmd); err != nil {
				log.Warn("metrics exec failed", "vm", vm.ID, "err", err)
			}
		}()
	}
```

**Step 5: Run tests to verify they pass**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -run TestStartVM_MetricsExec -v`
Expected: PASS

**Step 6: Run all app tests for regressions**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go test ./internal/app/ -v`
Expected: PASS

**Step 7: Commit**

```bash
git add internal/app/vm_service.go internal/app/vm_service_test.go
git commit -m "feat(app): exec-start node_exporter after VM boot"
```

---

### Task 5: Prometheus HTTP SD Endpoint — Unit Tests

**Files:**
- Modify: `internal/infra/httpapi/handler.go`
- Modify: `internal/app/vm_service.go` (if needed for a helper method)

**Step 1: Add PrometheusTarget types to handler.go**

In `internal/infra/httpapi/handler.go`, add after the response types
(around line 170):

```go
// prometheusTarget is a single target group in Prometheus HTTP SD format.
type prometheusTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

type PrometheusTargetsOutput struct {
	Body []prometheusTarget
}
```

**Step 2: Register the endpoint**

Add a new registration function and call it from `NewHandler`:

In `NewHandler` (line 321), add before `return mux`:

```go
	registerPrometheusRoutes(api, svc)
```

Then add the function:

```go
// --- Prometheus routes ---

func registerPrometheusRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID: "prometheus-targets",
		Method:      http.MethodGet,
		Path:        "/v1/prometheus/targets",
		Summary:     "Prometheus HTTP service discovery targets",
		Description: "Returns running VMs as Prometheus scrape targets in HTTP SD format.",
		Tags:        []string{"Prometheus"},
	}, func(ctx context.Context, input *struct{}) (*PrometheusTargetsOutput, error) {
		vms, err := svc.ListVMs(ctx, domain.VMFilter{})
		if err != nil {
			return nil, mapDomainError(err)
		}

		metricsPort := svc.MetricsPort()
		var targets []prometheusTarget
		for _, vm := range vms {
			if vm.State != domain.VMStateRunning || vm.IP == "" {
				continue
			}
			labels := map[string]string{
				"__meta_nexus_vm_id":    vm.ID,
				"__meta_nexus_vm_name":  vm.Name,
				"__meta_nexus_vm_state": string(vm.State),
			}
			// Tags will be added here once feature #10 is implemented:
			// for _, tag := range vm.Tags {
			//     labels["__meta_nexus_vm_tag_"+tag] = "true"
			// }
			targets = append(targets, prometheusTarget{
				Targets: []string{fmt.Sprintf("%s:%d", vm.IP, metricsPort)},
				Labels:  labels,
			})
		}

		if targets == nil {
			targets = []prometheusTarget{} // return [] not null
		}
		return &PrometheusTargetsOutput{Body: targets}, nil
	})
}
```

**Step 3: Add MetricsPort helper to VMService**

In `internal/app/vm_service.go`, add:

```go
// MetricsPort returns the configured node_exporter listen port.
func (s *VMService) MetricsPort() int {
	if s.config.Metrics.ListenPort == 0 {
		return 9100
	}
	return s.config.Metrics.ListenPort
}
```

**Step 4: Add `fmt` to handler.go imports if not present**

Check imports in handler.go — `fmt` may already be imported. If not, add it.

**Step 5: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/infra/httpapi/handler.go internal/app/vm_service.go
git commit -m "feat(httpapi): add Prometheus HTTP SD targets endpoint"
```

---

### Task 6: Add Tag Labels to HTTP SD (Feature #10 Integration)

**Files:**
- Modify: `internal/infra/httpapi/handler.go`

This task should be implemented **after** feature #10 (VM Tags) lands. Until
then, the commented-out tag loop from Task 5 is a placeholder.

**Step 1: Uncomment the tag label loop**

In the `registerPrometheusRoutes` handler, replace the comment block with:

```go
			for _, tag := range vm.Tags {
				labels["__meta_nexus_vm_tag_"+tag] = "true"
			}
```

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./...`
Expected: PASS (only if VM.Tags field exists from feature #10)

**Step 3: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat(httpapi): add VM tag labels to Prometheus SD targets"
```

---

### Task 7: Add E2E Harness Helper

**Files:**
- Modify: `tests/e2e/harness/harness.go`

**Step 1: Add PrometheusTarget type and helper**

In `tests/e2e/harness/harness.go`, add the type:

```go
type PrometheusTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}
```

Add the client method:

```go
// PrometheusTargets returns the Prometheus HTTP SD targets.
func (c *Client) PrometheusTargets() ([]PrometheusTarget, error) {
	resp, err := c.get("/v1/prometheus/targets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var targets []PrometheusTarget
	return targets, json.NewDecoder(resp.Body).Decode(&targets)
}
```

**Step 2: Verify it compiles**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && go build ./tests/e2e/...`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/e2e/harness/harness.go
git commit -m "feat(e2e): add Prometheus targets harness helper"
```

---

### Task 8: Add E2E Tests

**Files:**
- Create or modify: `tests/e2e/metrics_test.go`

**Step 1: Write the E2E tests**

Create `tests/e2e/metrics_test.go`:

```go
package e2e

import (
	"strings"
	"testing"
)

func TestPrometheusTargets(t *testing.T) {
	_, c := startDaemon(t)

	// No VMs — should return empty array.
	targets, err := c.PrometheusTargets()
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}

	// Create and start a VM.
	vm, err := c.CreateVM("metrics-test", "agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Should appear as a target.
	targets, err = c.PrometheusTargets()
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Labels["__meta_nexus_vm_name"] != "metrics-test" {
		t.Errorf("label vm_name = %q, want metrics-test", targets[0].Labels["__meta_nexus_vm_name"])
	}
	if !strings.Contains(targets[0].Targets[0], ":9100") {
		t.Errorf("target = %q, expected :9100 port", targets[0].Targets[0])
	}

	// Stop VM — should disappear from targets.
	if err := c.StopVM(vm.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	targets, err = c.PrometheusTargets()
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected 0 targets after stop, got %d", len(targets))
	}
}

func TestNodeExporterRunning(t *testing.T) {
	_, c := startDaemon(t)

	vm, err := c.CreateVM("ne-test", "agent")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.StartVM(vm.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Give node_exporter a moment to start.
	// Then check it's listening by curling from inside the VM.
	result, err := c.ExecVM(vm.ID, []string{"wget", "-q", "-O-", "http://localhost:9100/metrics"})
	if err != nil {
		t.Fatalf("exec wget: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("wget exit %d: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "node_cpu_seconds_total") {
		t.Error("expected Prometheus metrics in node_exporter output")
	}
}
```

**Note:** `TestNodeExporterRunning` requires the node_exporter binary to
actually exist at the configured path on the test host. This test will be
skipped in CI environments where node_exporter is not installed. Consider
wrapping it with:

```go
if _, err := os.Stat("/opt/nexus/bin/node_exporter"); err != nil {
    t.Skip("node_exporter not found, skipping")
}
```

**Step 2: Run E2E tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && mise run e2e`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/e2e/metrics_test.go
git commit -m "test(e2e): add Prometheus targets and node_exporter E2E tests"
```

---

### Task 9: Verify Everything

**Step 1: Run all unit tests**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && mise run test`
Expected: PASS

**Step 2: Run the linter**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && golangci-lint run ./...`
Expected: PASS (or only pre-existing warnings)

**Step 3: Build all binaries**

Run: `cd /home/kazw/Work/WorkFort/nexus/lead && mise run build`
Expected: PASS

**Step 4: Manual verification (if daemon is runnable)**

```bash
# Download node_exporter and place it at the default path:
# https://github.com/prometheus/node_exporter/releases
sudo mkdir -p /opt/nexus/bin
sudo cp node_exporter /opt/nexus/bin/

mise run run &

# Create and start a VM:
curl -s -X POST http://localhost:9600/v1/vms \
  -d '{"name":"test","role":"agent"}' | jq .id
curl -s -X POST http://localhost:9600/v1/vms/test/start

# Check Prometheus targets:
curl -s http://localhost:9600/v1/prometheus/targets | jq .
# Expected: one target with the VM's IP:9100

# Check node_exporter is running inside the VM:
curl -s -X POST http://localhost:9600/v1/vms/test/exec \
  -d '{"cmd":["wget","-q","-O-","http://localhost:9100/metrics"]}' | head -20
# Expected: Prometheus text format metrics
```

**Step 5: Commit any final fixes**

```bash
git add -A
git commit -m "fix: address issues found during observability verification"
```
