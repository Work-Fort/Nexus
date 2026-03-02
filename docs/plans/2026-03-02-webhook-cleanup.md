# Webhook Cleanup & Huma Migration

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove Sharkfin-specific webhook code and migrate all HTTP handlers to huma v2 for automatic OpenAPI 3.1 generation.

**Architecture:** Delete tightly-coupled webhook code from app and HTTP layers. Replace all `func(w, r)` handlers with huma's typed `func(ctx, *Input) (*Output, error)` signature using the `humago` adapter for stdlib `net/http`. This generates an OpenAPI 3.1 spec at runtime served at `/openapi` with interactive docs at `/docs`. No domain layer changes.

**Tech Stack:** Go 1.26, huma v2 (`github.com/danielgtaylor/huma/v2`), `humago` adapter, stdlib `net/http`

**Build command:** `mise run build` (not `go build` directly)
**Test command:** `go test ./...`

---

### Task 1: Delete Sharkfin webhook code

**Files:**
- Delete: `internal/infra/httpapi/webhook.go`
- Delete: `internal/infra/httpapi/webhook_test.go`
- Modify: `internal/app/vm_service.go`
- Modify: `internal/app/vm_service_test.go`
- Modify: `internal/infra/httpapi/handler.go`
- Modify: `internal/config/config.go`

**Step 1: Delete webhook files**

```bash
rm internal/infra/httpapi/webhook.go
rm internal/infra/httpapi/webhook_test.go
```

**Step 2: Remove SharkfinWebhook struct and HandleWebhook from vm_service.go**

In `internal/app/vm_service.go`, delete these two blocks:

Lines 21–30 — the `SharkfinWebhook` struct:
```go
// SharkfinWebhook is the payload Sharkfin POSTs on mentions and DMs.
type SharkfinWebhook struct {
	Event       string `json:"event"`
	Recipient   string `json:"recipient"`
	Channel     string `json:"channel"`
	ChannelType string `json:"channel_type"`
	From        string `json:"from"`
	MessageID   int64  `json:"message_id"`
	SentAt      string `json:"sent_at"`
}
```

Lines 304–338 — the `HandleWebhook` method:
```go
// HandleWebhook processes a Sharkfin webhook. It finds or creates an agent
// VM for the recipient, and ensures it's running.
func (s *VMService) HandleWebhook(ctx context.Context, wh SharkfinWebhook) error {
	...entire method...
}
```

After deletion, the `"errors"` import may become unused — check and remove if needed.

**Step 3: Remove webhook tests from vm_service_test.go**

In `internal/app/vm_service_test.go`, delete these three test functions:

Lines 583–610 — `TestHandleWebhookCreatesAgent`
Lines 612–633 — `TestHandleWebhookStartsExistingStopped`
Lines 660–680 — `TestHandleWebhookNoopIfRunning`

**Step 4: Remove webhook route from handler.go**

In `internal/infra/httpapi/handler.go`, delete line 46:
```go
	mux.HandleFunc("POST /webhooks/sharkfin", handleSharkfinWebhook(svc))
```

**Step 5: Remove webhook-url config default**

In `internal/config/config.go`, delete line 95:
```go
	viper.SetDefault("webhook-url", "")
```

**Step 6: Run tests**

```bash
go test ./internal/app/... ./internal/infra/httpapi/...
```

Expected: All tests pass. The `errors` import in `vm_service.go` is still used by other methods so should not need removal.

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: delete Sharkfin webhook code

Remove SharkfinWebhook struct, HandleWebhook method, webhook HTTP
handler, webhook tests, and webhook-url config default. The existing
CRUD + start/stop API is sufficient for all callers."
```

---

### Task 2: Add huma v2 dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Add dependency**

```bash
go get github.com/danielgtaylor/huma/v2
```

**Step 2: Verify it resolved**

```bash
grep huma go.mod
```

Expected: `github.com/danielgtaylor/huma/v2 v2.x.x`

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add huma v2 dependency for OpenAPI generation"
```

---

### Task 3: Rewrite handler.go with huma v2

This is the main migration task. Replace the entire `internal/infra/httpapi/handler.go` with the huma-based implementation below.

**Files:**
- Rewrite: `internal/infra/httpapi/handler.go`

**Step 1: Replace handler.go with huma implementation**

Write the complete file `internal/infra/httpapi/handler.go`:

```go
// SPDX-License-Identifier: Apache-2.0

// Package httpapi implements the Nexus HTTP API with OpenAPI 3.1 documentation.
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
)

const timeFormatJSON = "2006-01-02T15:04:05.000Z"

// --- huma input types ---

type CreateVMInput struct {
	Body struct {
		Name    string         `json:"name" doc:"VM name"`
		Role    string         `json:"role" doc:"VM role (agent or service)"`
		Image   string         `json:"image,omitempty" doc:"OCI image"`
		Runtime string         `json:"runtime,omitempty" doc:"Container runtime handler"`
		DNS     *dnsConfigBody `json:"dns,omitempty" doc:"DNS configuration"`
	}
}

type ListVMsInput struct {
	Role string `query:"role" doc:"Filter by VM role"`
}

type VMPathInput struct {
	ID string `path:"id" doc:"VM ID or name"`
}

type ExecVMInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		Cmd []string `json:"cmd" doc:"Command to execute"`
	}
}

type CreateDriveInput struct {
	Body struct {
		Name      string `json:"name" doc:"Drive name"`
		Size      string `json:"size" doc:"Size (e.g. 1G, 500Mi)"`
		MountPath string `json:"mount_path" doc:"Mount path inside VM"`
	}
}

type DrivePathInput struct {
	ID string `path:"id" doc:"Drive ID or name"`
}

type AttachDriveInput struct {
	ID   string `path:"id" doc:"Drive ID or name"`
	Body struct {
		VMID string `json:"vm_id" doc:"VM ID to attach to"`
	}
}

type CreateDeviceInput struct {
	Body struct {
		Name          string `json:"name" doc:"Device name"`
		HostPath      string `json:"host_path" doc:"Device path on host"`
		ContainerPath string `json:"container_path" doc:"Device path in container"`
		Permissions   string `json:"permissions" doc:"Permissions (r, w, m combination)"`
		GID           uint32 `json:"gid,omitempty" doc:"Device group ID"`
	}
}

type DevicePathInput struct {
	ID string `path:"id" doc:"Device ID or name"`
}

type AttachDeviceInput struct {
	ID   string `path:"id" doc:"Device ID or name"`
	Body struct {
		VMID string `json:"vm_id" doc:"VM ID to attach to"`
	}
}

// --- huma output types ---

type VMOutput struct {
	Body vmResponse
}

type VMListOutput struct {
	Body []vmResponse
}

type ExecOutput struct {
	Body execResponse
}

type DriveOutput struct {
	Body driveResponse
}

type DriveListOutput struct {
	Body []driveResponse
}

type DeviceOutput struct {
	Body deviceResponse
}

type DeviceListOutput struct {
	Body []deviceResponse
}

type StatusOutput struct {
	Body statusBody
}

// --- response body types ---

type dnsConfigBody struct {
	Servers []string `json:"servers,omitempty" doc:"DNS nameservers"`
	Search  []string `json:"search,omitempty" doc:"DNS search domains"`
}

type statusBody struct {
	Status string `json:"status" doc:"Operation status"`
}

type vmResponse struct {
	ID        string         `json:"id" doc:"VM ID"`
	Name      string         `json:"name" doc:"VM name"`
	Role      string         `json:"role" doc:"VM role"`
	State     string         `json:"state" doc:"Current state"`
	Image     string         `json:"image" doc:"OCI image"`
	Runtime   string         `json:"runtime" doc:"Runtime handler"`
	IP        string         `json:"ip,omitempty" doc:"Assigned IP address"`
	Gateway   string         `json:"gateway,omitempty" doc:"Network gateway"`
	DNS       *dnsConfigBody `json:"dns,omitempty" doc:"DNS configuration"`
	CreatedAt string         `json:"created_at" doc:"Creation timestamp"`
	StartedAt *string        `json:"started_at,omitempty" doc:"Start timestamp"`
	StoppedAt *string        `json:"stopped_at,omitempty" doc:"Stop timestamp"`
}

type driveResponse struct {
	ID        string  `json:"id" doc:"Drive ID"`
	Name      string  `json:"name" doc:"Drive name"`
	SizeBytes uint64  `json:"size_bytes" doc:"Size in bytes"`
	MountPath string  `json:"mount_path" doc:"Mount path"`
	VMID      *string `json:"vm_id,omitempty" doc:"Attached VM ID"`
	CreatedAt string  `json:"created_at" doc:"Creation timestamp"`
}

type deviceResponse struct {
	ID            string  `json:"id" doc:"Device ID"`
	Name          string  `json:"name" doc:"Device name"`
	HostPath      string  `json:"host_path" doc:"Host device path"`
	ContainerPath string  `json:"container_path" doc:"Container device path"`
	Permissions   string  `json:"permissions" doc:"Device permissions"`
	GID           uint32  `json:"gid" doc:"Device group ID"`
	VMID          *string `json:"vm_id,omitempty" doc:"Attached VM ID"`
	CreatedAt     string  `json:"created_at" doc:"Creation timestamp"`
}

type execResponse struct {
	ExitCode int    `json:"exit_code" doc:"Process exit code"`
	Stdout   string `json:"stdout" doc:"Standard output"`
	Stderr   string `json:"stderr" doc:"Standard error"`
}

// --- helpers ---

func vmToResponse(vm *domain.VM) vmResponse {
	r := vmResponse{
		ID:        vm.ID,
		Name:      vm.Name,
		Role:      string(vm.Role),
		State:     string(vm.State),
		Image:     vm.Image,
		Runtime:   vm.Runtime,
		IP:        vm.IP,
		Gateway:   vm.Gateway,
		CreatedAt: vm.CreatedAt.UTC().Format(timeFormatJSON),
	}
	if vm.DNSConfig != nil {
		r.DNS = &dnsConfigBody{
			Servers: vm.DNSConfig.Servers,
			Search:  vm.DNSConfig.Search,
		}
	}
	if vm.StartedAt != nil {
		s := vm.StartedAt.UTC().Format(timeFormatJSON)
		r.StartedAt = &s
	}
	if vm.StoppedAt != nil {
		s := vm.StoppedAt.UTC().Format(timeFormatJSON)
		r.StoppedAt = &s
	}
	return r
}

func driveToResponse(d *domain.Drive) driveResponse {
	r := driveResponse{
		ID:        d.ID,
		Name:      d.Name,
		SizeBytes: d.SizeBytes,
		MountPath: d.MountPath,
		CreatedAt: d.CreatedAt.UTC().Format(timeFormatJSON),
	}
	if d.VMID != "" {
		r.VMID = &d.VMID
	}
	return r
}

func deviceToResponse(d *domain.Device) deviceResponse {
	r := deviceResponse{
		ID:            d.ID,
		Name:          d.Name,
		HostPath:      d.HostPath,
		ContainerPath: d.ContainerPath,
		Permissions:   d.Permissions,
		GID:           d.GID,
		CreatedAt:     d.CreatedAt.UTC().Format(timeFormatJSON),
	}
	if d.VMID != "" {
		r.VMID = &d.VMID
	}
	return r
}

func mapDomainError(err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return huma.NewError(http.StatusNotFound, "not found")
	case errors.Is(err, domain.ErrAlreadyExists):
		return huma.NewError(http.StatusConflict, "already exists")
	case errors.Is(err, domain.ErrInvalidState):
		return huma.NewError(http.StatusConflict, "invalid state transition")
	case errors.Is(err, domain.ErrNetworkInUse):
		return huma.NewError(http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrDriveAttached):
		return huma.NewError(http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrDeviceAttached):
		return huma.NewError(http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrValidation):
		return huma.NewError(http.StatusBadRequest, err.Error())
	default:
		log.Error("internal error", "err", err)
		return huma.NewError(http.StatusInternalServerError, "internal server error")
	}
}

// --- API setup ---

// NewHandler returns an http.Handler with all Nexus API routes and OpenAPI docs.
// OpenAPI spec is served at /openapi, interactive docs at /docs.
func NewHandler(svc *app.VMService) http.Handler {
	mux := http.NewServeMux()
	config := huma.DefaultConfig("Nexus API", "1.0.0")
	api := humago.New(mux, config)

	registerVMRoutes(api, svc)
	registerDriveRoutes(api, svc)
	registerDeviceRoutes(api, svc)
	registerNetworkRoutes(api, svc)

	return mux
}

// --- VM routes ---

func registerVMRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-vm",
		Method:        http.MethodPost,
		Path:          "/v1/vms",
		Summary:       "Create a VM",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"VMs"},
	}, func(ctx context.Context, input *CreateVMInput) (*VMOutput, error) {
		var dnsCfg *domain.DNSConfig
		if input.Body.DNS != nil {
			dnsCfg = &domain.DNSConfig{
				Servers: input.Body.DNS.Servers,
				Search:  input.Body.DNS.Search,
			}
		}

		vm, err := svc.CreateVM(ctx, domain.CreateVMParams{
			Name:      input.Body.Name,
			Role:      domain.VMRole(input.Body.Role),
			Image:     input.Body.Image,
			Runtime:   input.Body.Runtime,
			DNSConfig: dnsCfg,
		})
		if err != nil {
			return nil, mapDomainError(err)
		}

		return &VMOutput{Body: vmToResponse(vm)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-vms",
		Method:      http.MethodGet,
		Path:        "/v1/vms",
		Summary:     "List VMs",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *ListVMsInput) (*VMListOutput, error) {
		var filter domain.VMFilter
		if input.Role != "" {
			vmRole := domain.VMRole(input.Role)
			if !domain.ValidRole(vmRole) {
				return nil, huma.NewError(http.StatusBadRequest, "invalid role filter")
			}
			filter.Role = &vmRole
		}

		vms, err := svc.ListVMs(ctx, filter)
		if err != nil {
			return nil, mapDomainError(err)
		}

		resp := make([]vmResponse, len(vms))
		for i, vm := range vms {
			resp[i] = vmToResponse(vm)
		}
		return &VMListOutput{Body: resp}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-vm",
		Method:      http.MethodGet,
		Path:        "/v1/vms/{id}",
		Summary:     "Get a VM",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *VMPathInput) (*VMOutput, error) {
		vm, err := svc.GetVM(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &VMOutput{Body: vmToResponse(vm)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-vm",
		Method:        http.MethodDelete,
		Path:          "/v1/vms/{id}",
		Summary:       "Delete a VM",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"VMs"},
	}, func(ctx context.Context, input *VMPathInput) (*struct{}, error) {
		if err := svc.DeleteVM(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "start-vm",
		Method:        http.MethodPost,
		Path:          "/v1/vms/{id}/start",
		Summary:       "Start a VM",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"VMs"},
	}, func(ctx context.Context, input *VMPathInput) (*struct{}, error) {
		if err := svc.StartVM(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "stop-vm",
		Method:        http.MethodPost,
		Path:          "/v1/vms/{id}/stop",
		Summary:       "Stop a VM",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"VMs"},
	}, func(ctx context.Context, input *VMPathInput) (*struct{}, error) {
		if err := svc.StopVM(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "exec-vm",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/exec",
		Summary:     "Execute a command in a VM",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *ExecVMInput) (*ExecOutput, error) {
		result, err := svc.ExecVM(ctx, input.ID, input.Body.Cmd)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &ExecOutput{Body: execResponse{
			ExitCode: result.ExitCode,
			Stdout:   result.Stdout,
			Stderr:   result.Stderr,
		}}, nil
	})
}

// --- Drive routes ---

func registerDriveRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-drive",
		Method:        http.MethodPost,
		Path:          "/v1/drives",
		Summary:       "Create a drive",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"Drives"},
	}, func(ctx context.Context, input *CreateDriveInput) (*DriveOutput, error) {
		d, err := svc.CreateDrive(ctx, domain.CreateDriveParams{
			Name:      input.Body.Name,
			Size:      input.Body.Size,
			MountPath: input.Body.MountPath,
		})
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &DriveOutput{Body: driveToResponse(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-drives",
		Method:      http.MethodGet,
		Path:        "/v1/drives",
		Summary:     "List drives",
		Tags:        []string{"Drives"},
	}, func(ctx context.Context, input *struct{}) (*DriveListOutput, error) {
		drives, err := svc.ListDrives(ctx)
		if err != nil {
			return nil, mapDomainError(err)
		}
		resp := make([]driveResponse, len(drives))
		for i, d := range drives {
			resp[i] = driveToResponse(d)
		}
		return &DriveListOutput{Body: resp}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-drive",
		Method:      http.MethodGet,
		Path:        "/v1/drives/{id}",
		Summary:     "Get a drive",
		Tags:        []string{"Drives"},
	}, func(ctx context.Context, input *DrivePathInput) (*DriveOutput, error) {
		d, err := svc.GetDrive(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &DriveOutput{Body: driveToResponse(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-drive",
		Method:        http.MethodDelete,
		Path:          "/v1/drives/{id}",
		Summary:       "Delete a drive",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"Drives"},
	}, func(ctx context.Context, input *DrivePathInput) (*struct{}, error) {
		if err := svc.DeleteDrive(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "attach-drive",
		Method:      http.MethodPost,
		Path:        "/v1/drives/{id}/attach",
		Summary:     "Attach drive to VM",
		Tags:        []string{"Drives"},
	}, func(ctx context.Context, input *AttachDriveInput) (*StatusOutput, error) {
		if err := svc.AttachDrive(ctx, input.ID, input.Body.VMID); err != nil {
			return nil, mapDomainError(err)
		}
		return &StatusOutput{Body: statusBody{Status: "ok"}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "detach-drive",
		Method:      http.MethodPost,
		Path:        "/v1/drives/{id}/detach",
		Summary:     "Detach drive from VM",
		Tags:        []string{"Drives"},
	}, func(ctx context.Context, input *DrivePathInput) (*StatusOutput, error) {
		if err := svc.DetachDrive(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return &StatusOutput{Body: statusBody{Status: "ok"}}, nil
	})
}

// --- Device routes ---

func registerDeviceRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-device",
		Method:        http.MethodPost,
		Path:          "/v1/devices",
		Summary:       "Create a device mapping",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"Devices"},
	}, func(ctx context.Context, input *CreateDeviceInput) (*DeviceOutput, error) {
		d, err := svc.CreateDevice(ctx, domain.CreateDeviceParams{
			Name:          input.Body.Name,
			HostPath:      input.Body.HostPath,
			ContainerPath: input.Body.ContainerPath,
			Permissions:   input.Body.Permissions,
			GID:           input.Body.GID,
		})
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &DeviceOutput{Body: deviceToResponse(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-devices",
		Method:      http.MethodGet,
		Path:        "/v1/devices",
		Summary:     "List devices",
		Tags:        []string{"Devices"},
	}, func(ctx context.Context, input *struct{}) (*DeviceListOutput, error) {
		devices, err := svc.ListDevices(ctx)
		if err != nil {
			return nil, mapDomainError(err)
		}
		resp := make([]deviceResponse, len(devices))
		for i, d := range devices {
			resp[i] = deviceToResponse(d)
		}
		return &DeviceListOutput{Body: resp}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-device",
		Method:      http.MethodGet,
		Path:        "/v1/devices/{id}",
		Summary:     "Get a device",
		Tags:        []string{"Devices"},
	}, func(ctx context.Context, input *DevicePathInput) (*DeviceOutput, error) {
		d, err := svc.GetDevice(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &DeviceOutput{Body: deviceToResponse(d)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-device",
		Method:        http.MethodDelete,
		Path:          "/v1/devices/{id}",
		Summary:       "Delete a device mapping",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"Devices"},
	}, func(ctx context.Context, input *DevicePathInput) (*struct{}, error) {
		if err := svc.DeleteDevice(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "attach-device",
		Method:      http.MethodPost,
		Path:        "/v1/devices/{id}/attach",
		Summary:     "Attach device to VM",
		Tags:        []string{"Devices"},
	}, func(ctx context.Context, input *AttachDeviceInput) (*StatusOutput, error) {
		if err := svc.AttachDevice(ctx, input.ID, input.Body.VMID); err != nil {
			return nil, mapDomainError(err)
		}
		return &StatusOutput{Body: statusBody{Status: "ok"}}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "detach-device",
		Method:      http.MethodPost,
		Path:        "/v1/devices/{id}/detach",
		Summary:     "Detach device from VM",
		Tags:        []string{"Devices"},
	}, func(ctx context.Context, input *DevicePathInput) (*StatusOutput, error) {
		if err := svc.DetachDevice(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return &StatusOutput{Body: statusBody{Status: "ok"}}, nil
	})
}

// --- Network routes ---

func registerNetworkRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID: "reset-network",
		Method:      http.MethodPost,
		Path:        "/v1/network/reset",
		Summary:     "Reset network bridge and CNI state",
		Tags:        []string{"Network"},
	}, func(ctx context.Context, input *struct{}) (*StatusOutput, error) {
		if err := svc.ResetNetwork(ctx); err != nil {
			return nil, mapDomainError(err)
		}
		return &StatusOutput{Body: statusBody{Status: "ok"}}, nil
	})
}
```

**Step 2: Verify it compiles**

```bash
go build ./internal/infra/httpapi/...
```

Expected: Compiles without errors. If `huma.NewError` doesn't exist, try `huma.Error404NotFound` etc. or check the huma v2 API.

**Step 3: Commit**

```bash
git add internal/infra/httpapi/handler.go
git commit -m "feat: migrate all HTTP handlers to huma v2

Replace func(w,r) handlers with huma typed handlers. This generates
an OpenAPI 3.1 spec at /openapi and interactive docs at /docs.
20 endpoints migrated: VMs (7), Drives (6), Devices (6), Network (1)."
```

---

### Task 4: Update handler tests for huma

The handler tests need minor updates. The `doRequest` helper must only set `Content-Type` when a body is present (huma is stricter about this). The `setupHandler` and test assertions stay the same because:

- `NewHandler` still returns `http.Handler`
- Success response JSON shape is unchanged (same structs)
- Tests check HTTP status codes, not error body format

**Files:**
- Modify: `internal/infra/httpapi/handler_test.go`

**Step 1: Update doRequest helper**

In `internal/infra/httpapi/handler_test.go`, replace the `doRequest` function (lines 140–150):

Old:
```go
func doRequest(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
```

New:
```go
func doRequest(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		var buf bytes.Buffer
		json.NewEncoder(&buf).Encode(body)
		req = httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
```

**Step 2: Run handler tests**

```bash
go test -v ./internal/infra/httpapi/...
```

Expected: All tests pass. If any test fails:

- **Status code mismatch on bad JSON (getting 422 instead of 400):** Huma returns 422 for validation errors but 400 for parse errors. Check which it is and adjust the test expectation if needed.
- **Status code mismatch on empty cmd (getting 422 instead of 400):** This means huma is doing its own validation before our handler runs. Remove any validation-related struct tags (like `minItems`) from input types and keep validation in the app layer.
- **Empty list returns null instead of []:** Ensure `make([]vmResponse, len(vms))` is used (not `var resp []vmResponse`) to create non-nil empty slices.

**Step 3: Run all tests**

```bash
go test ./...
```

Expected: All tests pass (app layer tests should be unaffected).

**Step 4: Commit**

```bash
git add internal/infra/httpapi/handler_test.go
git commit -m "test: update handler tests for huma v2 compatibility

Only change: doRequest helper now sets Content-Type only when a
request body is present, avoiding huma parsing empty bodies."
```

---

### Task 5: Build and verify

**Step 1: Full build**

```bash
mise run build
```

Expected: All binaries build successfully.

**Step 2: Full test suite**

```bash
go test ./...
```

Expected: All tests pass.

**Step 3: Vet**

```bash
go vet ./...
```

Expected: No issues.

**Step 4: Commit if any fixes were needed**

If steps 1-3 required fixes, commit them:

```bash
git add -A
git commit -m "fix: address build/test issues from huma migration"
```

---

### Task 6: Add OpenAPI spec export task

Add a mise task to export the OpenAPI spec from a running daemon. This requires the daemon to be running — a build-time export tool can be added later.

**Files:**
- Modify: `mise.toml`

**Step 1: Add export task to mise.toml**

Add after the existing tasks:

```toml
[tasks."openapi:export"]
description = "Export OpenAPI spec from running daemon (daemon must be running)"
run = "curl -sf http://127.0.0.1:9600/openapi -o docs/openapi.json && echo 'Exported to docs/openapi.json'"
```

**Step 2: Commit**

```bash
git add mise.toml
git commit -m "chore: add mise task for OpenAPI spec export"
```

---

## Summary of changes

| File | Change |
|------|--------|
| `internal/infra/httpapi/webhook.go` | **Deleted** |
| `internal/infra/httpapi/webhook_test.go` | **Deleted** |
| `internal/app/vm_service.go` | Remove `SharkfinWebhook` struct + `HandleWebhook` method |
| `internal/app/vm_service_test.go` | Remove 3 webhook tests |
| `internal/infra/httpapi/handler.go` | **Full rewrite** — huma v2 typed handlers |
| `internal/infra/httpapi/handler_test.go` | Update `doRequest` helper for huma compatibility |
| `internal/config/config.go` | Remove `webhook-url` viper default |
| `go.mod` / `go.sum` | Add `github.com/danielgtaylor/huma/v2` |
| `mise.toml` | Add `openapi:export` task |
| `cmd/daemon.go` | **No changes** — `NewHandler` signature unchanged |

## Key design decisions

- **No huma struct tag validation** — all validation stays in the app layer (returns 400 consistently, not huma's 422).
- **`huma.NewError(status, msg)`** for error mapping — safer than convenience functions that may not exist in all huma versions.
- **`*struct{}` return type** for 204 No Content endpoints — return `nil, nil` for empty responses.
- **`make([]T, len(items))`** for list endpoints — ensures JSON `[]` (not `null`) for empty results.
- **`doc:"..."` tags only** on struct fields — provides OpenAPI documentation without adding runtime validation.

## Verification

1. `mise run build` — all binaries compile
2. `go test ./...` — all tests pass
3. `go vet ./...` — no issues
4. Start daemon with `mise run run`, then:
   - `curl http://127.0.0.1:9600/openapi` — returns OpenAPI 3.1 JSON spec
   - `curl http://127.0.0.1:9600/docs` — returns interactive API docs page
   - `curl -X POST http://127.0.0.1:9600/v1/vms -H 'Content-Type: application/json' -d '{"name":"test","role":"agent"}'` — creates VM (201)
   - `curl http://127.0.0.1:9600/v1/vms` — lists VMs (200)
