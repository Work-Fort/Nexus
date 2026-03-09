// SPDX-License-Identifier: GPL-3.0-or-later

// Package httpapi implements the Nexus HTTP API with OpenAPI 3.1 documentation.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/danielgtaylor/huma/v2/sse"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/bytesize"
)

const timeFormatJSON = "2006-01-02T15:04:05.000Z"

// --- huma input types ---

type CreateVMInput struct {
	Body struct {
		Name     string         `json:"name" doc:"VM name"`
		Tags     []string       `json:"tags,omitempty" doc:"VM tags (e.g. agent, dev)"`
		Image    string         `json:"image,omitempty" doc:"OCI image"`
		Runtime  string         `json:"runtime,omitempty" doc:"Container runtime handler"`
		DNS      *dnsConfigBody `json:"dns,omitempty" doc:"DNS configuration"`
		RootSize        string         `json:"root_size,omitempty" doc:"Root filesystem size limit (e.g. 1G, 500M)"`
		RestartPolicy   string         `json:"restart_policy,omitempty" doc:"Restart policy (none, on-boot, always)" default:"none"`
		RestartStrategy string         `json:"restart_strategy,omitempty" doc:"Restart strategy (immediate, backoff, fixed)" default:"backoff"`
		Shell           string         `json:"shell,omitempty" doc:"Default shell for console sessions"`
		Init            bool           `json:"init,omitempty" doc:"Enable init injection"`
		Template        string         `json:"template,omitempty" doc:"Template name for provisioning"`
	}
}

type ListVMsInput struct {
	Tag      []string `query:"tag" doc:"Filter by tag (AND by default)"`
	TagMatch string   `query:"tag_match" doc:"Tag match mode: all (default) or any"`
}

type UpdateTagsInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		Tags []string `json:"tags" doc:"New tags for the VM"`
	}
}

type VMPathInput struct {
	ID string `path:"id" doc:"VM ID or name"`
}

type PatchVMInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		RootSize string  `json:"root_size" doc:"New root size (must be larger than current)"`
		Shell    *string `json:"shell,omitempty" doc:"Default shell for console sessions"`
	}
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

type UpdateRestartPolicyInput struct {
	ID   string `path:"id" doc:"VM ID or name"`
	Body struct {
		RestartPolicy   string `json:"restart_policy" doc:"Restart policy (none, on-boot, always)"`
		RestartStrategy string `json:"restart_strategy" doc:"Restart strategy (immediate, backoff, fixed)"`
	}
}

type CreateTemplateInput struct {
	Body struct {
		Name   string `json:"name" doc:"Template name"`
		Distro string `json:"distro" doc:"Target distro (matches /etc/os-release ID)"`
		Script string `json:"script" doc:"Provisioning script content"`
	}
}

type TemplatePathInput struct {
	ID string `path:"ref" doc:"Template ID or name"`
}

type UpdateTemplateInput struct {
	ID   string `path:"ref" doc:"Template ID or name"`
	Body struct {
		Name   string `json:"name,omitempty" doc:"Template name"`
		Distro string `json:"distro,omitempty" doc:"Target distro"`
		Script string `json:"script,omitempty" doc:"Provisioning script content"`
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

type TemplateOutput struct {
	Body templateResponse
}

type TemplateListOutput struct {
	Body []templateResponse
}

type StatusOutput struct {
	Body statusBody
}

type PrometheusTargetsOutput struct {
	Body []prometheusTarget
}

// --- response body types ---

type prometheusTarget struct {
	Targets []string          `json:"targets" doc:"List of host:port targets"`
	Labels  map[string]string `json:"labels" doc:"Label set for this target group"`
}

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
	Tags      []string       `json:"tags" doc:"VM tags"`
	State     string         `json:"state" doc:"Current state"`
	Image     string         `json:"image" doc:"OCI image"`
	Runtime   string         `json:"runtime" doc:"Runtime handler"`
	IP        string         `json:"ip,omitempty" doc:"Assigned IP address"`
	Gateway   string         `json:"gateway,omitempty" doc:"Network gateway"`
	DNS       *dnsConfigBody `json:"dns,omitempty" doc:"DNS configuration"`
	RootSize        *string        `json:"root_size,omitempty" doc:"Root filesystem size limit"`
	RestartPolicy   string         `json:"restart_policy" doc:"Restart policy"`
	RestartStrategy string         `json:"restart_strategy" doc:"Restart strategy"`
	Shell           string         `json:"shell,omitempty" doc:"Default shell for console sessions"`
	Init            bool           `json:"init" doc:"Whether init injection is enabled"`
	TemplateID      string         `json:"template_id,omitempty" doc:"Provisioning template ID"`
	ScriptOverride  string         `json:"script_override,omitempty" doc:"Per-VM script override"`
	CreatedAt       string         `json:"created_at" doc:"Creation timestamp"`
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

type templateResponse struct {
	ID        string `json:"id" doc:"Template ID"`
	Name      string `json:"name" doc:"Template name"`
	Distro    string `json:"distro" doc:"Target distro"`
	Script    string `json:"script" doc:"Provisioning script"`
	CreatedAt string `json:"created_at" doc:"Creation timestamp"`
	UpdatedAt string `json:"updated_at" doc:"Last update timestamp"`
}

type execResponse struct {
	ExitCode int    `json:"exit_code" doc:"Process exit code"`
	Stdout   string `json:"stdout" doc:"Standard output"`
	Stderr   string `json:"stderr" doc:"Standard error"`
}

// --- SSE exec stream types ---

type stdoutData struct {
	Data string `json:"data"`
}
type stderrData struct {
	Data string `json:"data"`
}
type exitData struct {
	ExitCode int `json:"exit_code"`
}

// sseWriter adapts an SSE sender into an io.Writer. Each Write call sends one
// SSE event whose type is determined by the makeMsg function.
type sseWriter struct {
	send    sse.Sender
	makeMsg func(string) sse.Message
	mu      *sync.Mutex
}

func (w *sseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.send(w.makeMsg(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// --- helpers ---

func vmToResponse(vm *domain.VM) vmResponse {
	tags := vm.Tags
	if tags == nil {
		tags = []string{}
	}
	r := vmResponse{
		ID:        vm.ID,
		Name:      vm.Name,
		Tags:      tags,
		State:     string(vm.State),
		Image:     vm.Image,
		Runtime:   vm.Runtime,
		IP:        vm.IP,
		Gateway:   vm.Gateway,
		CreatedAt: vm.CreatedAt.UTC().Format(timeFormatJSON),
	}
	r.RestartPolicy = string(vm.RestartPolicy)
	r.RestartStrategy = string(vm.RestartStrategy)
	r.Shell = vm.Shell
	r.Init = vm.Init
	r.TemplateID = vm.TemplateID
	r.ScriptOverride = vm.ScriptOverride
	if vm.DNSConfig != nil {
		r.DNS = &dnsConfigBody{
			Servers: vm.DNSConfig.Servers,
			Search:  vm.DNSConfig.Search,
		}
	}
	if vm.RootSize > 0 {
		s := bytesize.Format(uint64(vm.RootSize))
		r.RootSize = &s
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

func templateToResponse(t *domain.Template) templateResponse {
	return templateResponse{
		ID:        t.ID,
		Name:      t.Name,
		Distro:    t.Distro,
		Script:    t.Script,
		CreatedAt: t.CreatedAt.UTC().Format(timeFormatJSON),
		UpdatedAt: t.UpdatedAt.UTC().Format(timeFormatJSON),
	}
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
	case errors.Is(err, domain.ErrUnavailable):
		return huma.NewError(http.StatusServiceUnavailable, err.Error())
	default:
		log.Error("internal error", "err", err)
		return huma.NewError(http.StatusInternalServerError, "internal server error")
	}
}

// --- API setup ---

// NewHandler returns an http.Handler with all Nexus API routes and OpenAPI docs.
// OpenAPI spec is served at /openapi, interactive docs at /docs.
func NewHandler(svc *app.VMService, health *app.HealthService) http.Handler {
	mux := http.NewServeMux()
	config := huma.DefaultConfig("Nexus API", "1.0.0")
	api := humago.New(mux, config)

	registerVMRoutes(api, svc)
	registerDriveRoutes(api, svc)
	registerDeviceRoutes(api, svc)
	registerTemplateRoutes(api, svc)
	registerSnapshotRoutes(api, svc)
	registerNetworkRoutes(api, svc)
	registerBackupRoutes(api, svc)
	registerPrometheusRoutes(api, svc)

	// WebSocket endpoints (not supported by huma).
	mux.HandleFunc("GET /v1/vms/{id}/console", handleConsole(svc))

	// Health endpoint uses raw HandleFunc — huma doesn't support conditional
	// status codes (200/218/503) from a single operation.
	mux.HandleFunc("GET /health", handleHealth(health))

	return mux
}

func handleHealth(health *app.HealthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := health.Status()

		var statusCode int
		switch report.Status {
		case app.StatusHealthy:
			statusCode = http.StatusOK
		case app.StatusDegraded:
			statusCode = 218
		default:
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(report) //nolint:errcheck
	}
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

		var rootSize int64
		if input.Body.RootSize != "" {
			sz, err := bytesize.Parse(input.Body.RootSize)
			if err != nil {
				return nil, huma.NewError(http.StatusBadRequest, err.Error())
			}
			rootSize = int64(sz)
		}

		vm, err := svc.CreateVM(ctx, domain.CreateVMParams{
			Name:            input.Body.Name,
			Tags:            input.Body.Tags,
			Image:           input.Body.Image,
			Runtime:         input.Body.Runtime,
			DNSConfig:       dnsCfg,
			RootSize:        rootSize,
			RestartPolicy:   domain.RestartPolicy(input.Body.RestartPolicy),
			RestartStrategy: domain.RestartStrategy(input.Body.RestartStrategy),
			Shell:           input.Body.Shell,
			Init:            input.Body.Init,
			TemplateName:    input.Body.Template,
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
		filter := domain.VMFilter{
			Tags:     input.Tag,
			TagMatch: input.TagMatch,
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

	huma.Register(api, huma.Operation{
		OperationID: "patch-vm",
		Method:      http.MethodPatch,
		Path:        "/v1/vms/{id}",
		Summary:     "Update VM settings",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *PatchVMInput) (*VMOutput, error) {
		if input.Body.RootSize != "" {
			sizeBytes, err := bytesize.Parse(input.Body.RootSize)
			if err != nil {
				return nil, huma.NewError(http.StatusBadRequest, err.Error())
			}
			if err := svc.ExpandRootSize(ctx, input.ID, int64(sizeBytes)); err != nil {
				return nil, mapDomainError(err)
			}
		}
		if input.Body.Shell != nil {
			if _, err := svc.UpdateShell(ctx, input.ID, *input.Body.Shell); err != nil {
				return nil, mapDomainError(err)
			}
		}
		vm, err := svc.GetVM(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &VMOutput{Body: vmToResponse(vm)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-restart-policy",
		Method:      http.MethodPut,
		Path:        "/v1/vms/{id}/restart-policy",
		Summary:     "Update VM restart policy",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *UpdateRestartPolicyInput) (*VMOutput, error) {
		vm, err := svc.UpdateRestartPolicy(ctx, input.ID,
			domain.RestartPolicy(input.Body.RestartPolicy),
			domain.RestartStrategy(input.Body.RestartStrategy))
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &VMOutput{Body: vmToResponse(vm)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-tags",
		Method:      http.MethodPut,
		Path:        "/v1/vms/{id}/tags",
		Summary:     "Update VM tags",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *UpdateTagsInput) (*VMOutput, error) {
		vm, err := svc.SetTags(ctx, input.ID, input.Body.Tags)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &VMOutput{Body: vmToResponse(vm)}, nil
	})

	sse.Register(api, huma.Operation{
		OperationID: "exec-stream-vm",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/exec/stream",
		Summary:     "Stream command output from a VM",
		Tags:        []string{"VMs"},
	}, map[string]any{
		"stdout": stdoutData{},
		"stderr": stderrData{},
		"exit":   exitData{},
	}, func(ctx context.Context, input *ExecVMInput, send sse.Sender) {
		var mu sync.Mutex
		stdoutW := &sseWriter{
			send: send,
			makeMsg: func(s string) sse.Message {
				return sse.Message{Data: stdoutData{Data: s}}
			},
			mu: &mu,
		}
		stderrW := &sseWriter{
			send: send,
			makeMsg: func(s string) sse.Message {
				return sse.Message{Data: stderrData{Data: s}}
			},
			mu: &mu,
		}

		exitCode, err := svc.ExecStreamVM(ctx, input.ID, input.Body.Cmd, stdoutW, stderrW)
		if err != nil {
			mu.Lock()
			send(sse.Message{Data: exitData{ExitCode: -1}}) //nolint:errcheck
			mu.Unlock()
			return
		}

		mu.Lock()
		send(sse.Message{Data: exitData{ExitCode: exitCode}}) //nolint:errcheck
		mu.Unlock()
	})

	huma.Register(api, huma.Operation{
		OperationID: "sync-vm-shell",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/sync-shell",
		Summary:     "Detect and sync VM shell",
		Description: "Detects the root user's default shell inside the running VM and persists it.",
		Tags:        []string{"VMs"},
	}, func(ctx context.Context, input *VMPathInput) (*VMOutput, error) {
		vm, err := svc.SyncShell(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &VMOutput{Body: vmToResponse(vm)}, nil
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

// --- Template routes ---

func registerTemplateRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-template",
		Method:        http.MethodPost,
		Path:          "/v1/templates",
		Summary:       "Create a provisioning template",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"Templates"},
	}, func(ctx context.Context, input *CreateTemplateInput) (*TemplateOutput, error) {
		t, err := svc.CreateTemplate(ctx, domain.CreateTemplateParams{
			Name:   input.Body.Name,
			Distro: input.Body.Distro,
			Script: input.Body.Script,
		})
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &TemplateOutput{Body: templateToResponse(t)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-templates",
		Method:      http.MethodGet,
		Path:        "/v1/templates",
		Summary:     "List provisioning templates",
		Tags:        []string{"Templates"},
	}, func(ctx context.Context, input *struct{}) (*TemplateListOutput, error) {
		templates, err := svc.ListTemplates(ctx)
		if err != nil {
			return nil, mapDomainError(err)
		}
		resp := make([]templateResponse, len(templates))
		for i, t := range templates {
			resp[i] = templateToResponse(t)
		}
		return &TemplateListOutput{Body: resp}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-template",
		Method:      http.MethodGet,
		Path:        "/v1/templates/{ref}",
		Summary:     "Get a provisioning template",
		Tags:        []string{"Templates"},
	}, func(ctx context.Context, input *TemplatePathInput) (*TemplateOutput, error) {
		t, err := svc.GetTemplate(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &TemplateOutput{Body: templateToResponse(t)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "update-template",
		Method:      http.MethodPut,
		Path:        "/v1/templates/{ref}",
		Summary:     "Update a provisioning template",
		Tags:        []string{"Templates"},
	}, func(ctx context.Context, input *UpdateTemplateInput) (*TemplateOutput, error) {
		t, err := svc.UpdateTemplate(ctx, input.ID, domain.CreateTemplateParams{
			Name:   input.Body.Name,
			Distro: input.Body.Distro,
			Script: input.Body.Script,
		})
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &TemplateOutput{Body: templateToResponse(t)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-template",
		Method:        http.MethodDelete,
		Path:          "/v1/templates/{ref}",
		Summary:       "Delete a provisioning template",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"Templates"},
	}, func(ctx context.Context, input *TemplatePathInput) (*struct{}, error) {
		if err := svc.DeleteTemplate(ctx, input.ID); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})
}

// --- Backup routes ---

func registerBackupRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID: "export-vm",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/export",
		Summary:     "Export a VM as a backup archive",
		Tags:        []string{"Backup"},
	}, func(ctx context.Context, input *struct {
		ID             string `path:"id" doc:"VM ID or name"`
		IncludeDevices bool   `query:"include_devices" default:"false" doc:"Include device mappings"`
	}) (*huma.StreamResponse, error) {
		// Buffer the archive so errors can be reported properly
		// rather than partially streaming a corrupt archive.
		var buf bytes.Buffer
		if err := svc.ExportVM(ctx, input.ID, input.IncludeDevices, &buf); err != nil {
			return nil, mapDomainError(err)
		}

		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				ctx.SetHeader("Content-Type", "application/zstd")
				ctx.SetHeader("Content-Disposition", `attachment; filename="nexus-backup.tar.zst"`)
				ctx.BodyWriter().Write(buf.Bytes()) //nolint:errcheck
			},
		}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "import-vm",
		Method:        http.MethodPost,
		Path:          "/v1/vms/import",
		Summary:       "Import a VM from a backup archive",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"Backup"},
	}, func(ctx context.Context, input *struct {
		StrictDevices bool `query:"strict_devices" default:"false" doc:"Error on missing devices"`
		RawBody       []byte
	}) (*struct {
		Body struct {
			VM       vmResponse `json:"vm"`
			Warnings []string   `json:"warnings,omitempty"`
		}
	}, error) {
		result, err := svc.ImportVM(ctx, bytes.NewReader(input.RawBody), input.StrictDevices)
		if err != nil {
			return nil, mapDomainError(err)
		}

		return &struct {
			Body struct {
				VM       vmResponse `json:"vm"`
				Warnings []string   `json:"warnings,omitempty"`
			}
		}{
			Body: struct {
				VM       vmResponse `json:"vm"`
				Warnings []string   `json:"warnings,omitempty"`
			}{
				VM:       vmToResponse(result.VM),
				Warnings: result.Warnings,
			},
		}, nil
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
			for _, tag := range vm.Tags {
				labels["__meta_nexus_vm_tag_"+tag] = "true"
			}
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

// --- Snapshot routes ---

type snapshotResponse struct {
	ID        string `json:"id"`
	VMID      string `json:"vm_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

func snapshotToResponse(s *domain.Snapshot) snapshotResponse {
	return snapshotResponse{
		ID:        s.ID,
		VMID:      s.VMID,
		Name:      s.Name,
		CreatedAt: s.CreatedAt.Format(timeFormatJSON),
	}
}

func registerSnapshotRoutes(api huma.API, svc *app.VMService) {
	huma.Register(api, huma.Operation{
		OperationID:   "create-snapshot",
		Method:        http.MethodPost,
		Path:          "/v1/vms/{id}/snapshots",
		Summary:       "Create a snapshot of a VM",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Body struct {
			Name string `json:"name" minLength:"1"`
		}
	}) (*struct{ Body snapshotResponse }, error) {
		snap, err := svc.CreateSnapshot(ctx, input.ID, input.Body.Name)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &struct{ Body snapshotResponse }{Body: snapshotToResponse(snap)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-snapshots",
		Method:      http.MethodGet,
		Path:        "/v1/vms/{id}/snapshots",
		Summary:     "List VM snapshots",
		Tags:        []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID string `path:"id"`
	}) (*struct{ Body []snapshotResponse }, error) {
		snaps, err := svc.ListSnapshots(ctx, input.ID)
		if err != nil {
			return nil, mapDomainError(err)
		}
		resp := make([]snapshotResponse, len(snaps))
		for i, s := range snaps {
			resp[i] = snapshotToResponse(s)
		}
		return &struct{ Body []snapshotResponse }{Body: resp}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "delete-snapshot",
		Method:        http.MethodDelete,
		Path:          "/v1/vms/{id}/snapshots/{snap}",
		Summary:       "Delete a snapshot",
		DefaultStatus: http.StatusNoContent,
		Tags:          []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Snap string `path:"snap"`
	}) (*struct{}, error) {
		if err := svc.DeleteSnapshot(ctx, input.ID, input.Snap); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "restore-snapshot",
		Method:      http.MethodPost,
		Path:        "/v1/vms/{id}/snapshots/{snap}/restore",
		Summary:     "Restore a VM to a snapshot",
		Tags:        []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Snap string `path:"snap"`
	}) (*struct{}, error) {
		if err := svc.RestoreSnapshot(ctx, input.ID, input.Snap); err != nil {
			return nil, mapDomainError(err)
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "clone-snapshot",
		Method:        http.MethodPost,
		Path:          "/v1/vms/{id}/snapshots/{snap}/clone",
		Summary:       "Clone a VM from a snapshot",
		DefaultStatus: http.StatusCreated,
		Tags:          []string{"Snapshots"},
	}, func(ctx context.Context, input *struct {
		ID   string `path:"id"`
		Snap string `path:"snap"`
		Body struct {
			Name string `json:"name" minLength:"1"`
		}
	}) (*struct{ Body vmResponse }, error) {
		vm, err := svc.CloneSnapshot(ctx, input.ID, input.Snap, input.Body.Name)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return &struct{ Body vmResponse }{Body: vmToResponse(vm)}, nil
	})
}
