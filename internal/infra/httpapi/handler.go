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
