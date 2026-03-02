// SPDX-License-Identifier: Apache-2.0

// Package httpapi implements the Nexus HTTP API.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
)

const maxBodySize = 1 << 20 // 1 MiB

// NewHandler returns an http.Handler with all Nexus API routes.
func NewHandler(svc *app.VMService) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/vms", handleCreateVM(svc))
	mux.HandleFunc("GET /v1/vms", handleListVMs(svc))
	mux.HandleFunc("GET /v1/vms/{id}", handleGetVM(svc))
	mux.HandleFunc("DELETE /v1/vms/{id}", handleDeleteVM(svc))
	mux.HandleFunc("POST /v1/vms/{id}/start", handleStartVM(svc))
	mux.HandleFunc("POST /v1/vms/{id}/stop", handleStopVM(svc))
	mux.HandleFunc("POST /v1/vms/{id}/exec", handleExecVM(svc))
	mux.HandleFunc("POST /v1/network/reset", handleResetNetwork(svc))

	mux.HandleFunc("POST /v1/drives", handleCreateDrive(svc))
	mux.HandleFunc("GET /v1/drives", handleListDrives(svc))
	mux.HandleFunc("GET /v1/drives/{id}", handleGetDrive(svc))
	mux.HandleFunc("DELETE /v1/drives/{id}", handleDeleteDrive(svc))
	mux.HandleFunc("POST /v1/drives/{id}/attach", handleAttachDrive(svc))
	mux.HandleFunc("POST /v1/drives/{id}/detach", handleDetachDrive(svc))

	mux.HandleFunc("POST /v1/devices", handleCreateDevice(svc))
	mux.HandleFunc("GET /v1/devices", handleListDevices(svc))
	mux.HandleFunc("GET /v1/devices/{id}", handleGetDevice(svc))
	mux.HandleFunc("DELETE /v1/devices/{id}", handleDeleteDevice(svc))
	mux.HandleFunc("POST /v1/devices/{id}/attach", handleAttachDevice(svc))
	mux.HandleFunc("POST /v1/devices/{id}/detach", handleDetachDevice(svc))

	mux.HandleFunc("POST /webhooks/sharkfin", handleSharkfinWebhook(svc))

	return mux
}

// --- request/response types ---

type dnsConfigRequest struct {
	Servers []string `json:"servers,omitempty"`
	Search  []string `json:"search,omitempty"`
}

type createVMRequest struct {
	Name    string            `json:"name"`
	Role    string            `json:"role"`
	Image   string            `json:"image"`
	Runtime string            `json:"runtime"`
	DNS     *dnsConfigRequest `json:"dns,omitempty"`
}

type vmResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Role      string            `json:"role"`
	State     string            `json:"state"`
	Image     string            `json:"image"`
	Runtime   string            `json:"runtime"`
	IP        string            `json:"ip,omitempty"`
	Gateway   string            `json:"gateway,omitempty"`
	DNS       *dnsConfigRequest `json:"dns,omitempty"`
	CreatedAt string            `json:"created_at"`
	StartedAt *string           `json:"started_at,omitempty"`
	StoppedAt *string           `json:"stopped_at,omitempty"`
}

type createDriveRequest struct {
	Name      string `json:"name"`
	Size      string `json:"size"`
	MountPath string `json:"mount_path"`
}

type attachDriveRequest struct {
	VMID string `json:"vm_id"`
}

type driveResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	SizeBytes uint64  `json:"size_bytes"`
	MountPath string  `json:"mount_path"`
	VMID      *string `json:"vm_id,omitempty"`
	CreatedAt string  `json:"created_at"`
}

type createDeviceRequest struct {
	Name          string `json:"name"`
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Permissions   string `json:"permissions"`
	GID           uint32 `json:"gid"`
}

type attachDeviceRequest struct {
	VMID string `json:"vm_id"`
}

type deviceResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	HostPath      string  `json:"host_path"`
	ContainerPath string  `json:"container_path"`
	Permissions   string  `json:"permissions"`
	GID           uint32  `json:"gid"`
	VMID          *string `json:"vm_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

type execRequest struct {
	Cmd []string `json:"cmd"`
}

type execResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func mapError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, domain.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "already exists")
	case errors.Is(err, domain.ErrInvalidState):
		writeError(w, http.StatusConflict, "invalid state transition")
	case errors.Is(err, domain.ErrNetworkInUse):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrDriveAttached):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrDeviceAttached):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, domain.ErrValidation):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		log.Error("internal error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}

const timeFormatJSON = "2006-01-02T15:04:05.000Z"

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
		r.DNS = &dnsConfigRequest{
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

// --- handlers ---

func handleCreateVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req createVMRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		var dnsCfg *domain.DNSConfig
		if req.DNS != nil {
			dnsCfg = &domain.DNSConfig{
				Servers: req.DNS.Servers,
				Search:  req.DNS.Search,
			}
		}

		vm, err := svc.CreateVM(r.Context(), domain.CreateVMParams{
			Name:      req.Name,
			Role:      domain.VMRole(req.Role),
			Image:     req.Image,
			Runtime:   req.Runtime,
			DNSConfig: dnsCfg,
		})
		if err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, vmToResponse(vm))
	}
}

func handleListVMs(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var filter domain.VMFilter
		if role := r.URL.Query().Get("role"); role != "" {
			vmRole := domain.VMRole(role)
			if !domain.ValidRole(vmRole) {
				writeError(w, http.StatusBadRequest, "invalid role filter")
				return
			}
			filter.Role = &vmRole
		}

		vms, err := svc.ListVMs(r.Context(), filter)
		if err != nil {
			mapError(w, err)
			return
		}

		resp := make([]vmResponse, len(vms))
		for i, vm := range vms {
			resp[i] = vmToResponse(vm)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		vm, err := svc.GetVM(r.Context(), id)
		if err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, vmToResponse(vm))
	}
}

func handleDeleteVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DeleteVM(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleStartVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.StartVM(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleStopVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.StopVM(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleExecVM(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req execRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		result, err := svc.ExecVM(r.Context(), id, req.Cmd)
		if err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, execResponse{
			ExitCode: result.ExitCode,
			Stdout:   result.Stdout,
			Stderr:   result.Stderr,
		})
	}
}

func handleResetNetwork(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.ResetNetwork(r.Context()); err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// --- drive handlers ---

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

func handleCreateDrive(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req createDriveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		d, err := svc.CreateDrive(r.Context(), domain.CreateDriveParams{
			Name:      req.Name,
			Size:      req.Size,
			MountPath: req.MountPath,
		})
		if err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, driveToResponse(d))
	}
}

func handleListDrives(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		drives, err := svc.ListDrives(r.Context())
		if err != nil {
			mapError(w, err)
			return
		}
		resp := make([]driveResponse, len(drives))
		for i, d := range drives {
			resp[i] = driveToResponse(d)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetDrive(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		d, err := svc.GetDrive(r.Context(), id)
		if err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, driveToResponse(d))
	}
}

func handleDeleteDrive(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DeleteDrive(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleAttachDrive(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req attachDriveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if err := svc.AttachDrive(r.Context(), id, req.VMID); err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func handleDetachDrive(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DetachDrive(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// --- device handlers ---

func handleCreateDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req createDeviceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		d, err := svc.CreateDevice(r.Context(), domain.CreateDeviceParams{
			Name:          req.Name,
			HostPath:      req.HostPath,
			ContainerPath: req.ContainerPath,
			Permissions:   req.Permissions,
			GID:           req.GID,
		})
		if err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, deviceToResponse(d))
	}
}

func handleListDevices(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		devices, err := svc.ListDevices(r.Context())
		if err != nil {
			mapError(w, err)
			return
		}
		resp := make([]deviceResponse, len(devices))
		for i, d := range devices {
			resp[i] = deviceToResponse(d)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		d, err := svc.GetDevice(r.Context(), id)
		if err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, deviceToResponse(d))
	}
}

func handleDeleteDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DeleteDevice(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleAttachDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		var req attachDeviceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if err := svc.AttachDevice(r.Context(), id, req.VMID); err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func handleDetachDevice(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.DetachDevice(r.Context(), id); err != nil {
			mapError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
