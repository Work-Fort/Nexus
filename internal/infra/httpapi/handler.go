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
	mux.HandleFunc("POST /webhooks/sharkfin", handleSharkfinWebhook(svc))

	return mux
}

// --- request/response types ---

type createVMRequest struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Image   string `json:"image"`
	Runtime string `json:"runtime"`
}

type vmResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Role      string  `json:"role"`
	State     string  `json:"state"`
	Image     string  `json:"image"`
	Runtime   string  `json:"runtime"`
	CreatedAt string  `json:"created_at"`
	StartedAt *string `json:"started_at,omitempty"`
	StoppedAt *string `json:"stopped_at,omitempty"`
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
		CreatedAt: vm.CreatedAt.UTC().Format(timeFormatJSON),
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

		vm, err := svc.CreateVM(r.Context(), domain.CreateVMParams{
			Name:    req.Name,
			Role:    domain.VMRole(req.Role),
			Image:   req.Image,
			Runtime: req.Runtime,
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
