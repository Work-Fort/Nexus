// SPDX-License-Identifier: GPL-3.0-or-later
package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateVM(t *testing.T) {
	want := VM{
		ID:              "vm-abc123",
		Name:            "test-vm",
		Tags:            []string{"worker"},
		State:           "created",
		Image:           "ubuntu:22.04",
		Runtime:         "kata-fc",
		RestartPolicy:   "no",
		RestartStrategy: "drain",
		CreatedAt:       "2026-03-06T10:00:00Z",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vms" {
			t.Errorf("expected /v1/vms, got %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json content-type, got %s", ct)
		}

		var params CreateVMParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if params.Name != "test-vm" {
			t.Errorf("expected name test-vm, got %s", params.Name)
		}
		if len(params.Tags) != 1 || params.Tags[0] != "worker" {
			t.Errorf("expected tags [worker], got %v", params.Tags)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.CreateVM(context.Background(), CreateVMParams{
		Name:  "test-vm",
		Tags:  []string{"worker"},
		Image: "ubuntu:22.04",
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q", got.ID, want.ID)
	}
	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q", got.Name, want.Name)
	}
	if got.State != want.State {
		t.Errorf("State = %q, want %q", got.State, want.State)
	}
	if got.Image != want.Image {
		t.Errorf("Image = %q, want %q", got.Image, want.Image)
	}
	if got.Runtime != want.Runtime {
		t.Errorf("Runtime = %q, want %q", got.Runtime, want.Runtime)
	}
}

func TestListVMs(t *testing.T) {
	vms := []VM{
		{ID: "vm-1", Name: "alpha", Tags: []string{"worker"}, State: "running", CreatedAt: "2026-03-06T10:00:00Z"},
		{ID: "vm-2", Name: "beta", Tags: []string{"manager"}, State: "stopped", CreatedAt: "2026-03-06T11:00:00Z"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vms" {
			t.Errorf("expected /v1/vms, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(vms)
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.ListVMs(context.Background(), ListVMsFilter{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(got))
	}
	if got[0].Name != "alpha" {
		t.Errorf("first VM name = %q, want %q", got[0].Name, "alpha")
	}
	if len(got[1].Tags) != 1 || got[1].Tags[0] != "manager" {
		t.Errorf("second VM tags = %v, want [manager]", got[1].Tags)
	}
}

func TestGetVM(t *testing.T) {
	want := VM{
		ID:        "vm-abc123",
		Name:      "my-vm",
		Tags:      []string{"worker"},
		State:     "running",
		IP:        "10.0.0.5",
		Gateway:   "10.0.0.1",
		CreatedAt: "2026-03-06T10:00:00Z",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vms/my-vm" {
			t.Errorf("expected /v1/vms/my-vm, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.GetVM(context.Background(), "my-vm")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q", got.ID, want.ID)
	}
	if got.IP != want.IP {
		t.Errorf("IP = %q, want %q", got.IP, want.IP)
	}
	if got.Gateway != want.Gateway {
		t.Errorf("Gateway = %q, want %q", got.Gateway, want.Gateway)
	}
}

func TestDeleteVM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vms/doomed-vm" {
			t.Errorf("expected /v1/vms/doomed-vm, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.DeleteVM(context.Background(), "doomed-vm")
	if err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
}

func TestStartVM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vms/my-vm/start" {
			t.Errorf("expected /v1/vms/my-vm/start, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.StartVM(context.Background(), "my-vm")
	if err != nil {
		t.Fatalf("StartVM: %v", err)
	}
}

func TestStopVM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vms/my-vm/stop" {
			t.Errorf("expected /v1/vms/my-vm/stop, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.StopVM(context.Background(), "my-vm")
	if err != nil {
		t.Fatalf("StopVM: %v", err)
	}
}

func TestExecVM(t *testing.T) {
	want := ExecResult{
		ExitCode: 0,
		Stdout:   "hello world\n",
		Stderr:   "",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/vms/my-vm/exec" {
			t.Errorf("expected /v1/vms/my-vm/exec, got %s", r.URL.Path)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		cmd, ok := body["cmd"].([]any)
		if !ok || len(cmd) != 2 {
			t.Fatalf("expected cmd with 2 elements, got %v", body["cmd"])
		}
		if cmd[0] != "echo" || cmd[1] != "hello world" {
			t.Errorf("unexpected cmd: %v", cmd)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.ExecVM(context.Background(), "my-vm", []string{"echo", "hello world"})
	if err != nil {
		t.Fatalf("ExecVM: %v", err)
	}
	if got.ExitCode != want.ExitCode {
		t.Errorf("ExitCode = %d, want %d", got.ExitCode, want.ExitCode)
	}
	if got.Stdout != want.Stdout {
		t.Errorf("Stdout = %q, want %q", got.Stdout, want.Stdout)
	}
	if got.Stderr != want.Stderr {
		t.Errorf("Stderr = %q, want %q", got.Stderr, want.Stderr)
	}
}

func TestGetVMNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"title":  "not found",
			"detail": "vm 'ghost' not found",
		})
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.GetVM(context.Background(), "ghost")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", apiErr.StatusCode)
	}
}

func TestGetVMConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"title":  "conflict",
			"detail": "vm is already running",
		})
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.GetVM(context.Background(), "busy-vm")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected ErrConflict, got %v", err)
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 409 {
		t.Errorf("StatusCode = %d, want 409", apiErr.StatusCode)
	}
}

func TestCreateDrive(t *testing.T) {
	want := Drive{
		ID:        "drv-xyz789",
		Name:      "data-vol",
		SizeBytes: 1073741824,
		MountPath: "/data",
		CreatedAt: "2026-03-06T12:00:00Z",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/drives" {
			t.Errorf("expected /v1/drives, got %s", r.URL.Path)
		}

		var params CreateDriveParams
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if params.Name != "data-vol" {
			t.Errorf("expected name data-vol, got %s", params.Name)
		}
		if params.Size != "1G" {
			t.Errorf("expected size 1G, got %s", params.Size)
		}
		if params.MountPath != "/data" {
			t.Errorf("expected mount_path /data, got %s", params.MountPath)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.CreateDrive(context.Background(), CreateDriveParams{
		Name:      "data-vol",
		Size:      "1G",
		MountPath: "/data",
	})
	if err != nil {
		t.Fatalf("CreateDrive: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("ID = %q, want %q", got.ID, want.ID)
	}
	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q", got.Name, want.Name)
	}
	if got.SizeBytes != want.SizeBytes {
		t.Errorf("SizeBytes = %d, want %d", got.SizeBytes, want.SizeBytes)
	}
	if got.MountPath != want.MountPath {
		t.Errorf("MountPath = %q, want %q", got.MountPath, want.MountPath)
	}
}

func TestResetNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/network/reset" {
			t.Errorf("expected /v1/network/reset, got %s", r.URL.Path)
		}

		// Verify body is empty (nil body passed to postExpectStatus).
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("expected empty body, got %q", string(body))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.ResetNetwork(context.Background())
	if err != nil {
		t.Fatalf("ResetNetwork: %v", err)
	}
}
