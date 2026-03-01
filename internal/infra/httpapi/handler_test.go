// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/httpapi"
)

// --- mock VMStore ---

type mockStore struct {
	vms map[string]*domain.VM
}

func newMockStore() *mockStore {
	return &mockStore{vms: make(map[string]*domain.VM)}
}

func (m *mockStore) Create(_ context.Context, vm *domain.VM) error {
	if _, ok := m.vms[vm.ID]; ok {
		return domain.ErrAlreadyExists
	}
	m.vms[vm.ID] = vm
	return nil
}

func (m *mockStore) Get(_ context.Context, id string) (*domain.VM, error) {
	vm, ok := m.vms[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return vm, nil
}

func (m *mockStore) GetByName(_ context.Context, name string) (*domain.VM, error) {
	for _, vm := range m.vms {
		if vm.Name == name {
			return vm, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockStore) List(_ context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	var result []*domain.VM
	for _, vm := range m.vms {
		if filter.Role != nil && vm.Role != *filter.Role {
			continue
		}
		result = append(result, vm)
	}
	return result, nil
}

func (m *mockStore) UpdateState(_ context.Context, id string, state domain.VMState, now time.Time) error {
	vm, ok := m.vms[id]
	if !ok {
		return domain.ErrNotFound
	}
	vm.State = state
	switch state {
	case domain.VMStateRunning:
		vm.StartedAt = &now
	case domain.VMStateStopped:
		vm.StoppedAt = &now
	}
	return nil
}

func (m *mockStore) Delete(_ context.Context, id string) error {
	delete(m.vms, id)
	return nil
}

// --- mock Runtime ---

type mockRuntime struct {
	containers map[string]bool
}

func newMockRuntime() *mockRuntime {
	return &mockRuntime{containers: make(map[string]bool)}
}

func (m *mockRuntime) Create(_ context.Context, id, image, runtime string) error {
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) Start(_ context.Context, id string) error {
	m.containers[id] = true
	return nil
}

func (m *mockRuntime) Stop(_ context.Context, id string) error {
	m.containers[id] = false
	return nil
}

func (m *mockRuntime) Delete(_ context.Context, id string) error {
	delete(m.containers, id)
	return nil
}

func (m *mockRuntime) Exec(_ context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	return &domain.ExecResult{ExitCode: 0, Stdout: "ok\n"}, nil
}

// --- test helpers ---

func setupHandler() http.Handler {
	store := newMockStore()
	rt := newMockRuntime()
	svc := app.NewVMService(store, rt)
	return httpapi.NewHandler(svc)
}

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

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

// --- tests ---

func TestCreateVM(t *testing.T) {
	h := setupHandler()

	rec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name":    "test-agent",
		"role":    "agent",
		"image":   "alpine:latest",
		"runtime": "io.containerd.runc.v2",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)

	if resp["id"] == nil || resp["id"] == "" {
		t.Error("response missing id")
	}
	if resp["name"] != "test-agent" {
		t.Errorf("name = %v, want test-agent", resp["name"])
	}
	if resp["role"] != "agent" {
		t.Errorf("role = %v, want agent", resp["role"])
	}
	if resp["state"] != "created" {
		t.Errorf("state = %v, want created", resp["state"])
	}
}

func TestCreateVMBadJSON(t *testing.T) {
	h := setupHandler()

	req := httptest.NewRequest("POST", "/v1/vms", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateVMInvalidRole(t *testing.T) {
	h := setupHandler()

	rec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "bad", "role": "invalid", "image": "alpine:latest", "runtime": "runc",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestListVMsEmpty(t *testing.T) {
	h := setupHandler()

	rec := doRequest(h, "GET", "/v1/vms", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []any
	decodeJSON(t, rec, &resp)

	if len(resp) != 0 {
		t.Errorf("count = %d, want 0", len(resp))
	}
}

func TestListVMsWithResults(t *testing.T) {
	h := setupHandler()

	doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "vm1", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "vm2", "role": "service", "image": "alpine:latest", "runtime": "runc",
	})

	rec := doRequest(h, "GET", "/v1/vms", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []any
	decodeJSON(t, rec, &resp)

	if len(resp) != 2 {
		t.Errorf("count = %d, want 2", len(resp))
	}
}

func TestListVMsWithRoleFilter(t *testing.T) {
	h := setupHandler()

	doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "a1", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "s1", "role": "service", "image": "alpine:latest", "runtime": "runc",
	})

	rec := doRequest(h, "GET", "/v1/vms?role=agent", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []map[string]any
	decodeJSON(t, rec, &resp)

	if len(resp) != 1 {
		t.Errorf("count = %d, want 1", len(resp))
	}
	if len(resp) > 0 && resp[0]["role"] != "agent" {
		t.Errorf("role = %v, want agent", resp[0]["role"])
	}
}

func TestGetVMNotFound(t *testing.T) {
	h := setupHandler()

	rec := doRequest(h, "GET", "/v1/vms/nonexistent", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetVMFound(t *testing.T) {
	h := setupHandler()

	createRec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "get-me", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	var created map[string]any
	decodeJSON(t, createRec, &created)
	id := created["id"].(string)

	rec := doRequest(h, "GET", "/v1/vms/"+id, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)
	if resp["name"] != "get-me" {
		t.Errorf("name = %v, want get-me", resp["name"])
	}
}

func TestStartStopLifecycle(t *testing.T) {
	h := setupHandler()

	// Create
	createRec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "lifecycle", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	var created map[string]any
	decodeJSON(t, createRec, &created)
	id := created["id"].(string)

	// Start
	startRec := doRequest(h, "POST", "/v1/vms/"+id+"/start", nil)
	if startRec.Code != http.StatusNoContent {
		t.Fatalf("start status = %d, want %d; body: %s", startRec.Code, http.StatusNoContent, startRec.Body.String())
	}

	// Verify running
	getRec := doRequest(h, "GET", "/v1/vms/"+id, nil)
	var running map[string]any
	decodeJSON(t, getRec, &running)
	if running["state"] != "running" {
		t.Errorf("state after start = %v, want running", running["state"])
	}

	// Stop
	stopRec := doRequest(h, "POST", "/v1/vms/"+id+"/stop", nil)
	if stopRec.Code != http.StatusNoContent {
		t.Fatalf("stop status = %d, want %d; body: %s", stopRec.Code, http.StatusNoContent, stopRec.Body.String())
	}

	// Verify stopped
	getRec2 := doRequest(h, "GET", "/v1/vms/"+id, nil)
	var stopped map[string]any
	decodeJSON(t, getRec2, &stopped)
	if stopped["state"] != "stopped" {
		t.Errorf("state after stop = %v, want stopped", stopped["state"])
	}
}

func TestStartNonexistentVM(t *testing.T) {
	h := setupHandler()

	rec := doRequest(h, "POST", "/v1/vms/nonexistent/start", nil)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestStopNotRunningVM(t *testing.T) {
	h := setupHandler()

	createRec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "created-only", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	var created map[string]any
	decodeJSON(t, createRec, &created)
	id := created["id"].(string)

	rec := doRequest(h, "POST", "/v1/vms/"+id+"/stop", nil)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestDeleteVM(t *testing.T) {
	h := setupHandler()

	createRec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "delete-me", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	var created map[string]any
	decodeJSON(t, createRec, &created)
	id := created["id"].(string)

	// Delete
	deleteRec := doRequest(h, "DELETE", "/v1/vms/"+id, nil)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", deleteRec.Code, http.StatusNoContent)
	}

	// Verify gone
	getRec := doRequest(h, "GET", "/v1/vms/"+id, nil)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status = %d, want %d", getRec.Code, http.StatusNotFound)
	}
}

func TestExecVM(t *testing.T) {
	h := setupHandler()

	// Create and start
	createRec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "exec-me", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	var created map[string]any
	decodeJSON(t, createRec, &created)
	id := created["id"].(string)
	doRequest(h, "POST", "/v1/vms/"+id+"/start", nil)

	// Exec
	rec := doRequest(h, "POST", "/v1/vms/"+id+"/exec", map[string]any{
		"cmd": []string{"echo", "hello"},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)

	exitCode, ok := resp["exit_code"].(float64)
	if !ok || int(exitCode) != 0 {
		t.Errorf("exit_code = %v, want 0", resp["exit_code"])
	}
	if resp["stdout"] != "ok\n" {
		t.Errorf("stdout = %v, want ok\\n", resp["stdout"])
	}
}

func TestExecVMNotRunning(t *testing.T) {
	h := setupHandler()

	createRec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "exec-not-running", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	var created map[string]any
	decodeJSON(t, createRec, &created)
	id := created["id"].(string)

	rec := doRequest(h, "POST", "/v1/vms/"+id+"/exec", map[string]any{
		"cmd": []string{"echo", "hello"},
	})

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestExecVMEmptyCmd(t *testing.T) {
	h := setupHandler()

	createRec := doRequest(h, "POST", "/v1/vms", map[string]string{
		"name": "exec-empty", "role": "agent", "image": "alpine:latest", "runtime": "runc",
	})
	var created map[string]any
	decodeJSON(t, createRec, &created)
	id := created["id"].(string)
	doRequest(h, "POST", "/v1/vms/"+id+"/start", nil)

	rec := doRequest(h, "POST", "/v1/vms/"+id+"/exec", map[string]any{
		"cmd": []string{},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestListVMsInvalidRoleFilter(t *testing.T) {
	h := setupHandler()

	rec := doRequest(h, "GET", "/v1/vms?role=invalid", nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestExecVMBadJSON(t *testing.T) {
	h := setupHandler()

	req := httptest.NewRequest("POST", "/v1/vms/some-id/exec", bytes.NewBufferString("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
