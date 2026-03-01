// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookSharkfin(t *testing.T) {
	h := setupHandler()

	rec := doRequest(h, "POST", "/webhooks/sharkfin", map[string]any{
		"event":        "message.new",
		"recipient":    "deploy-bot",
		"channel":      "ops",
		"channel_type": "channel",
		"from":         "dev-agent",
		"message_id":   42,
		"sent_at":      "2025-01-15T10:30:00Z",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp map[string]any
	decodeJSON(t, rec, &resp)

	if resp["status"] != "ok" {
		t.Errorf("status = %v, want ok", resp["status"])
	}
}

func TestWebhookSharkfinBadJSON(t *testing.T) {
	h := setupHandler()

	req := httptest.NewRequest("POST", "/webhooks/sharkfin", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestWebhookSharkfinCreatesAndStartsVM(t *testing.T) {
	h := setupHandler()

	// Webhook for a recipient that doesn't exist yet
	rec := doRequest(h, "POST", "/webhooks/sharkfin", map[string]any{
		"event":     "message.new",
		"recipient": "new-bot",
		"channel":   "general",
		"from":      "user",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify the VM was created and is running by listing VMs
	listRec := doRequest(h, "GET", "/v1/vms?role=agent", nil)
	var vms []map[string]any
	decodeJSON(t, listRec, &vms)

	found := false
	for _, vm := range vms {
		if vm["name"] == "new-bot" {
			found = true
			if vm["state"] != "running" {
				t.Errorf("state = %v, want running", vm["state"])
			}
		}
	}
	if !found {
		t.Error("VM 'new-bot' not found after webhook")
	}
}

func TestWebhookSharkfinIdempotent(t *testing.T) {
	h := setupHandler()

	// First webhook creates + starts
	doRequest(h, "POST", "/webhooks/sharkfin", map[string]any{
		"event":     "message.new",
		"recipient": "idempotent-bot",
		"from":      "user",
	})

	// Second webhook for same recipient is a no-op
	rec := doRequest(h, "POST", "/webhooks/sharkfin", map[string]any{
		"event":     "message.new",
		"recipient": "idempotent-bot",
		"from":      "user",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
