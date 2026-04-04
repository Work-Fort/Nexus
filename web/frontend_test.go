// SPDX-License-Identifier: GPL-3.0-or-later
package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Work-Fort/Scope/go/frontend"
)

func TestFrontendHandler_Health(t *testing.T) {
	// Create a temp dir with a dummy remoteEntry.js.
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "remoteEntry.js"), []byte("// stub"), 0644); err != nil {
		t.Fatal(err)
	}

	manifest := frontend.Manifest{
		Name:    "nexus",
		Label:   "Nexus",
		Route:   "/nexus",
		WSPaths: []string{"/v1/vms/{id}/console"},
	}

	h := frontend.Handler(os.DirFS(tmpDir), manifest)

	req := httptest.NewRequest(http.MethodGet, "/ui/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Name != "nexus" {
		t.Fatalf("expected name=nexus, got %q", body.Name)
	}
}
