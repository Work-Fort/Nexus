// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/Work-Fort/Nexus/internal/app"
)

func handleSharkfinWebhook(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var wh app.SharkfinWebhook
		if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if err := svc.HandleWebhook(r.Context(), wh); err != nil {
			mapError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
