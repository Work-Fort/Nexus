// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/gorilla/websocket"

	"github.com/Work-Fort/Nexus/internal/app"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type resizeMsg struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

func handleConsole(svc *app.VMService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		// Parse optional query params.
		var cmd []string
		if q := r.URL.Query().Get("cmd"); q != "" {
			cmd = []string{q}
		}
		cols := uint16(80)
		rows := uint16(24)
		if c, err := strconv.ParseUint(r.URL.Query().Get("cols"), 10, 16); err == nil && c > 0 {
			cols = uint16(c)
		}
		if ro, err := strconv.ParseUint(r.URL.Query().Get("rows"), 10, 16); err == nil && ro > 0 {
			rows = uint16(ro)
		}

		// Validate VM before upgrading — allows returning proper HTTP errors.
		sess, err := svc.ExecConsoleVM(r.Context(), id, cmd, cols, rows)
		if err != nil {
			log.Error("console exec", "vm", id, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer sess.Close()

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Error("websocket upgrade", "err", err)
			return
		}
		defer ws.Close()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		var wsMu sync.Mutex // protects ws.WriteMessage (gorilla requires serialized writes)

		// Goroutine: read from PTY stdout → write to WebSocket.
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := sess.Stdout.Read(buf)
				if err != nil {
					cancel()
					return
				}
				wsMu.Lock()
				werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n])
				wsMu.Unlock()
				if werr != nil {
					cancel()
					return
				}
			}
		}()

		// Goroutine: wait for process exit → send exit event, close WebSocket.
		go func() {
			exitCode, _ := sess.Wait()
			exitMsg, _ := json.Marshal(map[string]any{"type": "exit", "exit_code": exitCode})
			wsMu.Lock()
			ws.WriteMessage(websocket.TextMessage, exitMsg) //nolint:errcheck
			wsMu.Unlock()
			cancel()
		}()

		// Main loop: read from WebSocket → write to PTY stdin or resize.
		for {
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				return
			}

			if msgType == websocket.TextMessage {
				var msg resizeMsg
				if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 {
					sess.Resize(ctx, msg.Cols, msg.Rows) //nolint:errcheck
					continue
				}
			}

			// Everything else is stdin input.
			if _, err := sess.Stdin.Write(data); err != nil {
				return
			}
		}
	}
}
