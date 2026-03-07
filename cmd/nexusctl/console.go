// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newConsoleCmd() *cobra.Command {
	var (
		shell string
		cols  int
		rows  int
	)

	cmd := &cobra.Command{
		Use:   "console <vm>",
		Short: "Attach an interactive console to a VM",
		Long:  "Opens a raw terminal session to the VM over WebSocket. Escape with ~. (tilde-dot after newline).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConsole(args[0], shell, cols, rows)
		},
	}
	cmd.Flags().StringVar(&shell, "cmd", "", "Shell command to run (default: VM login shell)")
	cmd.Flags().IntVar(&cols, "cols", 0, "Terminal columns (default: current terminal)")
	cmd.Flags().IntVar(&rows, "rows", 0, "Terminal rows (default: current terminal)")
	return cmd
}

func runConsole(vmID, shell string, cols, rows int) error {
	// Detect terminal size if not specified.
	if cols == 0 || rows == 0 {
		w, h, err := term.GetSize(int(os.Stdin.Fd()))
		if err == nil {
			if cols == 0 {
				cols = w
			}
			if rows == 0 {
				rows = h
			}
		} else {
			if cols == 0 {
				cols = 80
			}
			if rows == 0 {
				rows = 24
			}
		}
	}

	// Build WebSocket URL from the HTTP base URL.
	base := apiClient.BaseURL()
	wsBase := strings.Replace(base, "https://", "wss://", 1)
	wsBase = strings.Replace(wsBase, "http://", "ws://", 1)

	q := url.Values{}
	q.Set("cols", strconv.Itoa(cols))
	q.Set("rows", strconv.Itoa(rows))
	if shell != "" {
		q.Set("cmd", shell)
	}
	wsURL := wsBase + "/v1/vms/" + url.PathEscape(vmID) + "/console?" + q.Encode()

	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer ws.Close()

	// Put terminal into raw mode.
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	defer term.Restore(fd, oldState) //nolint:errcheck

	var (
		wsMu     sync.Mutex
		exitCode int
		done     = make(chan struct{})
	)

	// Goroutine: WS → stdout.
	go func() {
		defer close(done)
		for {
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			switch msgType {
			case websocket.BinaryMessage:
				os.Stdout.Write(data) //nolint:errcheck
			case websocket.TextMessage:
				var evt struct {
					Type     string `json:"type"`
					ExitCode int    `json:"exit_code"`
				}
				if json.Unmarshal(data, &evt) == nil && evt.Type == "exit" {
					exitCode = evt.ExitCode
					return
				}
				// Other text messages: write to stdout as-is.
				os.Stdout.Write(data) //nolint:errcheck
			}
		}
	}()

	// Goroutine: SIGWINCH → WS resize frames.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			w, h, err := term.GetSize(fd)
			if err != nil {
				continue
			}
			msg, _ := json.Marshal(map[string]any{
				"type": "resize",
				"cols": w,
				"rows": h,
			})
			wsMu.Lock()
			ws.WriteMessage(websocket.TextMessage, msg) //nolint:errcheck
			wsMu.Unlock()
		}
	}()

	// Goroutine: stdin → WS with ~. escape detection.
	//
	// Escape states: after a newline (or session start), if the user types ~.
	// we disconnect. This works like SSH's escape sequence and handles the
	// cross-buffer case (~ at end of one read, . at start of next).
	go func() {
		const (
			escNone     = iota // normal
			escNewline         // last byte was \n or \r
			escTilde           // saw ~ immediately after newline
		)

		buf := make([]byte, 4096)
		state := escNewline // treat start of session as after newline
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				wsMu.Lock()
				ws.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")) //nolint:errcheck
				wsMu.Unlock()
				return
			}
			data := buf[:n]

			// Scan for escape sequence.
			escape := false
			for _, b := range data {
				switch state {
				case escNewline:
					if b == '~' {
						state = escTilde
					} else if b == '\n' || b == '\r' {
						state = escNewline
					} else {
						state = escNone
					}
				case escTilde:
					if b == '.' {
						escape = true
					} else if b == '\n' || b == '\r' {
						state = escNewline
					} else {
						state = escNone
					}
				default:
					if b == '\n' || b == '\r' {
						state = escNewline
					} else {
						state = escNone
					}
				}
				if escape {
					break
				}
			}

			if escape {
				fmt.Fprintf(os.Stderr, "\r\nConnection closed.\r\n")
				wsMu.Lock()
				ws.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")) //nolint:errcheck
				wsMu.Unlock()
				return
			}

			wsMu.Lock()
			werr := ws.WriteMessage(websocket.TextMessage, data)
			wsMu.Unlock()
			if werr != nil {
				return
			}
		}
	}()

	<-done

	// Restore terminal before exiting.
	signal.Stop(sigCh)
	close(sigCh) // unblock SIGWINCH goroutine
	term.Restore(fd, oldState) //nolint:errcheck

	// Always os.Exit to avoid leaking the stdin goroutine (os.Stdin.Read
	// is not interruptible). Exit code 0 is the success case.
	os.Exit(exitCode)
	return nil // unreachable, but keeps the compiler happy
}
