// SPDX-License-Identifier: Apache-2.0
package domain

import (
	"context"
	"io"
)

// ConsoleSession represents an interactive TTY session inside a VM.
type ConsoleSession struct {
	Stdin  io.WriteCloser
	Stdout io.Reader
	Wait   func() (int, error)
	Resize func(ctx context.Context, w, h uint32) error
	Close  func()
}
