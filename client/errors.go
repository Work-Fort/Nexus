// SPDX-License-Identifier: Apache-2.0

// Package client provides a typed Go HTTP client for the Nexus daemon API.
//
// The client defines its own response types that mirror the API's JSON shapes,
// keeping zero dependency on internal packages. All methods accept a
// context.Context and return structured errors with sentinel values for
// common HTTP status codes.
package client

import (
	"errors"
	"fmt"
)

// Sentinel errors mapped from HTTP status codes.
var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
	ErrBadRequest = errors.New("bad request")
)

// APIError represents an error response from the Nexus API.
type APIError struct {
	StatusCode int    `json:"status"`
	Title      string `json:"title"`
	Detail     string `json:"detail,omitempty"`
	wrapped    error
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%d: %s: %s", e.StatusCode, e.Title, e.Detail)
	}
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Title)
}

func (e *APIError) Unwrap() error { return e.wrapped }

// mapStatusError returns the sentinel error for common HTTP status codes.
func mapStatusError(statusCode int) error {
	switch statusCode {
	case 404:
		return ErrNotFound
	case 409:
		return ErrConflict
	case 400:
		return ErrBadRequest
	default:
		return nil
	}
}
