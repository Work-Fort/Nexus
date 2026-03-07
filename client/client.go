// SPDX-License-Identifier: GPL-3.0-or-later
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a typed HTTP client for the Nexus daemon API.
type Client struct {
	base string
	http *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom *http.Client for the Nexus client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.http = hc }
}

// New creates a new Nexus API client. addr is the daemon address,
// e.g. "http://localhost:9600".
func New(addr string, opts ...Option) *Client {
	c := &Client{
		base: addr,
		http: &http.Client{Timeout: 60 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// BaseURL returns the base URL of the Nexus daemon (e.g. "http://localhost:9600").
func (c *Client) BaseURL() string { return c.base }

// HTTPClient returns the underlying *http.Client used by this client.
func (c *Client) HTTPClient() *http.Client { return c.http }

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *Client) post(ctx context.Context, path string, body any) (*http.Response, error) {
	return c.doJSON(ctx, http.MethodPost, path, body)
}

func (c *Client) postExpectStatus(ctx context.Context, path string, body any, status int) error {
	resp, err := c.post(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return handleResponse(resp, status)
}

func (c *Client) put(ctx context.Context, path string, body any) (*http.Response, error) {
	return c.doJSON(ctx, http.MethodPut, path, body)
}

func (c *Client) patch(ctx context.Context, path string, body any) (*http.Response, error) {
	return c.doJSON(ctx, http.MethodPatch, path, body)
}

func (c *Client) del(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		r = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// handleResponse checks that resp has the expected status code. For non-matching
// status codes it attempts to parse the JSON error body and wraps the
// appropriate sentinel error.
func handleResponse(resp *http.Response, expected int) error {
	if resp.StatusCode == expected {
		return nil
	}
	var apiErr APIError
	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
		return &APIError{
			StatusCode: resp.StatusCode,
			Title:      fmt.Sprintf("unexpected status %d", resp.StatusCode),
		}
	}
	apiErr.StatusCode = resp.StatusCode
	apiErr.wrapped = mapStatusError(resp.StatusCode)
	return &apiErr
}

// decodeJSON decodes a JSON response body into the given type.
func decodeJSON[T any](resp *http.Response) (*T, error) {
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &v, nil
}
