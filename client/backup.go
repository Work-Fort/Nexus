// SPDX-License-Identifier: Apache-2.0
package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// ImportResult holds the result of importing a VM backup.
type ImportResult struct {
	VM       VM       `json:"vm"`
	Warnings []string `json:"warnings,omitempty"`
}

// ExportVM streams a VM backup archive to the provided writer.
func (c *Client) ExportVM(ctx context.Context, ref string, includeDevices bool, w io.Writer) error {
	path := fmt.Sprintf("/v1/vms/%s/export?include_devices=%t", ref, includeDevices)
	resp, err := c.post(ctx, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return err
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// ImportVM imports a VM from a backup archive read from the provided reader.
func (c *Client) ImportVM(ctx context.Context, r io.Reader, strictDevices bool) (*ImportResult, error) {
	path := fmt.Sprintf("/v1/vms/import?strict_devices=%t", strictDevices)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/zstd")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	return decodeJSON[ImportResult](resp)
}
