// SPDX-License-Identifier: Apache-2.0
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Drive represents a persistent data volume.
type Drive struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	SizeBytes uint64  `json:"size_bytes"`
	MountPath string  `json:"mount_path"`
	VMID      *string `json:"vm_id,omitempty"`
	CreatedAt string  `json:"created_at"`
}

// CreateDriveParams holds parameters for creating a drive.
type CreateDriveParams struct {
	Name      string `json:"name"`
	Size      string `json:"size"`
	MountPath string `json:"mount_path"`
}

// CreateDrive creates a new persistent data drive.
func (c *Client) CreateDrive(ctx context.Context, params CreateDriveParams) (*Drive, error) {
	resp, err := c.post(ctx, "/v1/drives", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	return decodeJSON[Drive](resp)
}

// ListDrives returns all drives.
func (c *Client) ListDrives(ctx context.Context) ([]Drive, error) {
	resp, err := c.get(ctx, "/v1/drives")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var drives []Drive
	if err := json.NewDecoder(resp.Body).Decode(&drives); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return drives, nil
}

// GetDrive retrieves a single drive by ID or name.
func (c *Client) GetDrive(ctx context.Context, ref string) (*Drive, error) {
	resp, err := c.get(ctx, "/v1/drives/"+url.PathEscape(ref))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[Drive](resp)
}

// DeleteDrive deletes a drive by ID or name.
func (c *Client) DeleteDrive(ctx context.Context, ref string) error {
	resp, err := c.del(ctx, "/v1/drives/"+url.PathEscape(ref))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return handleResponse(resp, http.StatusNoContent)
}

// AttachDrive attaches a drive to a VM.
func (c *Client) AttachDrive(ctx context.Context, driveRef, vmRef string) error {
	return c.postExpectStatus(ctx, "/v1/drives/"+url.PathEscape(driveRef)+"/attach",
		map[string]string{"vm_id": vmRef}, http.StatusOK)
}

// DetachDrive detaches a drive from its VM.
func (c *Client) DetachDrive(ctx context.Context, ref string) error {
	return c.postExpectStatus(ctx, "/v1/drives/"+url.PathEscape(ref)+"/detach", nil, http.StatusOK)
}
