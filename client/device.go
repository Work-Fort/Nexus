// SPDX-License-Identifier: GPL-3.0-or-later
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Device represents a host device mapping.
type Device struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	HostPath      string  `json:"host_path"`
	ContainerPath string  `json:"container_path"`
	Permissions   string  `json:"permissions"`
	GID           uint32  `json:"gid"`
	VMID          *string `json:"vm_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

// CreateDeviceParams holds parameters for creating a device mapping.
type CreateDeviceParams struct {
	Name          string `json:"name"`
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Permissions   string `json:"permissions"`
	GID           uint32 `json:"gid,omitempty"`
}

// CreateDevice creates a new device mapping.
func (c *Client) CreateDevice(ctx context.Context, params CreateDeviceParams) (*Device, error) {
	resp, err := c.post(ctx, "/v1/devices", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	return decodeJSON[Device](resp)
}

// ListDevices returns all device mappings.
func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	resp, err := c.get(ctx, "/v1/devices")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var devices []Device
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return devices, nil
}

// GetDevice retrieves a single device mapping by ID or name.
func (c *Client) GetDevice(ctx context.Context, ref string) (*Device, error) {
	resp, err := c.get(ctx, "/v1/devices/"+url.PathEscape(ref))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[Device](resp)
}

// DeleteDevice deletes a device mapping by ID or name.
func (c *Client) DeleteDevice(ctx context.Context, ref string) error {
	resp, err := c.del(ctx, "/v1/devices/"+url.PathEscape(ref))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return handleResponse(resp, http.StatusNoContent)
}

// AttachDevice attaches a device to a VM.
func (c *Client) AttachDevice(ctx context.Context, deviceRef, vmRef string) error {
	return c.postExpectStatus(ctx, "/v1/devices/"+url.PathEscape(deviceRef)+"/attach",
		map[string]string{"vm_id": vmRef}, http.StatusOK)
}

// DetachDevice detaches a device from its VM.
func (c *Client) DetachDevice(ctx context.Context, ref string) error {
	return c.postExpectStatus(ctx, "/v1/devices/"+url.PathEscape(ref)+"/detach", nil, http.StatusOK)
}
