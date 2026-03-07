// SPDX-License-Identifier: GPL-3.0-or-later
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Template represents a provisioning template returned by the API.
type Template struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Distro    string `json:"distro"`
	Script    string `json:"script"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// CreateTemplateParams holds parameters for creating a template.
type CreateTemplateParams struct {
	Name   string `json:"name"`
	Distro string `json:"distro"`
	Script string `json:"script"`
}

// UpdateTemplateParams holds parameters for updating a template.
type UpdateTemplateParams struct {
	Name   string `json:"name,omitempty"`
	Distro string `json:"distro,omitempty"`
	Script string `json:"script,omitempty"`
}

// CreateTemplate creates a new provisioning template.
func (c *Client) CreateTemplate(ctx context.Context, params CreateTemplateParams) (*Template, error) {
	resp, err := c.post(ctx, "/v1/templates", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	return decodeJSON[Template](resp)
}

// ListTemplates returns all provisioning templates.
func (c *Client) ListTemplates(ctx context.Context) ([]Template, error) {
	resp, err := c.get(ctx, "/v1/templates")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var templates []Template
	if err := json.NewDecoder(resp.Body).Decode(&templates); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return templates, nil
}

// GetTemplate retrieves a single template by ID or name.
func (c *Client) GetTemplate(ctx context.Context, ref string) (*Template, error) {
	resp, err := c.get(ctx, "/v1/templates/"+url.PathEscape(ref))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[Template](resp)
}

// UpdateTemplate updates a template by ID or name.
func (c *Client) UpdateTemplate(ctx context.Context, ref string, params UpdateTemplateParams) (*Template, error) {
	resp, err := c.put(ctx, "/v1/templates/"+url.PathEscape(ref), params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[Template](resp)
}

// DeleteTemplate deletes a template by ID or name.
func (c *Client) DeleteTemplate(ctx context.Context, ref string) error {
	resp, err := c.del(ctx, "/v1/templates/"+url.PathEscape(ref))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return handleResponse(resp, http.StatusNoContent)
}
