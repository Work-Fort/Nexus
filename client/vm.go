// SPDX-License-Identifier: Apache-2.0
package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DNSConfig holds per-VM DNS resolution settings.
type DNSConfig struct {
	Servers []string `json:"servers,omitempty"`
	Search  []string `json:"search,omitempty"`
}

// VM represents a virtual machine returned by the API.
type VM struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Role            string     `json:"role"`
	State           string     `json:"state"`
	Image           string     `json:"image"`
	Runtime         string     `json:"runtime"`
	IP              string     `json:"ip,omitempty"`
	Gateway         string     `json:"gateway,omitempty"`
	DNS             *DNSConfig `json:"dns,omitempty"`
	RootSize        *string    `json:"root_size,omitempty"`
	RestartPolicy   string     `json:"restart_policy"`
	RestartStrategy string     `json:"restart_strategy"`
	Shell           string     `json:"shell,omitempty"`
	CreatedAt       string     `json:"created_at"`
	StartedAt       *string    `json:"started_at,omitempty"`
	StoppedAt       *string    `json:"stopped_at,omitempty"`
}

// CreateVMParams holds parameters for creating a VM.
type CreateVMParams struct {
	Name            string     `json:"name"`
	Role            string     `json:"role"`
	Image           string     `json:"image,omitempty"`
	Runtime         string     `json:"runtime,omitempty"`
	DNS             *DNSConfig `json:"dns,omitempty"`
	RootSize        string     `json:"root_size,omitempty"`
	RestartPolicy   string     `json:"restart_policy,omitempty"`
	RestartStrategy string     `json:"restart_strategy,omitempty"`
	Shell           string     `json:"shell,omitempty"`
}

// ExecResult holds command output from a VM.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// ListVMsFilter constrains VM listing.
type ListVMsFilter struct {
	Role string
}

// CreateVM creates a new virtual machine.
func (c *Client) CreateVM(ctx context.Context, params CreateVMParams) (*VM, error) {
	resp, err := c.post(ctx, "/v1/vms", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusCreated); err != nil {
		return nil, err
	}
	return decodeJSON[VM](resp)
}

// ListVMs returns all VMs, optionally filtered by role.
func (c *Client) ListVMs(ctx context.Context, filter ListVMsFilter) ([]VM, error) {
	path := "/v1/vms"
	if filter.Role != "" {
		path += "?role=" + filter.Role
	}
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var vms []VM
	if err := json.NewDecoder(resp.Body).Decode(&vms); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return vms, nil
}

// GetVM retrieves a single VM by ID or name.
func (c *Client) GetVM(ctx context.Context, ref string) (*VM, error) {
	resp, err := c.get(ctx, "/v1/vms/"+ref)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[VM](resp)
}

// DeleteVM deletes a VM by ID or name.
func (c *Client) DeleteVM(ctx context.Context, ref string) error {
	resp, err := c.del(ctx, "/v1/vms/"+ref)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return handleResponse(resp, http.StatusNoContent)
}

// StartVM starts a stopped or created VM.
func (c *Client) StartVM(ctx context.Context, ref string) error {
	return c.postExpectStatus(ctx, "/v1/vms/"+ref+"/start", nil, http.StatusNoContent)
}

// StopVM stops a running VM.
func (c *Client) StopVM(ctx context.Context, ref string) error {
	return c.postExpectStatus(ctx, "/v1/vms/"+ref+"/stop", nil, http.StatusNoContent)
}

// ExecVM executes a command in a VM and returns the buffered result.
func (c *Client) ExecVM(ctx context.Context, ref string, cmd []string) (*ExecResult, error) {
	resp, err := c.post(ctx, "/v1/vms/"+ref+"/exec", map[string]any{"cmd": cmd})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[ExecResult](resp)
}

// ExecStreamVM executes a command in a VM and streams stdout/stderr via SSE.
// It returns the process exit code. stdout and stderr writers receive the
// respective output chunks as they arrive.
func (c *Client) ExecStreamVM(ctx context.Context, ref string, cmd []string, stdout, stderr io.Writer) (int, error) {
	resp, err := c.post(ctx, "/v1/vms/"+ref+"/exec/stream", map[string]any{"cmd": cmd})
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return -1, err
	}

	// Parse SSE stream. Events have the format:
	//   event: <type>
	//   data: <json>
	//   <blank line>
	scanner := bufio.NewScanner(resp.Body)
	var eventType string
	exitCode := -1

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			switch eventType {
			case "stdout":
				var v struct {
					Data string `json:"data"`
				}
				if err := json.Unmarshal([]byte(data), &v); err == nil {
					fmt.Fprint(stdout, v.Data)
				}
			case "stderr":
				var v struct {
					Data string `json:"data"`
				}
				if err := json.Unmarshal([]byte(data), &v); err == nil {
					fmt.Fprint(stderr, v.Data)
				}
			case "exit":
				var v struct {
					ExitCode int `json:"exit_code"`
				}
				if err := json.Unmarshal([]byte(data), &v); err == nil {
					exitCode = v.ExitCode
				}
			}
			eventType = ""
		}
	}
	if err := scanner.Err(); err != nil {
		return exitCode, fmt.Errorf("reading SSE stream: %w", err)
	}
	return exitCode, nil
}

// UpdateShell updates the default shell for a VM.
func (c *Client) UpdateShell(ctx context.Context, ref string, shell string) (*VM, error) {
	resp, err := c.patch(ctx, "/v1/vms/"+ref, map[string]any{"shell": &shell})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[VM](resp)
}

// ExpandRootSize expands the root filesystem size of a VM.
// size is a human-readable size string like "2G" or "500M".
func (c *Client) ExpandRootSize(ctx context.Context, ref string, size string) (*VM, error) {
	resp, err := c.patch(ctx, "/v1/vms/"+ref, map[string]string{"root_size": size})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[VM](resp)
}

// UpdateRestartPolicy updates the restart policy and strategy for a VM.
func (c *Client) UpdateRestartPolicy(ctx context.Context, ref, policy, strategy string) (*VM, error) {
	resp, err := c.put(ctx, "/v1/vms/"+ref+"/restart-policy", map[string]string{
		"restart_policy":   policy,
		"restart_strategy": strategy,
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := handleResponse(resp, http.StatusOK); err != nil {
		return nil, err
	}
	return decodeJSON[VM](resp)
}
