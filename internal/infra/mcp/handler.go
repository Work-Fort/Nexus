// SPDX-License-Identifier: Apache-2.0

// Package mcp implements a Model Context Protocol (MCP) adapter for Nexus.
// It exposes VMService operations as MCP tools over Streamable HTTP.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/bytesize"
)

// NewHandler creates an http.Handler that serves the Nexus MCP endpoint.
func NewHandler(svc *app.VMService) http.Handler {
	s := server.NewMCPServer(
		"nexus",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	registerVMLifecycleTools(s, svc)
	registerVMExecTools(s, svc)
	registerVMManagementTools(s, svc)
	registerBackupTools(s, svc)
	registerDriveTools(s, svc)
	registerDeviceTools(s, svc)

	return server.NewStreamableHTTPServer(s)
}

// jsonResult marshals v as JSON and returns it as a text tool result.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(b)), nil
}

// errResult returns a tool-level error result.
func errResult(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(err.Error()), nil
}

// requireString extracts a required string argument from the request.
// Returns empty string and a tool error result if missing.
func requireString(req mcp.CallToolRequest, key string) (string, *mcp.CallToolResult) {
	v := mcp.ParseString(req, key, "")
	if v == "" {
		return "", mcp.NewToolResultErrorf("%s is required", key)
	}
	return v, nil
}

// registerVMLifecycleTools registers vm_create, vm_list, vm_get, vm_delete,
// vm_start, and vm_stop tools.
func registerVMLifecycleTools(s *server.MCPServer, svc *app.VMService) {
	// vm_create
	s.AddTool(mcp.NewTool("vm_create",
		mcp.WithDescription("Create a new VM"),
		mcp.WithString("name", mcp.Description("VM name"), mcp.Required()),
		mcp.WithString("role", mcp.Description("VM role (agent or service)"), mcp.Required()),
		mcp.WithString("image", mcp.Description("OCI image")),
		mcp.WithString("runtime", mcp.Description("Container runtime handler")),
		mcp.WithString("root_size", mcp.Description("Root filesystem size limit (e.g. 1G, 500M)")),
		mcp.WithString("restart_policy", mcp.Description("Restart policy (none, on-boot, always)")),
		mcp.WithString("restart_strategy", mcp.Description("Restart strategy (immediate, backoff, fixed)")),
		mcp.WithString("shell", mcp.Description("Default shell for console sessions")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}
		role, errRes := requireString(req, "role")
		if errRes != nil {
			return errRes, nil
		}

		params := domain.CreateVMParams{
			Name:            name,
			Role:            domain.VMRole(role),
			Image:           mcp.ParseString(req, "image", ""),
			Runtime:         mcp.ParseString(req, "runtime", ""),
			Shell:           mcp.ParseString(req, "shell", ""),
			RestartPolicy:   domain.RestartPolicy(mcp.ParseString(req, "restart_policy", "")),
			RestartStrategy: domain.RestartStrategy(mcp.ParseString(req, "restart_strategy", "")),
		}

		rootSizeStr := mcp.ParseString(req, "root_size", "")
		if rootSizeStr != "" {
			size, err := parseByteSize(rootSizeStr)
			if err != nil {
				return errResult(err)
			}
			params.RootSize = size
		}

		vm, err := svc.CreateVM(ctx, params)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(vm)
	})

	// vm_list
	s.AddTool(mcp.NewTool("vm_list",
		mcp.WithDescription("List VMs"),
		mcp.WithString("role", mcp.Description("Filter by VM role (agent or service)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filter := domain.VMFilter{}
		if role := mcp.ParseString(req, "role", ""); role != "" {
			r := domain.VMRole(role)
			filter.Role = &r
		}
		vms, err := svc.ListVMs(ctx, filter)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(vms)
	})

	// vm_get
	s.AddTool(mcp.NewTool("vm_get",
		mcp.WithDescription("Get a VM by ID or name"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		vm, err := svc.GetVM(ctx, id)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(vm)
	})

	// vm_delete
	s.AddTool(mcp.NewTool("vm_delete",
		mcp.WithDescription("Delete a VM"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.DeleteVM(ctx, id); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("deleted"), nil
	})

	// vm_start
	s.AddTool(mcp.NewTool("vm_start",
		mcp.WithDescription("Start a VM"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.StartVM(ctx, id); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("started"), nil
	})

	// vm_stop
	s.AddTool(mcp.NewTool("vm_stop",
		mcp.WithDescription("Stop a VM"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.StopVM(ctx, id); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("stopped"), nil
	})
}

// registerVMExecTools registers vm_exec and vm_exec_stream tools.
func registerVMExecTools(s *server.MCPServer, svc *app.VMService) {
	// vm_exec
	s.AddTool(mcp.NewTool("vm_exec",
		mcp.WithDescription("Execute a command in a running VM"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("cmd", mcp.Description("Command as JSON array (e.g. [\"ls\",\"-la\"])"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		cmdStr, errRes := requireString(req, "cmd")
		if errRes != nil {
			return errRes, nil
		}

		var cmd []string
		if err := json.Unmarshal([]byte(cmdStr), &cmd); err != nil {
			return errResult(fmt.Errorf("cmd must be a JSON array of strings: %w", err))
		}

		result, err := svc.ExecVM(ctx, id, cmd)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(result)
	})

	// vm_exec_stream
	s.AddTool(mcp.NewTool("vm_exec_stream",
		mcp.WithDescription("Execute a command in a running VM with streaming output"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("cmd", mcp.Description("Command as JSON array (e.g. [\"ls\",\"-la\"])"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		cmdStr, errRes := requireString(req, "cmd")
		if errRes != nil {
			return errRes, nil
		}

		var cmd []string
		if err := json.Unmarshal([]byte(cmdStr), &cmd); err != nil {
			return errResult(fmt.Errorf("cmd must be a JSON array of strings: %w", err))
		}

		var stdout, stderr bytes.Buffer
		exitCode, err := svc.ExecStreamVM(ctx, id, cmd, &stdout, &stderr)
		if err != nil {
			return errResult(err)
		}

		out := map[string]any{
			"exit_code": exitCode,
			"stdout":    stdout.String(),
			"stderr":    stderr.String(),
		}
		return jsonResult(out)
	})
}

// registerVMManagementTools registers vm_patch and vm_restart_policy tools.
func registerVMManagementTools(_ *server.MCPServer, _ *app.VMService) {}

// registerBackupTools registers vm_export and vm_import tools.
func registerBackupTools(_ *server.MCPServer, _ *app.VMService) {}

// registerDriveTools registers drive_create, drive_list, drive_get,
// drive_delete, drive_attach, and drive_detach tools.
func registerDriveTools(_ *server.MCPServer, _ *app.VMService) {}

// registerDeviceTools registers device_create, device_list, device_get,
// device_delete, device_attach, and device_detach tools.
func registerDeviceTools(_ *server.MCPServer, _ *app.VMService) {}

// parseByteSize parses a human-readable byte size string into int64.
func parseByteSize(s string) (int64, error) {
	n, err := bytesize.Parse(s)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}
