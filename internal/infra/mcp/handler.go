// SPDX-License-Identifier: GPL-3.0-or-later

// Package mcp implements a Model Context Protocol (MCP) adapter for Nexus.
// It exposes VMService operations as MCP tools over Streamable HTTP.
package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
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
	registerTemplateTools(s, svc)
	registerSnapshotTools(s, svc)

	return server.NewStreamableHTTPServer(s)
}

// jsonResult marshals v as JSON and returns it as a text tool result.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return mcp.NewToolResultErrorf("marshal: %v", err), nil
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
		mcp.WithString("image", mcp.Description("OCI image")),
		mcp.WithString("runtime", mcp.Description("Container runtime handler")),
		mcp.WithString("root_size", mcp.Description("Root filesystem size limit (e.g. 1G, 500M)")),
		mcp.WithString("restart_policy", mcp.Description("Restart policy (none, on-boot, always)")),
		mcp.WithString("restart_strategy", mcp.Description("Restart strategy (immediate, backoff, fixed)")),
		mcp.WithString("shell", mcp.Description("Default shell for console sessions")),
		mcp.WithBoolean("init", mcp.Description("Enable init injection")),
		mcp.WithString("template", mcp.Description("Template name/ID for init (auto-detect if omitted)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}

		params := domain.CreateVMParams{
			Name:            name,
			Image:           mcp.ParseString(req, "image", ""),
			Runtime:         mcp.ParseString(req, "runtime", ""),
			Shell:           mcp.ParseString(req, "shell", ""),
			RestartPolicy:   domain.RestartPolicy(mcp.ParseString(req, "restart_policy", "")),
			RestartStrategy: domain.RestartStrategy(mcp.ParseString(req, "restart_strategy", "")),
			Init:            mcp.ParseBoolean(req, "init", false),
			TemplateName:    mcp.ParseString(req, "template", ""),
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
			filter.Tags = []string{role}
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

// registerVMExecTools registers the vm_exec tool.
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

		var stdoutBuf, stderrBuf bytes.Buffer
		stdoutW := &notifyWriter{srv: s, ctx: ctx, method: "run_command.stdout", buf: &stdoutBuf}
		stderrW := &notifyWriter{srv: s, ctx: ctx, method: "run_command.stderr", buf: &stderrBuf}
		exitCode, err := svc.ExecStreamVM(ctx, id, cmd, stdoutW, stderrW)
		if err != nil {
			return errResult(err)
		}

		return jsonResult(map[string]any{
			"exit_code": exitCode,
			"stdout":    stdoutBuf.String(),
			"stderr":    stderrBuf.String(),
		})
	})
}

// registerVMManagementTools registers vm_patch and vm_restart_policy tools.
func registerVMManagementTools(s *server.MCPServer, svc *app.VMService) {
	// vm_patch — expand root size
	s.AddTool(mcp.NewTool("vm_patch",
		mcp.WithDescription("Expand the root filesystem size of a VM"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("root_size", mcp.Description("New root size (e.g. 2G) — must be larger than current"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		sizeStr, errRes := requireString(req, "root_size")
		if errRes != nil {
			return errRes, nil
		}

		newSize, err := parseByteSize(sizeStr)
		if err != nil {
			return errResult(err)
		}

		if err := svc.ExpandRootSize(ctx, id, newSize); err != nil {
			return errResult(err)
		}

		vm, err := svc.GetVM(ctx, id)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(vm)
	})

	// vm_restart_policy
	s.AddTool(mcp.NewTool("vm_restart_policy",
		mcp.WithDescription("Update the restart policy and strategy for a VM"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("restart_policy", mcp.Description("Restart policy (none, on-boot, always)"), mcp.Required()),
		mcp.WithString("restart_strategy", mcp.Description("Restart strategy (immediate, backoff, fixed)"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		policy, errRes := requireString(req, "restart_policy")
		if errRes != nil {
			return errRes, nil
		}
		strategy, errRes := requireString(req, "restart_strategy")
		if errRes != nil {
			return errRes, nil
		}

		vm, err := svc.UpdateRestartPolicy(ctx, id,
			domain.RestartPolicy(policy),
			domain.RestartStrategy(strategy))
		if err != nil {
			return errResult(err)
		}
		return jsonResult(vm)
	})

	// vm_sync_shell
	s.AddTool(mcp.NewTool("vm_sync_shell",
		mcp.WithDescription("Detect and sync the root user's default shell from a running VM"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		vm, err := svc.SyncShell(ctx, id)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(vm)
	})
}

// registerBackupTools registers vm_export and vm_import tools.
func registerBackupTools(s *server.MCPServer, svc *app.VMService) {
	// vm_export
	s.AddTool(mcp.NewTool("vm_export",
		mcp.WithDescription("Export a stopped VM as a base64-encoded tar.zst archive"),
		mcp.WithString("id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithBoolean("include_devices", mcp.Description("Include device mappings in export")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		includeDevices := mcp.ParseBoolean(req, "include_devices", false)

		var buf bytes.Buffer
		if err := svc.ExportVM(ctx, id, includeDevices, &buf); err != nil {
			return errResult(err)
		}

		encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
		return jsonResult(map[string]any{
			"archive_base64": encoded,
			"size_bytes":     buf.Len(),
		})
	})

	// vm_import
	s.AddTool(mcp.NewTool("vm_import",
		mcp.WithDescription("Import a VM from a base64-encoded tar.zst archive"),
		mcp.WithString("archive_base64", mcp.Description("Base64-encoded archive data"), mcp.Required()),
		mcp.WithBoolean("strict_devices", mcp.Description("Fail if device mappings cannot be restored")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		archiveStr, errRes := requireString(req, "archive_base64")
		if errRes != nil {
			return errRes, nil
		}
		strictDevices := mcp.ParseBoolean(req, "strict_devices", false)

		data, err := base64.StdEncoding.DecodeString(archiveStr)
		if err != nil {
			return errResult(fmt.Errorf("invalid base64: %w", err))
		}

		result, err := svc.ImportVM(ctx, bytes.NewReader(data), strictDevices)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(result)
	})
}

// registerDriveTools registers drive_create, drive_list, drive_get,
// drive_delete, drive_attach, and drive_detach tools.
func registerDriveTools(s *server.MCPServer, svc *app.VMService) {
	// drive_create
	s.AddTool(mcp.NewTool("drive_create",
		mcp.WithDescription("Create a new persistent data drive"),
		mcp.WithString("name", mcp.Description("Drive name"), mcp.Required()),
		mcp.WithString("size", mcp.Description("Size (e.g. 1G, 500Mi)"), mcp.Required()),
		mcp.WithString("mount_path", mcp.Description("Mount path inside VM (e.g. /data)"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}
		size, errRes := requireString(req, "size")
		if errRes != nil {
			return errRes, nil
		}
		mountPath, errRes := requireString(req, "mount_path")
		if errRes != nil {
			return errRes, nil
		}

		drive, err := svc.CreateDrive(ctx, domain.CreateDriveParams{
			Name:      name,
			Size:      size,
			MountPath: mountPath,
		})
		if err != nil {
			return errResult(err)
		}
		return jsonResult(drive)
	})

	// drive_list
	s.AddTool(mcp.NewTool("drive_list",
		mcp.WithDescription("List all drives"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		drives, err := svc.ListDrives(ctx)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(drives)
	})

	// drive_get
	s.AddTool(mcp.NewTool("drive_get",
		mcp.WithDescription("Get a drive by ID or name"),
		mcp.WithString("id", mcp.Description("Drive ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		drive, err := svc.GetDrive(ctx, id)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(drive)
	})

	// drive_delete
	s.AddTool(mcp.NewTool("drive_delete",
		mcp.WithDescription("Delete a drive (must be detached)"),
		mcp.WithString("id", mcp.Description("Drive ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.DeleteDrive(ctx, id); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("deleted"), nil
	})

	// drive_attach
	s.AddTool(mcp.NewTool("drive_attach",
		mcp.WithDescription("Attach a drive to a stopped VM"),
		mcp.WithString("id", mcp.Description("Drive ID or name"), mcp.Required()),
		mcp.WithString("vm_id", mcp.Description("VM ID or name to attach to"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		vmID, errRes := requireString(req, "vm_id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.AttachDrive(ctx, id, vmID); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("attached"), nil
	})

	// drive_detach
	s.AddTool(mcp.NewTool("drive_detach",
		mcp.WithDescription("Detach a drive from its VM"),
		mcp.WithString("id", mcp.Description("Drive ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.DetachDrive(ctx, id); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("detached"), nil
	})
}

// registerDeviceTools registers device_create, device_list, device_get,
// device_delete, device_attach, and device_detach tools.
func registerDeviceTools(s *server.MCPServer, svc *app.VMService) {
	// device_create
	s.AddTool(mcp.NewTool("device_create",
		mcp.WithDescription("Register a new host device mapping"),
		mcp.WithString("name", mcp.Description("Device mapping name"), mcp.Required()),
		mcp.WithString("host_path", mcp.Description("Host device path (e.g. /dev/dri/renderD128)"), mcp.Required()),
		mcp.WithString("container_path", mcp.Description("Path inside the container"), mcp.Required()),
		mcp.WithString("permissions", mcp.Description("Device permissions: combination of r, w, m"), mcp.Required()),
		mcp.WithNumber("gid", mcp.Description("GID for device node inside container (0 = root)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}
		hostPath, errRes := requireString(req, "host_path")
		if errRes != nil {
			return errRes, nil
		}
		containerPath, errRes := requireString(req, "container_path")
		if errRes != nil {
			return errRes, nil
		}
		permissions, errRes := requireString(req, "permissions")
		if errRes != nil {
			return errRes, nil
		}

		gid := mcp.ParseUInt32(req, "gid", 0)

		device, err := svc.CreateDevice(ctx, domain.CreateDeviceParams{
			Name:          name,
			HostPath:      hostPath,
			ContainerPath: containerPath,
			Permissions:   permissions,
			GID:           gid,
		})
		if err != nil {
			return errResult(err)
		}
		return jsonResult(device)
	})

	// device_list
	s.AddTool(mcp.NewTool("device_list",
		mcp.WithDescription("List all registered devices"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		devices, err := svc.ListDevices(ctx)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(devices)
	})

	// device_get
	s.AddTool(mcp.NewTool("device_get",
		mcp.WithDescription("Get a device by ID or name"),
		mcp.WithString("id", mcp.Description("Device ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		device, err := svc.GetDevice(ctx, id)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(device)
	})

	// device_delete
	s.AddTool(mcp.NewTool("device_delete",
		mcp.WithDescription("Delete a device (must be detached)"),
		mcp.WithString("id", mcp.Description("Device ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.DeleteDevice(ctx, id); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("deleted"), nil
	})

	// device_attach
	s.AddTool(mcp.NewTool("device_attach",
		mcp.WithDescription("Attach a device to a stopped VM"),
		mcp.WithString("id", mcp.Description("Device ID or name"), mcp.Required()),
		mcp.WithString("vm_id", mcp.Description("VM ID or name to attach to"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		vmID, errRes := requireString(req, "vm_id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.AttachDevice(ctx, id, vmID); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("attached"), nil
	})

	// device_detach
	s.AddTool(mcp.NewTool("device_detach",
		mcp.WithDescription("Detach a device from its VM"),
		mcp.WithString("id", mcp.Description("Device ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.DetachDevice(ctx, id); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("detached"), nil
	})
}

// registerTemplateTools registers template_create, template_list, template_get,
// template_update, and template_delete tools.
func registerTemplateTools(s *server.MCPServer, svc *app.VMService) {
	// template_create
	s.AddTool(mcp.NewTool("template_create",
		mcp.WithDescription("Create a provisioning template"),
		mcp.WithString("name", mcp.Description("Template name"), mcp.Required()),
		mcp.WithString("distro", mcp.Description("Distro identifier (matches /etc/os-release ID)"), mcp.Required()),
		mcp.WithString("script", mcp.Description("Provisioning script content"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}
		distro, errRes := requireString(req, "distro")
		if errRes != nil {
			return errRes, nil
		}
		script, errRes := requireString(req, "script")
		if errRes != nil {
			return errRes, nil
		}

		tmpl, err := svc.CreateTemplate(ctx, domain.CreateTemplateParams{
			Name:   name,
			Distro: distro,
			Script: script,
		})
		if err != nil {
			return errResult(err)
		}
		return jsonResult(tmpl)
	})

	// template_list
	s.AddTool(mcp.NewTool("template_list",
		mcp.WithDescription("List all templates"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		templates, err := svc.ListTemplates(ctx)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(templates)
	})

	// template_get
	s.AddTool(mcp.NewTool("template_get",
		mcp.WithDescription("Get template by ID or name"),
		mcp.WithString("ref", mcp.Description("Template ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ref, errRes := requireString(req, "ref")
		if errRes != nil {
			return errRes, nil
		}
		tmpl, err := svc.GetTemplate(ctx, ref)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(tmpl)
	})

	// template_update
	s.AddTool(mcp.NewTool("template_update",
		mcp.WithDescription("Update a template"),
		mcp.WithString("ref", mcp.Description("Template ID or name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("New template name")),
		mcp.WithString("distro", mcp.Description("New distro identifier")),
		mcp.WithString("script", mcp.Description("New provisioning script content")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ref, errRes := requireString(req, "ref")
		if errRes != nil {
			return errRes, nil
		}

		params := domain.CreateTemplateParams{
			Name:   mcp.ParseString(req, "name", ""),
			Distro: mcp.ParseString(req, "distro", ""),
			Script: mcp.ParseString(req, "script", ""),
		}

		tmpl, err := svc.UpdateTemplate(ctx, ref, params)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(tmpl)
	})

	// template_delete
	s.AddTool(mcp.NewTool("template_delete",
		mcp.WithDescription("Delete a template"),
		mcp.WithString("ref", mcp.Description("Template ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ref, errRes := requireString(req, "ref")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.DeleteTemplate(ctx, ref); err != nil {
			return errResult(err)
		}
		return mcp.NewToolResultText("deleted"), nil
	})
}

// parseByteSize parses a human-readable byte size string into int64.
func parseByteSize(s string) (int64, error) {
	n, err := bytesize.Parse(s)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func registerSnapshotTools(s *server.MCPServer, svc *app.VMService) {
	s.AddTool(mcp.NewTool("snapshot_create",
		mcp.WithDescription("Create a point-in-time snapshot of a VM"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("Snapshot name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef, errRes := requireString(req, "vm_id")
		if errRes != nil {
			return errRes, nil
		}
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}
		snap, err := svc.CreateSnapshot(ctx, vmRef, name)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(snap)
	})

	s.AddTool(mcp.NewTool("snapshot_list",
		mcp.WithDescription("List snapshots for a VM"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef, errRes := requireString(req, "vm_id")
		if errRes != nil {
			return errRes, nil
		}
		snaps, err := svc.ListSnapshots(ctx, vmRef)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(snaps)
	})

	s.AddTool(mcp.NewTool("snapshot_delete",
		mcp.WithDescription("Delete a VM snapshot"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("Snapshot ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef, errRes := requireString(req, "vm_id")
		if errRes != nil {
			return errRes, nil
		}
		snapRef, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.DeleteSnapshot(ctx, vmRef, snapRef); err != nil {
			return errResult(err)
		}
		return jsonResult(map[string]string{"status": "deleted"})
	})

	s.AddTool(mcp.NewTool("snapshot_restore",
		mcp.WithDescription("Restore a stopped VM to a previous snapshot"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("Snapshot ID or name"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef, errRes := requireString(req, "vm_id")
		if errRes != nil {
			return errRes, nil
		}
		snapRef, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		if err := svc.RestoreSnapshot(ctx, vmRef, snapRef); err != nil {
			return errResult(err)
		}
		return jsonResult(map[string]string{"status": "restored"})
	})

	s.AddTool(mcp.NewTool("snapshot_clone",
		mcp.WithDescription("Clone a VM from a snapshot"),
		mcp.WithString("vm_id", mcp.Description("VM ID or name"), mcp.Required()),
		mcp.WithString("id", mcp.Description("Snapshot ID or name"), mcp.Required()),
		mcp.WithString("name", mcp.Description("Name for the new VM"), mcp.Required()),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vmRef, errRes := requireString(req, "vm_id")
		if errRes != nil {
			return errRes, nil
		}
		snapRef, errRes := requireString(req, "id")
		if errRes != nil {
			return errRes, nil
		}
		name, errRes := requireString(req, "name")
		if errRes != nil {
			return errRes, nil
		}
		vm, err := svc.CloneSnapshot(ctx, vmRef, snapRef, name)
		if err != nil {
			return errResult(err)
		}
		return jsonResult(vm)
	})
}
