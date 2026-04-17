# Nexus UI Requirements

## Purpose

Add a web frontend to Nexus as a Module Federation remote, served by the Nexus
daemon and loaded by Scope. The primary goal is enabling VM management and
terminal access through the browser, removing the need to switch between
terminal windows to manage and interact with VMs.

This is on the critical path to dogfooding — it unblocks bootstrapping Claude
Code in agent VMs through the web UI instead of manually SSHing from separate
terminals.

## Requirements

### VM List View

- Display all VMs with their current status (running, stopped, etc.)
- Show key details: name, ID, status, IP address, resource usage
- Support basic actions: start, stop, restart, delete
- Filterable/searchable as the VM count grows

### VM Detail View

- Show full VM configuration and status
- Display attached drives, devices, network info
- Show provisioned files and templates
- Access to start/stop/restart controls

### Terminal (xterm.js)

- Embedded terminal connecting to Nexus's existing WebSocket console endpoint
  (`GET /v1/vms/{id}/console?cols=N&rows=M`)
- Terminal resize support (send resize JSON frames on window/pane resize)
- Accessible from the VM list (click to connect) and VM detail view
- Handle connection lifecycle: connecting state, exit events, reconnection
- The existing WebSocket protocol is documented in `docs/terminal-access-design.md`

### Module Federation Integration

- Follow the Scope service frontend contract
  (see `scope/lead/docs/frontend/service-contract.md`)
- Follow the SolidJS getting started guide
  (see `scope/lead/docs/frontend/getting-started/solidjs.md`)
- Export `ServiceModule` with `default`, `manifest`, optional `SidebarContent`
- Use `frontend.Handler` from `github.com/Work-Fort/Scope/pkg/frontend` to
  serve the UI and expose `/ui/health` for Pylon discovery
- Declare `WSPaths` in the manifest for the console WebSocket endpoint so
  Scope's `connected` state tracks WebSocket connectivity
- Share `solid-js`, `@workfort/ui`, `@workfort/ui-solid`, `@workfort/auth`
  as singletons (import from shell, do not bundle)

### Go Backend Changes

- Add `frontend.Handler` to the Nexus daemon's HTTP server
- Embed the Vite build output via `//go:embed`
- Add the frontend manifest with `WSPaths` for the console endpoint
- This automatically provides `/ui/health` for Pylon service discovery

## Out of Scope (for now)

- VM creation wizard (use MCP or REST API for now)
- Drive/device management UI
- Template management UI
- Log streaming
- Resource monitoring graphs

These can be added incrementally as Module Federation remotes within the same
Nexus UI package.
