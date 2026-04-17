# Nexus UI Design

Web frontend for Nexus, served as a Module Federation remote by the Nexus
daemon and loaded by Scope. Enables VM management and terminal access through
the browser.

## Project Structure

```
web/
├── embed.go              # !ui build tag — empty Dist
├── embed_ui.go           # ui build tag — //go:embed all:dist
├── package.json          # npm (no pnpm — single module, no workspace)
├── vite.config.ts        # MF remote config
├── tsconfig.json
├── src/
│   ├── index.ts           # MF entry: mount/unmount/manifest
│   ├── App.vue            # Router: list → detail (tabbed)
│   ├── components/
│   │   ├── VMList.vue     # VM list with search and refresh rate
│   │   ├── VMDetail.vue   # Tabbed detail view (Overview | Terminal)
│   │   ├── VMOverview.vue # Config, drives, devices, network
│   │   └── Terminal.vue   # xterm.js WebSocket terminal
│   └── lib/
│       ├── api.ts         # REST client (fetch, talks to /v1/*)
│       └── console.ts     # WebSocket client for terminal
└── dist/                  # Vite output (gitignored)
```

## Module Federation

Vue-based MF remote. Vue is bundled by the remote, not shared.

**`vite.config.ts`:**
- `name: 'nexus'`
- `filename: 'remoteEntry.js'`
- Exposes `'./index': './src/index.ts'`
- Shared singletons with `import: false`: `@workfort/ui`, `@workfort/auth`
- Vue compiler configured with `isCustomElement: tag => tag.startsWith('wf-')`

**`src/index.ts`** exports:
- `mount(el, props)` — calls `createApp()`, mounts Vue app into the element
- `unmount(el)` — calls `app.unmount()` to tear down the Vue tree
- `manifest` — `{ name: 'nexus', label: 'Nexus', route: '/nexus', display: 'menu' }`

No `mountSidebar`/`unmountSidebar`. No `HeaderActions`. Nexus appears in the
sidebar hamburger menu as a single link.

## Routing & Views

Three views via Vue Router (bundled, not shared):

### `/nexus` — VM List

- Fetches `GET /v1/vms` on mount
- Each VM rendered as a card/row: name, status indicator, IP address
- Text search input filters by VM name
- Refresh rate dropdown beside search: 2s, 5s (default), 10s, 30s
  - Polls `GET /v1/vms` at the selected interval via `setInterval`
  - In-memory state only — resets to default on navigate away (no
    localStorage; Scope shares origin across forts)
- Inline actions: start, stop, restart, delete
- Click a VM → navigates to `/nexus/vms/:id`

### `/nexus/vms/:id` — VM Detail (tabbed)

Two tabs: **Overview** | **Terminal**

Tab state is part of the route (`/nexus/vms/:id/terminal`) so tabs are
linkable. Back button returns to the VM list.

**Overview tab:**
- VM configuration and status
- Attached drives, devices, network info
- Provisioned template
- Start/stop/restart controls

**Terminal tab:**
- Full-height xterm.js terminal
- Connects WebSocket on tab activation
- Disconnects on tab deactivation or navigate away

## Terminal

**Dependencies:** `xterm`, `@xterm/addon-fit`, `@xterm/addon-web-links`

**Lifecycle:**
1. Tab activates → create `Terminal` instance, attach to DOM, call `fit()`
2. Derive WebSocket URL from page location:
   - Through BFF: `ws://{host}/forts/{fort}/api/nexus/v1/vms/{id}/console?cols=N&rows=M`
   - Direct: `ws://{host}/v1/vms/{id}/console?cols=N&rows=M`
3. Connect WebSocket, pipe:
   - `terminal.onData` → text frames (stdin)
   - Binary frames → `terminal.write()` (stdout)
4. `addon-fit` on container resize → send `{"type":"resize","cols":N,"rows":N}`
5. Receive `{"type":"exit","exit_code":N}` → display exit status, close WebSocket
6. Tab deactivates or navigate away → close WebSocket → process dies server-side

One-shot sessions — no reconnection logic. Process dies when the connection
closes (existing server-side design, no scrollback buffer). A "Reconnect"
button starts a fresh session.

## REST API Client

Thin fetch wrapper in `src/lib/api.ts`. No external HTTP library.

**Base URL derivation** (same pattern as Sharkfin):
- Through BFF: `/forts/{fort}/api/nexus/v1/...` (parsed from `location.pathname`)
- Direct: `/v1/...`

**Methods:**
- `listVMs(tag?, tagMatch?)` → `GET /v1/vms`
- `getVM(id)` → `GET /v1/vms/{id}`
- `startVM(id)` → `POST /v1/vms/{id}/start`
- `stopVM(id)` → `POST /v1/vms/{id}/stop`
- `restartVM(id)` → `POST /v1/vms/{id}/restart`
- `deleteVM(id)` → `DELETE /v1/vms/{id}`

No create endpoint — out of scope. No state management library — Vue's
`ref`/`reactive` is sufficient.

## Go Backend Changes

Three files:

**`web/embed.go`** (new):
```go
//go:build !ui
package web

import "embed"

var Dist embed.FS
```

**`web/embed_ui.go`** (new):
```go
//go:build ui
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
```

**`cmd/daemon.go`** (modified):
- Import `github.com/Work-Fort/Scope/pkg/frontend` and the `web` package
- Mount the frontend handler after existing mux setup:
  ```go
  distFS, _ := fs.Sub(web.Dist, "dist")
  uiHandler := frontend.Handler(distFS, frontend.Manifest{
      Name:    "nexus",
      Label:   "Nexus",
      Route:   "/nexus",
      WSPaths: []string{"/v1/vms/{id}/console"},
  })
  mux.Handle("/ui/", uiHandler)
  ```
- Add `--ui-dir` flag for dev mode (serve from disk instead of embed)

`frontend.Handler` handles `/ui/health`, cache headers, and static file
serving automatically.

## Build

Follows Sharkfin's build tag pattern:

- **Dev:** `go build` (no `-tags ui`) → empty `Dist`, use `--ui-dir` to serve
  from disk while running `npm run dev` in `web/`
- **Production:** `cd web && npm run build` then `go build -tags ui` → single
  binary with embedded frontend

No explicit mise task chaining — the Go build assumes `web/dist/` exists when
built with `-tags ui`.

## Out of Scope

- VM creation wizard
- Drive/device management UI
- Template management UI
- Log streaming
- Resource monitoring graphs
- Server-side terminal session persistence
