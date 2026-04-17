# Nexus UI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a Vue-based web frontend to Nexus as a Module Federation remote, enabling VM management and terminal access through the browser.

**Architecture:** Vue 3 MF remote served by the Nexus daemon via `frontend.Handler` from `github.com/Work-Fort/Scope/go/frontend` (v0.1.0). Three views (VM list, VM detail with tabs, terminal) connected to the existing REST API and WebSocket console endpoint. Build tag pattern (`ui`/`!ui`) for optional frontend embedding. Uses `createMemoryHistory()` for routing since MF remotes don't own the URL bar.

**Tech Stack:** Vue 3, Vite, @module-federation/vite, xterm.js (v5), @workfort/ui (web components), @workfort/auth, @workfort/ui-vue

**Design doc:** `docs/2026-04-03-nexus-ui-design.md`

---

### Task 1: Go Embed Scaffolding

Set up the build tag pattern for optional frontend embedding.

**Files:**
- Create: `web/embed.go`
- Create: `web/embed_ui.go`

**Step 1: Create the dev embed file (no UI tag)**

Create `web/embed.go`:

```go
//go:build !ui

// SPDX-License-Identifier: GPL-3.0-or-later
package web

import "embed"

// Dist is empty when built without the "ui" tag. Use --ui-dir to serve
// from disk during development.
var Dist embed.FS
```

**Step 2: Create the production embed file (UI tag)**

Create `web/embed_ui.go`:

```go
//go:build ui

// SPDX-License-Identifier: GPL-3.0-or-later
package web

import "embed"

// Dist holds the Vite build output. Built via:
//
//	cd web && npm run build
//	go build -tags ui
//
//go:embed all:dist
var Dist embed.FS
```

**Step 3: Verify Go compilation without UI tag**

Run: `go build ./web/`
Expected: compiles cleanly (empty embed.FS, no dist/ needed)

**Step 4: Commit**

```
feat(ui): add web embed scaffolding with build tag split
```

---

### Task 2: Mount frontend.Handler in Daemon

Add the Scope frontend SDK dependency and wire `frontend.Handler` into the
daemon's HTTP mux with a `--ui-dir` dev flag.

**Files:**
- Modify: `cmd/daemon.go`
- Modify: `go.mod` (add `github.com/Work-Fort/Scope/go/frontend`)

**Step 1: Add Scope frontend SDK dependency**

Run: `go get github.com/Work-Fort/Scope/go/frontend@v0.1.0`

**Step 2: Write the failing test**

Add a test to `internal/infra/httpapi/handler_test.go` (or a new
`web/frontend_test.go`) that:
1. Creates a temporary directory with a dummy `remoteEntry.js` file
2. Calls `frontend.Handler(os.DirFS(tmpDir), manifest)` with a test manifest
3. Issues `GET /ui/health`
4. Asserts 200 status and manifest JSON containing `"name":"nexus"`

**Step 3: Run test to verify it fails**

Run: `mise run test`
Expected: FAIL (handler not wired yet)

**Step 4: Wire frontend.Handler into daemon.go**

In `cmd/daemon.go`, add imports:

```go
import (
    "io/fs"
    "github.com/Work-Fort/Scope/go/frontend"
    "github.com/Work-Fort/Nexus/web"
)
```

Add after `mux.Handle("/", httpapi.NewHandler(svc, health))` (line ~286):

```go
// Frontend UI handler.
uiManifest := frontend.Manifest{
    Name:    "nexus",
    Label:   "Nexus",
    Route:   "/nexus",
    WSPaths: []string{"/v1/vms/{id}/console"},
}

uiDir := viper.GetString("ui-dir")
if uiDir != "" {
    mux.Handle("/ui/", frontend.Handler(os.DirFS(uiDir), uiManifest))
    log.Info("ui enabled", "source", "disk", "dir", uiDir)
} else {
    distFS, _ := fs.Sub(web.Dist, "dist")
    mux.Handle("/ui/", frontend.Handler(distFS, uiManifest))
    log.Info("ui enabled", "source", "embed")
}
```

Add the `--ui-dir` flag:

```go
cmd.Flags().String("ui-dir", "", "Serve UI from disk (dev mode)")
```

Add `"ui-dir"` to the viper bind loop.

**Step 5: Run test to verify it passes**

Run: `mise run test`
Expected: PASS

**Step 6: Commit**

```
feat(ui): mount frontend.Handler with --ui-dir dev flag
```

---

### Task 3: Scaffold Vue Project

Create the Vite + Vue + MF project in `web/`.

**Files:**
- Create: `web/package.json`
- Create: `web/vite.config.ts`
- Create: `web/tsconfig.json`
- Create: `web/.gitignore`
- Create: `web/src/index.ts`
- Create: `web/src/App.vue`
- Create: `web/src/env.d.ts`

**Step 1: Create package.json**

```json
{
  "name": "@workfort/nexus-ui",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite build --watch",
    "build": "vite build"
  },
  "dependencies": {
    "vue": "^3.5.0",
    "vue-router": "^4.5.0",
    "@workfort/ui": "^0.3.0",
    "@workfort/ui-vue": "^0.1.0",
    "@workfort/auth": "^0.1.0"
  },
  "devDependencies": {
    "@module-federation/vite": "^1.1.0",
    "@vitejs/plugin-vue": "^5.0.0",
    "typescript": "^5.8.0",
    "vite": "^6.0.0"
  }
}
```

**Step 2: Create vite.config.ts**

```ts
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { federation } from '@module-federation/vite';

export default defineConfig({
  plugins: [
    vue({
      template: {
        compilerOptions: {
          isCustomElement: (tag) => tag.startsWith('wf-'),
        },
      },
    }),
    federation({
      name: 'nexus',
      filename: 'remoteEntry.js',
      exposes: {
        './index': './src/index.ts',
      },
      shared: {
        '@workfort/ui': { singleton: true, import: false },
        '@workfort/auth': { singleton: true, import: false },
      },
    }),
  ],
  build: {
    target: 'esnext',
    outDir: 'dist',
  },
});
```

**Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "jsx": "preserve",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src/**/*.ts", "src/**/*.vue", "src/env.d.ts"]
}
```

**Step 4: Create src/env.d.ts**

```ts
/// <reference types="vite/client" />
declare module '*.vue' {
  import type { DefineComponent } from 'vue';
  const component: DefineComponent<{}, {}, any>;
  export default component;
}
```

**Step 5: Create src/index.ts (MF entry)**

Follow the mount/unmount pattern from Passport:

```ts
import { createApp, type App } from 'vue';
import AppComponent from './App.vue';

const apps = new WeakMap<HTMLElement, App>();

export function mount(el: HTMLElement, props: { connected: boolean }) {
  const app = createApp(AppComponent, { connected: props.connected });
  app.mount(el);
  apps.set(el, app);
}

export function unmount(el: HTMLElement) {
  const app = apps.get(el);
  if (app) {
    app.unmount();
    apps.delete(el);
  }
}

export const manifest = {
  name: 'nexus',
  label: 'Nexus',
  route: '/nexus',
  display: 'menu' as const,
};
```

**Step 6: Create src/App.vue (placeholder)**

```vue
<template>
  <wf-panel label="Nexus">
    <p>Nexus UI</p>
  </wf-panel>
</template>

<script setup lang="ts">
defineProps<{ connected: boolean }>();
</script>
```

**Step 7: Create web/.gitignore**

```
node_modules/
dist/
```

**Step 8: Install dependencies and verify build**

Run:
```bash
cd web && npm install && npm run build
```
Expected: `dist/remoteEntry.js` exists

**Step 9: Commit**

```
feat(ui): scaffold Vue + MF remote project
```

---

### Task 4: API Client

Thin fetch wrapper for the Nexus REST API.

**Files:**
- Create: `web/src/lib/api.ts`

**Step 1: Create the API client**

```ts
function getBaseUrl(): string {
  const match = location.pathname.match(/^\/forts\/([^/]+)/);
  if (match) {
    return `/forts/${match[1]}/api/nexus/v1`;
  }
  return '/v1';
}

const base = getBaseUrl();

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path}: ${res.status} ${text}`);
  }
  return res.json();
}

export interface VM {
  id: string;
  name: string;
  tags: string[];
  state: string;
  image: string;
  runtime: string;
  ip?: string;
  gateway?: string;
  dns?: { servers?: string[]; search?: string[] };
  root_size?: string;
  restart_policy: string;
  restart_strategy: string;
  shell?: string;
  init: boolean;
  env?: Record<string, string>;
  template_id?: string;
  created_at: string;
  started_at?: string;
  stopped_at?: string;
}

export interface Drive {
  id: string;
  name: string;
  size_bytes: number;
  mount_path: string;
  vm_id?: string;
  created_at: string;
}

export interface Device {
  id: string;
  name: string;
  host_path: string;
  container_path: string;
  permissions: string;
  gid: number;
  vm_id?: string;
  created_at: string;
}

export const api = {
  listVMs: (tag?: string[], tagMatch?: string) => {
    const params = new URLSearchParams();
    tag?.forEach((t) => params.append('tag', t));
    if (tagMatch) params.set('tag_match', tagMatch);
    const qs = params.toString();
    return request<VM[]>('GET', `/vms${qs ? `?${qs}` : ''}`);
  },
  getVM: (id: string) => request<VM>('GET', `/vms/${id}`),
  startVM: (id: string) => request<void>('POST', `/vms/${id}/start`),
  stopVM: (id: string) => request<void>('POST', `/vms/${id}/stop`),
  restartVM: (id: string) => request<void>('POST', `/vms/${id}/restart`),
  deleteVM: (id: string) => request<void>('DELETE', `/vms/${id}`),
  listDrives: () => request<Drive[]>('GET', '/drives'),
  listDevices: () => request<Device[]>('GET', '/devices'),
};
```

**Step 2: Verify build**

Run: `cd web && npm run build`
Expected: builds without errors

**Step 3: Commit**

```
feat(ui): add REST API client
```

---

### Task 5: WebSocket Console Client

Client for the terminal WebSocket protocol.

**Files:**
- Create: `web/src/lib/console.ts`

**Step 1: Install xterm dependencies**

Use all v5 packages (v5 and v6 use different namespaces and are incompatible):

Run: `cd web && npm install xterm xterm-addon-fit xterm-addon-web-links`

**Step 2: Create the console client**

```ts
export interface ConsoleOptions {
  vmId: string;
  cols: number;
  rows: number;
  onData: (data: ArrayBuffer) => void;
  onExit: (exitCode: number) => void;
  onClose: () => void;
}

export function getConsoleUrl(vmId: string, cols: number, rows: number): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const match = location.pathname.match(/^\/forts\/([^/]+)/);
  const base = match
    ? `/forts/${match[1]}/api/nexus/v1`
    : '/v1';
  return `${proto}//${location.host}${base}/vms/${vmId}/console?cols=${cols}&rows=${rows}`;
}

export function connectConsole(opts: ConsoleOptions): {
  send: (data: string) => void;
  resize: (cols: number, rows: number) => void;
  close: () => void;
} {
  const url = getConsoleUrl(opts.vmId, opts.cols, opts.rows);
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';

  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) {
      opts.onData(ev.data);
    } else {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'exit') {
          opts.onExit(msg.exit_code);
        }
      } catch {
        // Not JSON — treat as text stdout (shouldn't happen per protocol).
      }
    }
  };

  ws.onclose = () => opts.onClose();

  return {
    send: (data: string) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    },
    resize: (cols: number, rows: number) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    },
    close: () => ws.close(),
  };
}
```

**Step 3: Verify build**

Run: `cd web && npm run build`
Expected: builds without errors

**Step 4: Commit**

```
feat(ui): add WebSocket console client
```

---

### Task 6: VM List View

The landing page — shows all VMs with search and refresh.

**Files:**
- Create: `web/src/components/VMList.vue`
- Modify: `web/src/App.vue`

**Step 1: Create VMList.vue**

Build the VM list component with:
- Fetch VMs on mount via `api.listVMs()`
- Text search input (`wf-text-input`) filtering by VM name
- Refresh rate dropdown (2s, 5s default, 10s, 30s) using a `<select>`
- `setInterval` polling at the selected rate, cleared on unmount
- Each VM as a `wf-list-item` showing name, `wf-status-dot` for state, IP address
- Click navigates to `/nexus/vms/:id`
- Inline action buttons: start, stop, restart, delete
- Delete requires confirmation

Reference `vmResponse` fields from `internal/infra/httpapi/handler.go:222-243`
for the VM shape. Map VM `state` to `wf-status-dot` status: `running` → `online`,
`stopped` → `offline`, everything else → `away`.

**Step 2: Wire up App.vue with Vue Router**

Replace the placeholder `App.vue` with a `<router-view>`. Set up Vue Router
with routes:
- `/` → `VMList`
- `/vms/:id` → `VMDetail` (created in Task 7)
- `/vms/:id/terminal` → `VMDetail` with terminal tab active

Update `src/index.ts` to create the router in `mount()` and pass it to the app.
The router must use `createMemoryHistory()` — MF remotes don't own the URL bar,
and the actual browser path is `/forts/{fort}/nexus/...` which doesn't match a
hardcoded base. Memory history avoids conflicts with the shell's router.

**Step 3: Verify build**

Run: `cd web && npm run build`
Expected: builds without errors

**Step 4: Manual smoke test**

Run the daemon with `--ui-dir web/dist`, open browser, verify VM list renders.

**Step 5: Commit**

```
feat(ui): add VM list view with search and polling
```

---

### Task 7: VM Detail & Overview Tab

Tabbed detail view with VM config and controls.

**Files:**
- Create: `web/src/components/VMDetail.vue`
- Create: `web/src/components/VMOverview.vue`

**Step 1: Create VMOverview.vue**

Display all VM fields from the API response:
- Status with `wf-status-dot`
- ID, name, image, runtime, shell
- IP address, gateway, DNS config
- Root size, restart policy/strategy
- Init enabled, environment variables
- Template ID
- Attached drives (fetched separately via `api.listDrives()`, filtered by `vm_id`)
- Attached devices (fetched separately via `api.listDevices()`, filtered by `vm_id`)
- Timestamps (created, started, stopped)
- Action buttons: start, stop, restart (shown conditionally based on state)

**Step 2: Create VMDetail.vue**

Tabbed container with two tabs: Overview | Terminal.
- Fetch VM via `api.getVM(route.params.id)` on mount
- Tab navigation updates the route:
  - `/vms/:id` → Overview tab
  - `/vms/:id/terminal` → Terminal tab
- Use `<router-view>` or `v-if` to switch between `VMOverview` and `Terminal`
  (Task 8)
- Show VM name in a header above the tabs
- Back link to VM list

**Step 3: Verify build**

Run: `cd web && npm run build`
Expected: builds without errors

**Step 4: Commit**

```
feat(ui): add VM detail view with overview tab
```

---

### Task 8: Terminal Tab

xterm.js terminal connected to the console WebSocket.

**Files:**
- Create: `web/src/components/Terminal.vue`
- Modify: `web/src/components/VMDetail.vue` (wire terminal tab)

**Step 1: Install xterm v5 if not already done in Task 5**

Verify `xterm`, `xterm-addon-fit`, `xterm-addon-web-links` are in `package.json`.

**Step 2: Create Terminal.vue**

The component receives `vmId` as a prop.

On mount:
1. Create `Terminal` instance from `xterm`, apply `FitAddon` from `xterm-addon-fit`
   and `WebLinksAddon` from `xterm-addon-web-links` (all v5 packages)
2. Attach to a `<div ref="terminalEl">` via `terminal.open(el)`
3. Call `fitAddon.fit()` to get initial cols/rows
4. Call `connectConsole()` with the VM ID and dimensions
5. Wire `terminal.onData` → `console.send`
6. Wire `console.onData` → `terminal.write(new Uint8Array(data))`
7. Wire `fitAddon` resize → `console.resize`
8. On `console.onExit` → write exit message to terminal, show "Reconnect" button
9. On `console.onClose` → if not from exit event, show disconnected state

On unmount:
1. Call `console.close()`
2. Call `terminal.dispose()`

Use `ResizeObserver` on the terminal container to trigger `fitAddon.fit()`
on window/pane resize.

Import paths (all v5):
- `import { Terminal } from 'xterm'`
- `import { FitAddon } from 'xterm-addon-fit'`
- `import { WebLinksAddon } from 'xterm-addon-web-links'`
- `import 'xterm/css/xterm.css'`

**Step 3: Wire terminal tab in VMDetail.vue**

Add the Terminal component to the terminal tab, passing `vmId` from the route.

**Step 4: Verify build**

Run: `cd web && npm run build`
Expected: builds without errors

**Step 5: Manual smoke test**

Run daemon with `--ui-dir web/dist`. Navigate to a running VM → Terminal tab.
Verify:
- Terminal connects and shows shell prompt
- Keystrokes are sent and output appears
- Resize works (resize browser window)
- Navigate away and back — fresh session starts

**Step 6: Commit**

```
feat(ui): add xterm.js terminal tab
```

---

### Task 9: Build Integration

Add `web/dist` to `.gitignore` and update build tasks.

**Files:**
- Modify: `.gitignore`
- Modify: `.mise/tasks/build.sh` (add `-tags ui` variant or note)
- Modify: `.mise/tasks/build/release` (add web build + `-tags ui`)

**Step 1: Update .gitignore**

Add:
```
web/dist/
web/node_modules/
```

**Step 2: Update build/release task**

In `.mise/tasks/build/release`, add the web build before Go compilation:

```bash
# Build frontend
echo "Building frontend..."
(cd web && npm ci && npm run build)

# Then add -tags ui to the nexus go build line:
go build -tags ui -ldflags=... -o build/nexus .
```

Only the main `nexus` binary needs `-tags ui`. The other binaries (nexusctl,
nexus-netns, etc.) don't embed the frontend.

**Step 3: Verify release build**

Run: `mise run build:release`
Expected: builds frontend, then Go with embedded UI

**Step 4: Verify the embedded binary serves the UI**

Run: `build/nexus daemon` and check `curl localhost:16400/ui/health`
Expected: 200 with manifest JSON

**Step 5: Commit**

```
feat(ui): integrate frontend build into release task
```

---

### Task 10: Final Verification

End-to-end smoke test of the complete flow.

**Step 1: Build and run**

```bash
mise run build:release
build/nexus daemon
```

**Step 2: Verify service discovery**

```bash
curl -s localhost:16400/ui/health | jq .
```

Expected: `{"name":"nexus","label":"Nexus","route":"/nexus","ws_paths":["/v1/vms/{id}/console"]}`

**Step 3: Verify UI loads**

Open browser to Scope, verify Nexus appears in sidebar menu, VM list loads,
detail view works, terminal connects.

**Step 4: Commit any fixes**

If fixes are needed, commit them individually with descriptive messages.
