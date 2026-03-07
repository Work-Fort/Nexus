# Provisioning Templates Design

## Problem

Container images (Alpine, Ubuntu, Arch) exit immediately when started as VMs
because their default entrypoint (`/bin/sh`, etc.) has no long-running process.
To use container images as VMs, we need to bootstrap an init system (OpenRC or
systemd) as PID 1.

## Solution

**Provisioning templates** — reusable shell scripts stored in the database that
run as the container entrypoint. Templates are a first-class CRUD resource with
full REST and MCP API surface.

When a VM is created with `init: true`, Nexus auto-detects the image's distro,
finds the matching template, and injects it as the container's entrypoint via
bind-mount.

## Template Resource

| Field        | Type      | Description                                      |
|--------------|-----------|--------------------------------------------------|
| `id`         | string    | Auto-generated NXID                              |
| `name`       | string    | Unique human-readable name                       |
| `distro`     | string    | Distro identifier for auto-detection matching    |
| `script`     | text      | Shell script body                                |
| `created_at` | timestamp |                                                  |
| `updated_at` | timestamp |                                                  |

## Built-in Defaults

Seeded into the database on first run:

### alpine-openrc (distro: `alpine`)

```sh
#!/bin/sh
if ! command -v openrc >/dev/null 2>&1; then
    apk add --no-cache openrc
    sed -i 's/^#rc_sys=""/rc_sys="lxc"/' /etc/rc.conf
    mkdir -p /run/openrc
    touch /run/openrc/softlevel
fi
exec /sbin/init
```

### ubuntu-systemd (distro: `ubuntu`)

```sh
#!/bin/sh
if [ ! -d /run/systemd/system ]; then
    apt-get update -qq && apt-get install -y -qq systemd-sysv dbus >/dev/null 2>&1
fi
exec /lib/systemd/systemd
```

### arch-systemd (distro: `arch`)

```sh
#!/bin/sh
if [ ! -d /run/systemd/system ]; then
    pacman -Sy --noconfirm systemd >/dev/null 2>&1
fi
exec /lib/systemd/systemd
```

## Distro Detection

After pulling an image, Nexus inspects the image filesystem to determine the
distro:

1. Read `/etc/os-release` and parse the `ID=` field (standard on all modern
   Linux distros).
2. Fallback: check for package manager binaries — `/sbin/apk` (alpine),
   `/usr/bin/apt` (ubuntu/debian), `/usr/bin/pacman` (arch).

The detected ID is matched against the template `distro` field. If no template
matches, VM creation fails with: `"no init template found for distro: <id>"`.

Distro detection lives in the containerd runtime layer (`runtime.DetectDistro`)
since it needs access to the image content store.

## VM Creation Flow

When `init: true` is passed to CreateVM:

1. Pull image (existing)
2. Detect distro — `runtime.DetectDistro(ctx, image)` reads `/etc/os-release`
3. Resolve template — app layer looks up template by distro from the store
4. Write temp script — write script to `$RUNTIME_DIR/nexus/init/<vm-id>.sh`
5. Bind-mount — mount the script into the container at `/nexus-init.sh`
   (same pattern as resolv.conf for DNS)
6. Override entrypoint — set process args to `/bin/sh /nexus-init.sh`
7. Create container (existing, with extra mount and entrypoint override)

## Per-VM Override

VMs reference a shared template but can optionally store a per-VM script
override. On start:

- If `script_override` is set on the VM, use that.
- Otherwise, read the script from the referenced template.

This allows customizing a single VM without forking the whole template, while
still inheriting updates from the shared template by default.

### New VM Fields

| Field             | Type           | Description                            |
|-------------------|----------------|----------------------------------------|
| `init`            | bool           | Whether init injection is enabled      |
| `template_id`     | string         | Reference to the shared template       |
| `script_override` | text (nullable)| Per-VM script override, null = use template |

## API Surface

### Template REST Endpoints

| Method | Path                  | Description                              |
|--------|-----------------------|------------------------------------------|
| POST   | `/v1/templates`       | Create template                          |
| GET    | `/v1/templates`       | List templates                           |
| GET    | `/v1/templates/:ref`  | Get template by ID or name               |
| PUT    | `/v1/templates/:ref`  | Update template                          |
| DELETE | `/v1/templates/:ref`  | Delete template (fails if VMs reference) |

### MCP Tools

`template_create`, `template_list`, `template_get`, `template_update`,
`template_delete` — 5 new tools.

### VM Changes

- `vm_create` gains `init` (bool) and `template` (optional name/ID) parameters.
  When `init` is true and `template` is omitted, auto-detection selects the
  template.
- `vm_patch` gains `script_override` (string, nullable) parameter.

## E2E Tests

Real image tests — no mocks. Verify the bootstrap scripts actually install and
run init systems on real images.

1. **Alpine + OpenRC** — Create VM from `alpine:latest` with `init: true` →
   start → exec `rc-status` → verify OpenRC is running.
2. **Ubuntu + systemd** — Create VM from `ubuntu:latest` with `init: true` →
   start → exec `systemctl is-system-running` → verify systemd reports
   `running` or `degraded`.
3. **Arch + systemd** — Create VM from `archlinux:latest` with `init: true` →
   start → exec `systemctl is-system-running` → same check.

Each test also verifies stop/restart idempotency (init comes back up).

Separate test target: `mise run e2e:init` to avoid slow package installs on
every E2E run.
