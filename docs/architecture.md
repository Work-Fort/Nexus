# Architecture

## Overview

Nexus is an HTTP service for managing VMs/containers via containerd, designed
to run as an unprivileged systemd user service. Production workloads run in
Kata Containers with Firecracker for hardware-level isolation.

Nexus is one component in the WorkFort platform:

```
workfort (TUI)        User interface, setup wizard, chat client
  │
  ├── Portal VM       Tenant orchestrator — manages agent lifecycle,
  │                   configures services, handles webhooks from Sharkfin
  │
  ├── Sharkfin VM     Messaging — channels, identity, presence, MCP bridge
  │
  ├── Agent VMs       Ephemeral — run Claude Code with Sharkfin MCP bridge
  │
  └── Nexus (host)    VM lifecycle, storage (btrfs), networking
```

WorkFort talks to Nexus (local or cloud) to provision service VMs (Portal,
Sharkfin). The Portal orchestrates agent VMs through Nexus's API. Sharkfin
handles inter-agent and human-agent messaging. Agent VMs run Claude Code
with a Sharkfin MCP bridge for communication.

## Nexus Responsibilities

1. **VM lifecycle** — create, start, stop, exec, delete containers/VMs
2. **Storage** — btrfs subvolumes with qgroups for per-VM data volumes
3. **Networking** — VM-to-VM and VM-to-host communication

## VM Roles

### Service VMs (long-lived)

- **Portal** — tenant orchestrator. Receives webhooks from Sharkfin when
  agents are @mentioned. Decides when to create/start/stop agent VMs.
  Manages credentials, agent configuration, and failure recovery. Talks
  to Nexus's REST API.
- **Sharkfin** — messaging daemon. Manages channels, identity, presence.
  Fires webhooks to Portal on mentions/DMs. Agent VMs connect to it via
  the `sharkfin mcp-bridge` command.

### Agent VMs (ephemeral)

Spun up on demand by the Portal when an agent is needed. Each agent VM runs:
- `claude -p "..." --allowedTools "mcp__sharkfin__*"` — Claude Code session
- `sharkfin mcp-bridge` — connects to the Sharkfin VM for messaging
- `~/.claude/.credentials.json` — injected at startup

Agent VMs are disposable. Data that needs to persist lives on btrfs data
volumes that can be detached and reattached to new VMs.

## Hexagonal Architecture (Ports & Adapters)

```
domain/          Pure types + port interfaces (VMStore, Runtime)
app/             Use cases (VMService, webhook handler)
infra/sqlite/    VMStore adapter (sqlc + goose migrations)
infra/containerd/ Runtime adapter (containerd v2 Go client)
infra/httpapi/   HTTP handlers (stdlib net/http)
cmd/             CLI wiring (Cobra + Viper)
```

## Runtime Abstraction

Containerd's runtime handler pattern lets Nexus use the same API for both
development and production:

- `io.containerd.runc.v2` — Linux containers (development/testing)
- `io.containerd.kata.v2` — Kata VMs with Firecracker (production)

The runtime handler is the only difference. All Nexus operations (create,
start, stop, exec, delete) work identically across both.

## Kata/Firecracker Boot Flow

When using Kata with Firecracker, the boot sequence is:

1. Firecracker boots a Kata-provided kernel (`vmlinux-6.18.12-181`) with
   a Kata guest rootfs (`kata-ubuntu-noble.image`)
2. `/sbin/init` inside the guest **is** `kata-agent` — an 18MB statically-linked
   Rust binary that acts as PID 1
3. `kata-agent` listens on vsock for instructions from the host-side
   containerd shim (`containerd-shim-kata-v2`)
4. The shim passes the container spec (OCI image) to `kata-agent`, which
   mounts it as the container's rootfs inside the VM
5. The container's `CMD`/`ENTRYPOINT` runs as a workload process, not PID 1

This means:
- **No init system management needed.** Kata handles the VM init. Container
  images don't need OpenRC, systemd, or any init system.
- **Kata provides the kernel.** Purpose-built for the guest environment with
  vsock, cgroups, etc. No need for custom kernels.
- **The OCI image is just a workload payload.** Standard Docker images work
  as-is.

## Storage Architecture

There are three separate storage layers, each with a different owner:

### 1. Container Image (containerd)

OCI images pulled and snapshotted by containerd's snapshotter (currently
overlayfs). This is the container's root filesystem — disposable and
replaceable. Containerd handles pull, unpack, and snapshot lifecycle.

### 2. Guest VM Rootfs (Kata)

Pre-built by the Kata project. A read-only image shared across all VMs on
the host. Contains the kernel, kata-agent, and minimal OS. Not managed by
Nexus.

### 3. Data Volume (Nexus)

Persistent user data stored on btrfs subvolumes. This is the layer that
Nexus owns and manages. Key properties:

- **Survives OS changes** — detach the data volume, upgrade the container
  image, reattach the data volume
- **Per-VM quotas via btrfs qgroups** — enforced in all environments to
  prevent a single VM from consuming all host storage
- **CoW snapshots** — efficient cloning for development workflows
- **Data sharing** — mount the same subvolume (or a snapshot) into multiple
  VMs

## Networking

VMs need to communicate with each other and with Nexus on the host:

- **Agent VM → Sharkfin VM**: MCP bridge connection (TCP)
- **Sharkfin VM → Portal VM**: Webhook notifications (HTTP)
- **Portal VM → Nexus**: VM lifecycle API calls (HTTP to host gateway IP)
- **WorkFort → Sharkfin VM**: WebSocket chat connection
- **Agent VMs → Internet**: Claude API calls (HTTPS)

## Deployment Scenarios

The architecture is identical in all environments — same VM topology,
same networking, same storage model.

### Local

- Nexus runs as a systemd user service
- WorkFort setup wizard provisions service VMs (Portal, Sharkfin)
- Data volumes on btrfs subvolumes with sensible default quotas
- Quotas prevent runaway VMs from filling the host disk

### WorkFort Cloud

- Each tenant gets a dedicated btrfs EBS volume
- Volume size determined by account/subscription level
- Tenants allocate space from their volume to individual VMs
- Per-VM qgroup quotas prevent VMs from interfering with one another
- Same btrfs subvolume + qgroup mechanism as local, different quota source

## Unprivileged Operation

Nexus runs without root or CAP_SYS_ADMIN:

- **containerd socket**: Access via `containerd` group (permanent GID in
  `/etc/containerd/config.toml`)
- **Image config**: Read from content store via `img.Spec(ctx)` instead of
  `oci.WithImageConfig()` which requires an overlay mount
- **Task I/O**: `cio.NullIO` for Start (no FIFO creation), user-writable
  FIFO directory for Exec
- **Known limitation**: Only numeric USER directives supported in images
  (e.g., `USER 1000:1000`). Named users require rootfs mount to resolve
  against `/etc/passwd`.
