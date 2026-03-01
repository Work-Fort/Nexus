# Architecture

## Overview

Nexus is an HTTP service for managing VMs/containers via containerd, designed
to run as an unprivileged systemd user service. Production workloads run in
Kata Containers with Firecracker for hardware-level isolation.

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

## Deployment Scenarios

### Local Development

- Data volumes on btrfs subvolumes with sensible default quotas
- Quotas prevent runaway VMs from filling the host disk
- Easy attach/detach for OS image upgrades

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
