# Kata Containers Setup

## Overview

Nexus uses Kata Containers with Firecracker as the production VM runtime.
Each container runs inside a dedicated microVM with its own kernel, providing
hardware-level isolation. The containerd Go client uses `io.containerd.kata.v2`
as the runtime handler — all lifecycle operations (create, start, stop, exec,
delete) work identically to the runc development runtime.

## Installation

Kata 3.x ships as a self-contained tarball under `/opt/kata/`. The containerd
shim must be discoverable in PATH:

```bash
ln -s /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/
```

No containerd config changes are needed — containerd v2 auto-discovers shims
by binary name (`containerd-shim-kata-v2` → runtime `io.containerd.kata.v2`).

## Kernel Modules

Kata requires three vhost kernel modules for virtio networking and VM sockets:

| Module | Purpose |
|--------|---------|
| `vhost_net` | Host kernel accelerator for virtio network |
| `vhost_vsock` | Host support for VM sockets (guest ↔ host communication) |
| `vhost` | Core vhost infrastructure (loaded as dependency) |

### Load modules (immediate)

```bash
sudo modprobe vhost_net
sudo modprobe vhost_vsock
```

### Load modules at boot

Create `/etc/modules-load.d/kata.conf`:

```
vhost_net
vhost_vsock
```

### Verify

```bash
lsmod | grep vhost
kata-runtime check
```

`kata-runtime check` should print `System is capable of running Kata Containers`.

## KVM Access

The nexus user must have access to `/dev/kvm`. On Arch Linux this is
typically handled by adding the user to the `kvm` group:

```bash
sudo usermod -aG kvm $USER
```

Verify permissions:

```bash
ls -la /dev/kvm
# Should show crw-rw-rw- or group kvm with rw
```

## Unprivileged Operation

Nexus runs without root. Kata/Firecracker needs:

- `/dev/kvm` access (via group or permissions)
- vhost modules loaded (one-time setup by root)
- containerd socket access (via `containerd` group)

No `CAP_SYS_ADMIN` is needed on the nexus binary for Kata operations —
containerd and the Kata shim handle VM creation via their own privileges.

## Verification

```bash
# Check Kata installation
kata-runtime --version
kata-runtime check

# Test through Nexus (with daemon running)
curl -X POST http://127.0.0.1:9600/v1/vms \
  -d '{"name":"kata-test","role":"agent","runtime":"io.containerd.kata.v2"}'
curl -X POST http://127.0.0.1:9600/v1/vms/<id>/start
curl -X POST http://127.0.0.1:9600/v1/vms/<id>/exec \
  -d '{"cmd":["uname","-r"]}'
# Should return Kata's guest kernel (e.g. 6.18.12), not the host kernel
```
