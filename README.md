# Nexus

HTTP service for managing agent and service VMs via containerd. Designed to run
as an unprivileged systemd user service.

## Quick Start

```bash
go build -o nexus .
./nexus daemon
```

The daemon listens on `127.0.0.1:9600` by default. See `nexus daemon --help`
for all flags.

## Prerequisites

- **containerd** >= 2.0 running as a system service
- Socket access: add your user to the `containerd` group (see below)
- **Kata Containers** (optional): install to `/opt/kata` and symlink the shim

### containerd Socket Access

```bash
sudo groupadd -f containerd
sudo usermod -aG containerd $USER

# Set socket group permanently in containerd config
sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml > /dev/null
CONTAINERD_GID=$(getent group containerd | cut -d: -f3)
sudo sed -i "s/gid = 0/gid = $CONTAINERD_GID/" /etc/containerd/config.toml
sudo systemctl restart containerd
```

### Kata Containers

```bash
sudo ln -sf /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
```

Then pass `--runtime io.containerd.kata.v2` to use Kata instead of runc.

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/vms` | Create a VM |
| `GET` | `/v1/vms` | List VMs (optional `?role=agent\|service`) |
| `GET` | `/v1/vms/{id}` | Get a VM |
| `DELETE` | `/v1/vms/{id}` | Delete a VM |
| `POST` | `/v1/vms/{id}/start` | Start a VM |
| `POST` | `/v1/vms/{id}/stop` | Stop a VM |
| `POST` | `/v1/vms/{id}/exec` | Execute a command in a running VM |
| `POST` | `/webhooks/sharkfin` | Sharkfin webhook (find-or-create agent) |

## Architecture

Hexagonal (Ports & Adapters):

```
domain/          Pure types + port interfaces (VMStore, Runtime)
app/             Use cases (VMService, webhook handler)
infra/sqlite/    VMStore adapter (sqlc + goose migrations)
infra/containerd/ Runtime adapter (containerd v2 Go client)
infra/httpapi/   HTTP handlers (stdlib net/http)
cmd/             CLI wiring (Cobra + Viper)
```

## Known Limitations

### Named USER directives in container images

Nexus reads the OCI image config from containerd's content store without
performing client-side overlay mounts. This allows nexus to run as an
unprivileged user (no `CAP_SYS_ADMIN` required).

The trade-off: containerd's `oci.WithImageConfig()` mounts the container's
rootfs to resolve named users (e.g., `USER nginx`) against `/etc/passwd` and
to look up supplemental groups from `/etc/group`. Since we skip that mount,
**only numeric USER directives are supported** (e.g., `USER 1000:1000`).

This does **not** affect processes running inside the VM/container. Once the
container starts, the guest kernel mounts the rootfs normally and all user/group
resolution works as expected. The limitation only applies to the initial process
identity set in the OCI spec at creation time.

If an image uses a named USER directive, container creation will fail with an
error indicating the non-numeric user. To fix this, either:

1. Rebuild the image with a numeric USER (e.g., `USER 1000:1000`)
2. Override the user at creation time (not yet implemented)
