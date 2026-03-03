# Kata Guest Kernel Testing

How to verify that a custom guest kernel works with Kata Containers and Nexus.
The Anvil kernel research doc (`~/Work/WorkFort/anvil/kata-kernel-research.md`)
lists the specific config gaps; this guide covers the testing methodology.

## Prerequisites

- Kata Containers 3.x installed (`/opt/kata/`)
- containerd running with btrfs snapshotter available
- Host kernel modules loaded (`vhost_net`, `vhost_vsock`)
- `/dev/kvm` accessible
- Nexus built (`mise run build`)

## Required Guest Kernel Configs

A guest kernel must have these to work with Kata + Firecracker:

| Config | Purpose |
|--------|---------|
| `VIRTIO_VSOCKETS` + `VIRTIO_VSOCKETS_COMMON` | Agent ↔ shim communication |
| `VIRTIO_MMIO` | Virtio device discovery (Firecracker uses MMIO, not PCI) |
| `VIRTIO_MMIO_CMDLINE_DEVICES` | Firecracker passes device addresses via cmdline |
| `VIRTIO_BLK` | Block device hotplug (container rootfs, drives) |
| `VIRTIO_NET` | Guest networking |
| `VIRTIO_CONSOLE` | Serial console |
| `X86_MPPARSE` | vCPU topology via MP tables |
| `MEMORY_HOTPLUG_DEFAULT_ONLINE` | Auto-online hotplugged memory (renamed to `MHP_DEFAULT_ONLINE_TYPE_ONLINE_AUTO` in kernel 6.14+) |

For QEMU (virtio-fs rootfs sharing, NVDIMM boot), also:

| Config | Purpose |
|--------|---------|
| `VIRTIO_PCI` | Virtio over PCI bus (QEMU uses PCI, not MMIO) |
| `VIRTIO_FS` | Virtio-fs for rootfs sharing from host |
| `FUSE_FS` | FUSE layer (dependency of VIRTIO_FS) |
| `FS_DAX` | DAX support for NVDIMM-backed rootfs image |
| `LIBNVDIMM` | NVDIMM library |
| `BLK_DEV_PMEM` | Persistent memory block device |
| `ZONE_DEVICE` | Memory zone for DAX devices |

For btrfs snapshotter support, also:

| Config | Purpose |
|--------|---------|
| `BTRFS_FS` | Mount btrfs container rootfs inside guest |
| `BTRFS_FS_POSIX_ACL` | POSIX ACLs on container files |

## Testing a Kernel

### 1. Place the kernel binary

Download or build the kernel and put it somewhere accessible:

```bash
# From an Anvil build
cp ~/.cache/anvil/build-kernel/artifacts/vmlinux-6.19.5-x86_64 /tmp/
```

### 2. Create a Kata config override

Kata reads `/etc/kata-containers/configuration.toml` first, falling back to
`/opt/kata/share/defaults/kata-containers/configuration.toml`. Create an
override pointing to the test kernel and the target hypervisor:

**Firecracker config:**

```bash
sudo mkdir -p /etc/kata-containers
sudo tee /etc/kata-containers/configuration.toml <<'EOF'
[hypervisor.firecracker]
path = "/opt/kata/bin/firecracker"
kernel = "/tmp/vmlinux-6.19.5-x86_64"
image = "/opt/kata/share/kata-containers/kata-containers.img"
rootfs_type = "ext4"
block_device_driver = "virtio-mmio"
default_vcpus = 1
default_memory = 2048
memory_slots = 10
jailer_path = "/opt/kata/bin/jailer"
kernel_params = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1"
entropy_source = "/dev/urandom"
static_sandbox_resource_mgmt = true

[agent.kata]

[runtime]
internetworking_model = "tcfilter"
disable_guest_seccomp = true
static_sandbox_resource_mgmt = true
EOF
```

**QEMU config** (for comparison or device passthrough testing):

```bash
# Remove the override to fall back to the QEMU default:
sudo rm /etc/kata-containers/configuration.toml
# The default at /opt/kata/share/defaults/kata-containers/configuration.toml
# uses [hypervisor.qemu] with virtio-fs.
```

### 3. Run the test matrix

Test each snapshotter + runtime combination through Nexus:

```bash
# Start Nexus
./nexus &

# Test: overlayfs + Kata (baseline — should always work with stock kernel)
curl -s -X POST http://127.0.0.1:9600/v1/vms \
  -d '{"name":"test-overlay","role":"test","runtime":"io.containerd.kata.v2"}' | jq .
curl -s -X POST http://127.0.0.1:9600/v1/vms/<id>/start | jq .
curl -s -X POST http://127.0.0.1:9600/v1/vms/<id>/exec \
  -d '{"cmd":["uname","-r"]}' | jq .
# Expected: guest kernel version (e.g. 6.1.164), NOT host kernel

# Cleanup
curl -s -X POST http://127.0.0.1:9600/v1/vms/<id>/stop | jq .
curl -s -X DELETE http://127.0.0.1:9600/v1/vms/<id> | jq .
```

For btrfs snapshotter testing (requires Nexus to be configured with
`WithSnapshotter("btrfs")`), the same sequence applies. If exec returns
exit code 255 with empty output, the guest kernel can't mount btrfs — check
`CONFIG_BTRFS_FS`.

### 4. Interpret failures

| Symptom | Likely cause |
|---------|-------------|
| VM start hangs, then vsock timeout | Kernel can't boot at all. Check `VIRTIO_VSOCKETS`, `VIRTIO_MMIO_CMDLINE_DEVICES`, `X86_MPPARSE`. |
| VM starts but exec returns 255 (empty) | Guest can't mount container rootfs. Check filesystem support (`BTRFS_FS`, `EXT4_FS`). |
| Vsock timeout with QEMU | Kernel can't mount the rootfs image. Check `ACPI_NFIT`, `VIRTIO_PMEM` (NVDIMM path), or set `disable_image_nvdimm = true` in Kata config to use virtio-blk instead. |
| VM starts but only 1 vCPU visible | Missing `X86_MPPARSE`. |
| VM starts but memory less than configured | Missing `MEMORY_HOTPLUG_DEFAULT_ONLINE`. |
| `firecracker.socket: connect: no such file or directory` | Kernel built for a different Firecracker setup. Check all three required Firecracker configs. |

### 5. Verify kernel config

Extract the config from the kernel binary or check the source config directly:

```bash
# If the kernel has CONFIG_IKCONFIG_PROC=y:
# (inside the guest) zcat /proc/config.gz | grep BTRFS

# Otherwise, check the build config:
grep -E 'VIRTIO_MMIO_CMDLINE|X86_MPPARSE|MEMORY_HOTPLUG_DEFAULT|BTRFS_FS' \
  path/to/kernel/.config
```

All required options must show `=y` (built-in), not `=m` (module) — Kata
guest kernels typically have no module loading infrastructure.

## Modifying a Kernel Config

To fix a kernel that's missing required options:

```bash
cd ~/Work/WorkFort/anvil

# Edit the config
vi configs/microvm-kernel-x86_64.config

# Add or change the missing options, e.g.:
# CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
# CONFIG_X86_MPPARSE=y
# CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE=y

# Rebuild via Anvil
# (follow Anvil's build process — produces vmlinux binary)
```

After rebuilding, copy the new kernel to the path referenced in the Kata
config and retest.

## Quick Checklist

For a Firecracker-only kernel:

- [ ] `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`
- [ ] `CONFIG_X86_MPPARSE=y`
- [ ] `CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE=y`
- [ ] `CONFIG_BTRFS_FS=y` (if using btrfs snapshotter)
- [ ] `CONFIG_BTRFS_FS_POSIX_ACL=y` (if using btrfs snapshotter)
- [ ] `CONFIG_MEMCG_SWAP=y` (kernel <6.19 only — always-on in cgroupv2-only kernels)
- [ ] Boot test passes (uname -r returns expected version)
- [ ] Exec test passes (non-255 exit code, output returned)

## Anvil Kernel Status

The Anvil 6.19.5 kernel (`~/.cache/anvil/build-kernel/artifacts/vmlinux-6.19.5-x86_64`)
is fully Kata-compatible. Verified with QEMU + NVDIMM/DAX: create, start, exec
(`uname -r` returns `6.19.5`), stop, delete all pass. Config at
`~/.cache/anvil/build-kernel/artifacts/config-6.19.5-x86_64`.

## References

- Anvil kernel research: `~/Work/WorkFort/anvil/kata-kernel-research.md`
- Kata kernel config fragments: `github.com/kata-containers/kata-containers/tree/main/tools/packaging/kernel/configs/fragments/`
- Firecracker guest kernel policy: `github.com/firecracker-microvm/firecracker/blob/main/docs/kernel-policy.md`
