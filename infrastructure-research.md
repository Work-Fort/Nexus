# Infrastructure Research: VM Runtime for Autonomous Development Teams

## Context

Building a platform for fully autonomous development teams. Agents and services (Git forge, chat) run on VMs. The platform includes:

- **Combine** — Git forge (forked from Soft Serve, Go)
- **Communication tool** — Slack-like, Bubble Tea TUI over SSH
- **Compute layer** — VM-based agent isolation (this document)

Requirements:
- Fast VM provisioning for agents
- GPU passthrough for some workloads
- EBS-compatible storage on AWS
- Go-native API for VM lifecycle management
- Support for both GPU and non-GPU agent workloads

---

## Firecracker

**Repo:** github.com/firecracker-microvm/firecracker
**Language:** Rust | **License:** Apache 2.0

### What It Does Well

- ~125ms boot time
- <5 MiB memory overhead per VM
- Single binary, minimal device model
- KVM-based hardware isolation
- Snapshot/restore (~4ms restore)
- virtio-block, virtio-net, virtio-vsock
- Production-proven: AWS Lambda, Fargate, DSQL

### What It Cannot Do

- **No GPU/PCIe passthrough** — PCIe development paused in 2025 (GitHub discussion #4845)
- No device hotplug (CPU, memory, block devices must be configured before boot)
- No UEFI boot (direct kernel boot only)
- No live migration
- No virtio-fs (block-level only)
- Linux-only (host and guest)

### Running on AWS EC2

| Approach | Instance Types | /dev/kvm | Overhead |
|----------|---------------|----------|----------|
| Bare metal | Any `*.metal` (c5.metal, i3.metal) | Always available | None |
| Nested virtualization (Feb 2026) | C8i, M8i, R8i only | Enabled via flag | ~3% CPU, ~1.8x I/O |

Nested virt must be explicitly enabled:
```bash
aws ec2 run-instances \
    --instance-type m8i.4xlarge \
    --cpu-options "NestedVirtualization=enabled"
```

Bare metal is ~10x more expensive but zero overhead. Nested virt only on 8th-gen Intel — no GPU families.

### EBS as Block Devices

Firecracker's `path_on_host` accepts any path the process can open:

1. **File on mounted EBS**: Attach EBS → mount → put rootfs images → point Firecracker at files
2. **Raw block device**: Pass `/dev/nvme1n1` directly (firecracker-containerd uses device-mapper nodes this way)

Constraint: no hot-plug — all drives must be attached before VM boot.

### Fast Provisioning Strategy

```
EBS Snapshot → EBS Volume → Mount on host
                              |
                              +-- golden-rootfs.ext4 (read-only, shared)
                              +-- firecracker-snapshot-{memory,vmstate}.bin
                              |
                              Per agent VM:
                                dm-snapshot (CoW overlay on golden rootfs)
                                → Firecracker restore from snapshot
                                → Running VM in <10ms
```

This is how Lambda works internally. Block devices are intentionally NOT included in Firecracker snapshots — enables sharing one read-only rootfs across hundreds of clones via device-mapper thin provisioning.

### Production Hardening

- Disable SMT (hyperthreading) — prevents Spectre/MDS side channels
- Disable KSM — prevents memory deduplication side channels
- Always use the `jailer` binary (cgroups, seccomp, namespaces)
- Disable swap — prevents guest memory remnants on disk

---

## Cloud Hypervisor

**Repo:** github.com/cloud-hypervisor/cloud-hypervisor
**Language:** Rust | **License:** Apache 2.0

Same rust-vmm foundation as Firecracker, but adds what Firecracker intentionally left out.

### Comparison with Firecracker

| | Firecracker | Cloud Hypervisor |
|--|------------|-----------------|
| VFIO GPU passthrough | No | **Yes** — NVIDIA Turing through Blackwell |
| CPU/memory hotplug | No | Yes |
| Boot time | ~125ms | ~200ms |
| Codebase | ~50K lines Rust | ~50K lines Rust |
| virtio-fs | No | Yes |
| vGPU | No | Experimental (broken as of late 2025) |
| Device model | 16 devices | Broader (PCI, VFIO, hotplug) |

### Production Users

Ubicloud (swapped Firecracker for CH), Koyeb (via Kata), Cirrus Runners (chose CH for GPU + AVX-512), Northflank (via Kata).

### GPU Passthrough

Full VFIO PCI passthrough. Supports NVIDIA Turing, Ampere, Hopper, Lovelace/Blackwell including GPUDirect P2P DMA over PCIe.

```bash
cloud-hypervisor \
    --kernel vmlinux \
    --disk path=rootfs.ext4 \
    --device path=/sys/bus/pci/devices/0000:04:00.0
```

### AWS Constraint

VFIO GPU passthrough requires **bare metal GPU instances** (g4dn.metal, g5g.metal). Standard GPU instances don't expose IOMMU. Feb 2026 nested virt only covers C8i/M8i/R8i — no GPU families.

---

## NVIDIA GPU Virtualization Options

### Full VFIO Passthrough

- Works with: Cloud Hypervisor, QEMU/KVM, crosvm, Kata
- All NVIDIA datacenter GPUs
- Complete isolation — entire GPU dedicated to one VM
- Limitation: 1 GPU = 1 VM, no sharing

### MIG (Multi-Instance GPU)

- Hardware partitioning into up to 7 isolated instances
- Each instance: dedicated compute, memory, cache, bandwidth
- GPUs: A100, A30, H100, H200, B100, B200 (Ampere, Hopper, Blackwell)
- Pass individual MIG instances through VFIO to separate VMs
- Works with Cloud Hypervisor and QEMU

### vGPU

- Requires NVIDIA vGPU software license ($$$)
- Works with QEMU/KVM (official), VMware, Citrix
- Cloud Hypervisor support experimental/broken
- On Ampere+: uses SR-IOV + time-slicing within each VF

### Time-Slicing

- Container-level only (not VM-level)
- No memory isolation, no fault isolation
- Not suitable for multi-tenant security

### Recommendation

For agent platform with GPU isolation: **MIG + VFIO**. Partition GPU at hardware level, pass MIG slices through VFIO to individual VMs. Hardware isolation per agent, no contention, no shared memory attack surface.

---

## Kata Containers

**Repo:** github.com/kata-containers/kata-containers
**Language:** Go (runtime) + Rust (runtime-rs, agent) | **License:** Apache 2.0

Kata is an **orchestration framework** wrapping VMMs (QEMU, Cloud Hypervisor, Firecracker, Dragonball, StratoVirt). Each container gets its own VM with a dedicated kernel.

### VMM Backends

| VMM | VFIO | virtio-fs | Hotplug | Best For |
|-----|------|-----------|---------|----------|
| QEMU | Yes | Yes | Full | GPU workloads |
| Cloud Hypervisor | Yes | Yes | Full | Modern cloud, lighter than QEMU |
| Firecracker | No | No | No | FaaS, minimal overhead |
| Dragonball | No | Yes | Limited | Out-of-box Kata 3.x |
| StratoVirt | No | Yes | Block only | Enterprise containers |

### Using Kata from Go

#### Path 1: containerd Go Client (Recommended)

```go
import "github.com/containerd/containerd/v2/client"

c, _ := client.New("/run/containerd/containerd.sock")

container, _ := c.NewContainer(ctx, "agent-vm-1",
    client.WithImage(image),
    client.WithNewSnapshot("agent-vm-1-snap", image),
    client.WithRuntime("io.containerd.kata.v2", nil),
    client.WithNewSpec(
        oci.WithAnnotations(map[string]string{
            "io.katacontainers.config.hypervisor.default_vcpus":  "4",
            "io.katacontainers.config.hypervisor.default_memory": "8192",
            "io.katacontainers.config.hypervisor.block_device_driver": "virtio-blk",
        }),
    ),
)

task, _ := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
task.Start(ctx)
```

Benefits: image management, snapshotting, layer distribution handled by containerd. Per-VM config via OCI annotations.

#### Path 2: virtcontainers Directly

```go
import vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"

sandbox, _ := vc.CreateSandbox(ctx, vc.SandboxConfig{
    ID:             "agent-1",
    HypervisorType: vc.QemuHypervisor,
    HypervisorConfig: vc.HypervisorConfig{
        KernelPath: "/usr/share/kata-containers/vmlinux.container",
        ImagePath:  "/usr/share/kata-containers/kata-containers.img",
        MemorySize: 8192,
        NumVCPUs:   4,
    },
    Containers: []vc.ContainerConfig{{
        ID:     "workload",
        RootFs: vc.RootFs{Target: "/path/to/rootfs"},
    }},
}, nil, nil)

sandbox.Start(ctx)
```

Full control over VM lifecycle, device hotplug, networking. You manage images and distribution yourself.

#### Selecting VMM Backend Per-VM

Via containerd runtime handlers:
```go
// GPU workload → QEMU
client.WithRuntime("io.containerd.kata-qemu-nvidia-gpu.v2", nil)

// Lightweight agent → Cloud Hypervisor
client.WithRuntime("io.containerd.kata-clh.v2", nil)
```

Via virtcontainers:
```go
HypervisorType: vc.QemuHypervisor        // GPU
HypervisorType: vc.CloudHypervisorType    // non-GPU
```

### GPU Passthrough Configuration

Host preparation:
```bash
# Enable IOMMU in kernel boot params: intel_iommu=on
# Bind GPU to vfio-pci driver
echo "10de 15f8" > /sys/bus/pci/drivers/vfio-pci/new_id
echo "0000:04:00.0" > /sys/bus/pci/devices/0000:04:00.0/driver/unbind
echo "0000:04:00.0" > /sys/bus/pci/drivers/vfio-pci/bind
```

From Go via containerd:
```go
container, _ := c.NewContainer(ctx, "gpu-agent",
    client.WithRuntime("io.containerd.kata-qemu-nvidia-gpu.v2", nil),
    client.WithNewSpec(
        oci.WithAnnotations(map[string]string{
            "io.katacontainers.config.hypervisor.machine_type":             "q35",
            "io.katacontainers.config.hypervisor.hotplug_vfio_on_root_bus": "true",
            "io.katacontainers.config.hypervisor.pcie_root_port":           "1",
            "io.katacontainers.config.hypervisor.enable_iommu":             "true",
        }),
        oci.WithDevices("/dev/vfio/66", "", "rwm"),
    ),
)
```

### Block Devices / Volumes

```go
oci.WithAnnotations(map[string]string{
    "io.katacontainers.config.hypervisor.block_device_driver":       "virtio-blk",
    "io.katacontainers.config.hypervisor.block_device_cache_direct": "true",
})
```

Filesystem sharing via virtio-fs:
```go
"io.katacontainers.config.hypervisor.shared_fs":       "virtio-fs",
"io.katacontainers.config.hypervisor.virtio_fs_cache": "auto",
```

### Networking

```go
"io.katacontainers.config.runtime.internetworking_model": "tcfilter"
```

- **tcfilter** (default): TC redirect between veth and TAP. Best CNI compatibility.
- **macvtap**: Slightly higher performance, less compatible.

### Sandbox API (virtcontainers)

```go
// Lifecycle
vc.CreateSandbox(ctx, config, factory, hook)
sandbox.Start(ctx)
sandbox.Stop(ctx, force)
sandbox.Delete(ctx)
sandbox.Pause(ctx) / sandbox.Resume(ctx)

// Containers within sandbox
sandbox.CreateContainer(ctx, config)
sandbox.StartContainer(ctx, id)
sandbox.StopContainer(ctx, id, force)
sandbox.EnterContainer(ctx, id, cmd)
sandbox.KillContainer(ctx, id, signal, all)

// Device hotplug
sandbox.AddDevice(ctx, deviceInfo)
sandbox.HotplugAddDevice(ctx, device, deviceType)
sandbox.HotplugRemoveDevice(ctx, device, deviceType)

// Networking
sandbox.AddInterface(ctx, iface)
sandbox.RemoveInterface(ctx, iface)
sandbox.UpdateRoutes(ctx, routes)

// IO and monitoring
sandbox.IOStream(containerID, processID)
sandbox.WaitProcess(ctx, containerID, processID)
sandbox.Stats(ctx)
sandbox.Monitor(ctx)
```

---

## QEMU/KVM (Fallback)

Best GPU compatibility but heaviest:

| | QEMU/KVM | Cloud Hypervisor |
|--|----------|-----------------|
| VFIO | Gold standard | Yes |
| vGPU | Official NVIDIA support | Experimental |
| Boot time | 2-5s (GPU config) | ~200ms |
| Memory overhead | 100s of MiB | ~10-20 MiB |
| Codebase | ~2M lines C | ~50K lines Rust |

Use when Cloud Hypervisor's VFIO falls short for specific GPU models/drivers. Kata uses QEMU as the backend for `kata-qemu-nvidia-gpu` runtime class.

Note: QEMU `microvm` machine type gets sub-200ms boot but **lacks PCI** — cannot do GPU passthrough. Must use `q35` or `pc` machine types for GPU.

---

## Other VMMs Evaluated

| VMM | GPU | Verdict |
|-----|-----|---------|
| **crosvm** | VFIO works | Built for Chrome OS, not cloud workloads |
| **libkrun** | Linux GPU not ready | Interesting future, not production-ready |
| **Dragonball** | No GPU | Kata 3.x built-in, no passthrough |
| **ACRN** | Intel iGPU only | IoT/automotive, not datacenter |
| **Slicer** | Via Cloud Hypervisor | Early-stage, reference implementation |

---

## Architecture Decision: Dual-VMM via Kata

Use Kata Containers as the orchestration layer with two VMM backends:

```
Platform (Go)
    |
    v
containerd Go Client
    |
    +-- io.containerd.kata-clh.v2          → Cloud Hypervisor (non-GPU agents)
    |     ~200ms boot, minimal overhead
    |
    +-- io.containerd.kata-qemu-nvidia-gpu.v2  → QEMU (GPU agents)
          Full VFIO, MIG support
```

Benefits:
- Single API (containerd) for both VM types
- Image management handled by containerd
- Per-VM VMM selection via runtime handler
- MIG + VFIO for GPU sharing with hardware isolation
- virtcontainers available as escape hatch for advanced VM ops

---

## MCP Integration Notes

### HTTP MCP Auth

The MCP spec says auth is **OPTIONAL**. Claude Code specifically defaults to attempting OAuth 2.0 Dynamic Client Registration for HTTP MCP servers.

Workaround — add dummy auth header:
```json
{
  "mcpServers": {
    "my-server": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer local"
      }
    }
  }
}
```

Or use stdio-to-HTTP bridges for legacy clients.

### HTTP over UDS

Not supported by Claude Code. The `url` field only accepts `http://` / `https://`. Bridge with socat if needed:
```bash
socat tcp-listen:9999,fork unix-connect:/tmp/service.sock
```

For the platform itself, UDS is useful for same-VM agent-to-sidecar communication. The MCP spec is transport-agnostic — custom transports are explicitly allowed.

### Transport Recommendations

| Scenario | Transport |
|----------|-----------|
| Agent on VM → forge MCP endpoint | HTTP with token auth |
| Same-VM sidecar communication | UDS (custom transport) |
| Local dev with Claude Code | stdio bridge or dummy auth header |

---

## AWS Deployment Summary

| Component | Instance Type | Notes |
|-----------|--------------|-------|
| Non-GPU agent VMs | c5.metal or m8i.* (nested virt) | Cloud Hypervisor via Kata |
| GPU agent VMs | g4dn.metal or g5g.metal | QEMU via Kata, VFIO passthrough |
| Git forge (Combine) | Any instance | Standard Go binary |
| Chat service | Any instance | Standard Go binary |

Bare metal for production multi-tenant. Nested virt (C8i/M8i/R8i) for dev/test at ~10x lower cost.
