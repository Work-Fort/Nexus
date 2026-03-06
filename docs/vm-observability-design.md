# VM Observability Design

Approved design for feature #12 from `docs/remaining-features.md`.

## Summary

In-VM metrics via node_exporter, bind-mounted from the host and exec-started
after each VM boots. Prometheus scrapes VMs directly over the CNI bridge.
Nexus exposes an HTTP service discovery endpoint so Prometheus knows which
VMs exist and their IPs.

## Node Exporter Provisioning

**Host binary path:** Configurable via `metrics.node-exporter-path` (default
`/opt/nexus/bin/node_exporter`). If the path doesn't exist at startup, Nexus
logs a warning and disables metrics provisioning for all VMs.

**Bind mount:** During `recreateContainer`, if the node_exporter host path
exists, add a read-only bind mount:

```
host: /opt/nexus/bin/node_exporter → container: /usr/local/bin/node_exporter (ro)
```

**Exec start:** After `StartVM` succeeds, fire a background goroutine that
execs node_exporter inside the VM:

```go
go func() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    s.runtime.Exec(ctx, vm.ID, []string{
        "/usr/local/bin/node_exporter",
        "--web.listen-address=:9100",
        "--collector.disable-defaults",
        "--collector.cpu",
        "--collector.meminfo",
        "--collector.diskstats",
        "--collector.filesystem",
        "--collector.loadavg",
        "--collector.netdev",
    })
}()
```

Fire-and-forget — if it fails, log a warning. Minimal collector set keeps
the scrape payload small.

## Prometheus HTTP Service Discovery

`GET /v1/prometheus/targets` returns Prometheus HTTP SD format. Only
includes running VMs with an assigned IP.

```json
[
  {
    "targets": ["10.88.0.2:9100"],
    "labels": {
      "__meta_nexus_vm_id": "abc123",
      "__meta_nexus_vm_name": "my-agent",
      "__meta_nexus_vm_state": "running",
      "__meta_nexus_vm_tag_agent": "true",
      "__meta_nexus_vm_tag_dev": "true"
    }
  }
]
```

Each VM tag becomes a `__meta_nexus_vm_tag_<tagname>: "true"` label.
Prometheus relabeling rules can filter or group by tag:

```yaml
scrape_configs:
  - job_name: nexus-vms
    http_sd_configs:
      - url: http://localhost:9600/v1/prometheus/targets
    relabel_configs:
      - source_labels: [__meta_nexus_vm_tag_agent]
        regex: "true"
        action: keep
```

## Configuration

Three config keys under `metrics`:

```yaml
metrics:
  node-exporter-path: /opt/nexus/bin/node_exporter
  listen-port: 9100
  collectors:
    - cpu
    - meminfo
    - diskstats
    - filesystem
    - loadavg
    - netdev
```

- **`metrics.node-exporter-path`** — Host path to node_exporter binary. If
  absent, metrics provisioning is disabled. Default:
  `/opt/nexus/bin/node_exporter`.
- **`metrics.listen-port`** — Port node_exporter listens on inside each VM.
  Used by the HTTP SD endpoint to construct target addresses. Default: `9100`.
- **`metrics.collectors`** — Enabled collector names. Passed as
  `--collector.disable-defaults` + `--collector.<name>` flags. Default: cpu,
  meminfo, diskstats, filesystem, loadavg, netdev.

All optional — zero config if the binary is at the default path.

## Testing

**Unit tests:**
- `StartVM` bind-mounts node_exporter when host path exists
- `StartVM` skips bind-mount when host path doesn't exist
- `StartVM` fires exec after start when metrics enabled
- Prometheus targets endpoint returns correct JSON for running VMs with IPs
- Prometheus targets endpoint excludes stopped VMs and VMs without IPs
- Prometheus targets endpoint includes tag labels

**E2E tests:**
- Start VM, hit `GET /v1/prometheus/targets`, verify VM appears with correct
  IP and port
- Stop VM, verify it disappears from targets
- Verify node_exporter is listening: exec `curl -s http://localhost:9100/metrics`
  inside the VM, check for Prometheus text format output
