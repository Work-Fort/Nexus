# Clustering Research

Research into multi-node Nexus: networking, encryption, state replication,
scheduling, and storage. This document captures options and trade-offs to
inform the clustering design.

## Current Architecture

Single-node daemon. SQLite via `modernc.org/sqlite` (pure Go). Hexagonal
ports-and-adapters: `VMStore`, `DriveStore`, `DeviceStore`, `TemplateStore`,
`SnapshotStore` are all interfaces in `internal/domain/ports.go`. Btrfs
adapter for drives. CNI for networking. Containerd + Kata for VM runtime.

The hexagonal architecture is the key enabler for clustering — each concern
(state replication, drive storage, scheduling) becomes a new adapter behind
an existing port or a new port entirely.

---

## 1. Node-to-Node Networking

### Overlay Protocols

| Protocol | Encryption | Overhead | Kernel Support | Used By |
|----------|-----------|----------|----------------|---------|
| VXLAN | None | ~50 bytes/pkt | Native | Flannel, Calico, Docker Swarm |
| Geneve | None | ~50+ bytes/pkt | Native | OVN-Kubernetes, Antrea |
| WireGuard | ChaCha20-Poly1305 | ~60 bytes/pkt | Native (5.6+) | Cilium, Calico, Flannel |
| IPsec | AES/ChaCha | 50-73 bytes/pkt | Native | Docker Swarm, Cilium |

VXLAN is the most deployed but has no encryption. Geneve is VXLAN's successor
with extensible headers. WireGuard combines encapsulation and encryption in
~4,000 lines of kernel code with the best throughput of any option.

### nftables

The ecosystem is migrating from iptables to nftables:
- kube-proxy nftables mode heading to GA (Kubernetes 1.33+)
- IPVS mode deprecated in Kubernetes 1.35
- Calico v3.31: nftables dataplane GA
- Docker Engine 29: experimental nftables support
- RHEL 10 will remove iptables entirely

Key advantages over iptables:
- **Atomic incremental updates** (no global lock, no full-ruleset reload)
- **O(1) set/map lookups** vs O(n) linear rule traversal
- **Unified** IPv4/IPv6/ARP syntax
- Better rule organization with tables/chains/sets

Nexus currently uses CNI which delegates to whatever the host provides.
For clustering, nftables-native rules for inter-node traffic and VM
network policy would be the forward-looking choice.

### Same L2 vs Cross L3/WAN

**Same L2 network:**
- Can skip overlay entirely (direct routing or BGP)
- Simplest setup, best performance
- Broadcast/ARP storms at scale (100+ nodes)

**Cross L3/WAN:**
- Requires overlay or tunnel
- Latency is the dominant concern
- Encryption becomes critical (untrusted network)
- MTU path discovery matters

**Recommendation:** Design for L3 from the start even if nodes are initially
on the same L2. Use WireGuard tunnels between all nodes regardless of
topology — this gives encryption for free and avoids a painful migration
when nodes span networks.

---

## 2. Inter-Node Encryption

| Property | WireGuard | IPsec | mTLS |
|----------|-----------|-------|------|
| Layer | L3 (network) | L3 (network) | L7 (application) |
| FIPS compliant | No | Yes | Yes |
| Throughput | Best | Good | Worst |
| Latency | Lowest | Low-Medium | Medium-High |
| Granularity | Node-to-node | Node-to-node | Service-to-service |
| Key management | Static keypairs | Complex (IKE/SA) | PKI/CA infrastructure |
| Complexity | ~4K lines kernel | Large kernel subsystem | Proxy runtime |

**Recommendation: WireGuard.** Best throughput, lowest complexity, in-kernel.
Controllable from Go via `wgctrl-go` (programmatic interface creation, peer
management, key exchange). Not FIPS-compliant, but that's not a Nexus concern.

Each Nexus node generates a WireGuard keypair on first run. Public keys are
exchanged via the gossip protocol (see section 4). All inter-node traffic
flows over WireGuard tunnels automatically.

---

## 3. Service Mesh: Not Needed

Every major service mesh requires Kubernetes:
- **Istio** — K8s only, heavy (25-50 GB extra memory at scale)
- **Linkerd** — K8s only, lightweight but still requires K8s
- **Cilium Service Mesh** — eBPF-based, effectively K8s-tied

**Consul Connect** is the only mesh that works with VMs, but it requires
3-5 Consul servers + an agent on every node. Disproportionate for 2-50 nodes.

The problems a mesh solves are better addressed by simpler mechanisms:

| Problem | Mesh Solution | Nexus Solution |
|---------|--------------|----------------|
| Service discovery | Mesh control plane | Embedded gossip (memberlist) |
| Encryption | mTLS via sidecar proxies | WireGuard tunnels |
| Traffic management | Envoy/proxy rules | Not needed at this scale |
| Observability | Distributed tracing | Prometheus scraping (already built) |

---

## 4. Cluster State and Consensus

### External vs Embedded

| Approach | External Deps | Operational Burden | Fit |
|----------|--------------|-------------------|-----|
| Consul cluster | 3-5 servers + agents | High | Poor |
| etcd cluster | 3-5 servers | High | Poor |
| rqlite | Separate process, HTTP API | Medium | Poor |
| dqlite | CGo, patched SQLite | Medium (build complexity) | Risky |
| **Embedded Raft + SQLite** | **None** | **None** | **Best** |

**rqlite** wraps SQLite with Raft over HTTP — but it's a separate process,
not embeddable as a library. Loses the single-binary advantage.

**dqlite** (Canonical) is embeddable and provides a `database/sql`-compatible
driver, but requires CGo, a patched SQLite, and is Linux-only. Kills the
pure-Go build that `modernc.org/sqlite` provides.

### Recommended: Nomad's Pattern

Nomad embeds both Raft (consensus) and Serf (gossip) directly in a single
binary. Zero external dependencies. This is the right pattern for Nexus.

**hashicorp/raft** is the obvious library choice:
- Batteries-included: manages transport, log storage, snapshots
- Used by Nomad, Consul, Vault
- Simplest Go integration of the three mature options (vs etcd/raft which
  requires you to implement transport and I/O, or dragonboat which is
  multi-group Raft and more complex than needed)

### How It Works

```
API Request → Leader Server → raft.Apply(mutation)
                                    │
                              Replicated to quorum
                                    │
                              FSM.Apply(log entry)
                                    │
                              SQL executed against local SQLite
```

- **Writes** go through `raft.Apply()`. The leader serializes the SQL
  mutation, replicates to quorum, then each node's FSM applies it to
  its local SQLite database.
- **Reads** go directly to local SQLite (eventually consistent). For a
  VM orchestrator this is fine — you're reading "what VMs exist" which
  changes slowly relative to read frequency.
- **Snapshots** serialize the entire SQLite database file. On restore,
  replace the local database and replay subsequent log entries.

### Gossip for Membership (memberlist)

HashiCorp's `memberlist` implements the SWIM protocol for cluster membership
and failure detection among **already-joined** nodes. Each node periodically
pings random peers; failures are detected via indirect probing.

Node metadata (up to 512 bytes) carries API address, WireGuard public key,
available resources, and VM count. Delegate callbacks fire on join/leave/update.

Memberlist is for **post-join** communication, not discovery. Discovery of
new nodes is handled by the pairing system (see section 4.5).

### Node Discovery: Pairing Mode (mDNS)

New nodes don't auto-join a cluster. Instead, they enter **pairing mode** —
an explicit state where they broadcast availability via mDNS and wait for
an administrator on an existing cluster to accept them.

#### The Flow

```
┌─────────────────┐                        ┌─────────────────┐
│   NEW NODE       │                        │ EXISTING CLUSTER │
│   (pairing mode) │                        │ (running)        │
├──────────────────┤                        ├──────────────────┤
│                  │                        │                  │
│ 1. Boot / config │                        │                  │
│    says "pair"   │                        │                  │
│                  │                        │                  │
│ 2. Broadcast     │ ── mDNS ──────────►   │ 3. Browse sees   │
│    _nexus._tcp   │    (LAN-only)          │    pending node  │
│    status=pairing│                        │                  │
│                  │                        │ 4. Admin reviews  │
│                  │                        │    in dashboard   │
│                  │                        │                  │
│                  │   ◄── HTTPS ────────── │ 5. Admin clicks  │
│                  │      join request      │    "Accept Node" │
│                  │      + join token      │                  │
│                  │                        │                  │
│ 6. Validate token│                        │                  │
│    Submit CSR    │ ── HTTPS ──────────►   │ 7. Issue cert    │
│                  │                        │    Add to Raft   │
│                  │                        │    Add WireGuard  │
│                  │                        │    peer          │
│ 8. Join cluster  │                        │                  │
│    Stop mDNS     │                        │                  │
│    Start gossip  │                        │                  │
└──────────────────┘                        └──────────────────┘
```

#### Node States

| State | mDNS | Gossip | Raft | Description |
|-------|------|--------|------|-------------|
| **Standalone** | Off | Off | Off | Default. Single-node Nexus, not clustered. |
| **Pairing** | Broadcasting | Off | Off | Waiting for a cluster to accept it. |
| **Joining** | Off | Off | Off | Token validated, exchanging certs. |
| **Member** | Off | Active | Active | Fully joined cluster member. |

A node enters pairing mode via:
- Interactive setup: `nexus cluster pair` (blocks until accepted)
- Configuration: `pairing-mode: true` in config file (for automated provisioning)
- CLI flag: `nexus daemon --pairing-mode`

#### mDNS Service Advertisement

In pairing mode, the node broadcasts a `_nexus._tcp.local.` DNS-SD service:

```
Instance: nexus-<node_id_prefix>._nexus._tcp.local.
SRV:      <hostname>:9400
TXT:      node_id=<id>
          version=<daemon_version>
          status=pairing
          hostname=<hostname>
          api_port=9400
```

The `status=pairing` field is what distinguishes a node seeking a cluster
from an existing cluster member. No join token or cluster ID is broadcast —
the new node doesn't know what cluster it will join yet.

Once the node is accepted and joins the cluster, it **stops mDNS** and
transitions to gossip (memberlist) for ongoing cluster communication.

#### Existing Cluster: Browsing for Nodes

An existing cluster continuously browses for `_nexus._tcp` services with
`status=pairing`. Discovered nodes appear as "pending" in the cluster's
node list, visible to administrators.

The cluster itself may also advertise via mDNS (with `status=active` and
its `cluster_id`) so that tools and dashboards can auto-discover the
cluster API endpoint on the LAN.

#### Security: Join Tokens

Pairing mode is **discovery only** — being discoverable does not grant
cluster access. Authorization requires a pre-shared join token:

1. Admin generates a token on the cluster: `nexus cluster token create`
   - Token format: `nexus-<base32-random>` (e.g., `nexus-ABCDEF...`)
   - Tokens are short-lived (configurable TTL, default 24 hours)
   - Tokens can be single-use or multi-use
2. Admin clicks "Accept Node" in the dashboard (or runs `nexus cluster accept <node_id>`)
3. Cluster sends the join token to the new node over HTTPS
4. New node validates the token, generates a TLS keypair, submits a CSR
5. Cluster signs the CSR, returns the certificate + CA cert + peer list
6. Node joins memberlist and Raft using the issued certificate

For cross-network joining (when mDNS doesn't work), manual join is the
fallback: `nexus cluster join <cluster_addr> --token <token>`.

#### Go Library: brutella/dnssd

**Recommended: [`brutella/dnssd`](https://github.com/brutella/dnssd)** (MIT).

| Library | Maintained | Add/Remove Callbacks | TXT Format | RFC Compliance |
|---------|-----------|---------------------|------------|----------------|
| hashicorp/mdns | Moderate (45 issues) | No (one-shot query) | `[]string` | Partial |
| grandcat/zeroconf | **Stale** (2023) | No | `[]string` | Good |
| **brutella/dnssd** | **Active** (7 issues, Feb 2026) | **Yes** | `map[string]string` | **Best** (passes Apple conformance) |

Key features for Nexus:
- `dnssd.LookupType(ctx, "_nexus._tcp", addFn, removeFn)` — continuous
  browsing with callbacks when nodes appear/disappear
- `ServiceHandle.UpdateText()` — update TXT records live (status changes)
- Context-based cancellation — clean shutdown
- Hot-plug support — handles network interface changes

#### API Endpoints

**New node (pairing mode):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /v1/pairing/status` | GET | Returns node info + pairing state |
| `POST /v1/pairing/accept` | POST | Cluster sends join token to this node |

**Existing cluster:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /v1/cluster/nodes` | GET | List all nodes (members + pending) |
| `GET /v1/cluster/discover` | GET | List nodes found via mDNS browse |
| `POST /v1/cluster/accept` | POST | Admin accepts a pending node (sends token) |
| `POST /v1/cluster/token` | POST | Generate a new join token |
| `DELETE /v1/cluster/nodes/{id}` | DELETE | Remove a node from the cluster |

**Cross-network (manual join):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /v1/cluster/join` | POST | Node submits join token + CSR to cluster |

#### mDNS Limitations

mDNS is strictly L2 (same broadcast domain). It does not cross routers or
VLANs. For cross-network scenarios:
- **Manual join** with a token is the fallback
- **DNS-SD over unicast DNS** is a future option (publish SRV/TXT records
  in a conventional DNS zone)
- **Cloud auto-join** via instance tags (AWS, GCP) could be added later

---

## 5. VM Scheduling

### Strategies

| Strategy | Description | Complexity | Best For |
|----------|------------|-----------|---------|
| Random | Pick any node with capacity | Trivial | Even workloads |
| Round-Robin | Sequential distribution | Trivial | Homogeneous nodes |
| Least-Loaded | Most available resources | Low | Heterogeneous nodes |
| First-Fit | First node satisfying constraints | Low | Constraint-heavy |
| Bin Packing | Pack onto fewest nodes | Medium | Cost optimization |
| Spread | Distribute across failure domains | Medium | High availability |

### Nexus-Specific Constraints

1. **Device affinity (hard):** VMs with device passthrough must land on the
   node that has the physical device. Non-negotiable.
2. **Drive locality (hard):** VMs with attached btrfs drives must run on
   the node that has the drive's subvolume, unless drive migration or
   network storage is available.
3. **Resource capacity (hard):** Node must have sufficient CPU, memory, disk.
4. **Spread (soft):** Prefer distributing across nodes for isolation.

### Recommended Approach

**Phase 1 — Constraint-based first-fit:** Filter nodes by hard constraints
(has device, has drive, has enough resources). Pick the first feasible node.

**Phase 2 — Resource-aware scoring:** Among feasible nodes, prefer
least-loaded (spread strategy). Better than bin packing for developer
environments where workload isolation matters more than density.

**Phase 3 — Affinity labels:** Allow users to express placement preferences
via VM tags (which Nexus already supports).

### How Nomad Does It

For reference, Nomad's scheduling pipeline:

1. **Evaluation** — triggered by job submit or node state change
2. **Eval broker** — priority queue on the leader (single broker prevents
   double-scheduling)
3. **Feasibility check** — filter nodes by resources, constraints, datacenter
4. **Ranking** — bin-packing score normalized to 0-1 across resource
   dimensions
5. **Plan submission** — proposed allocations sent to leader
6. **Conflict resolution** — optimistic concurrency; conflicting plans
   rejected and retried with fresh state

This full pipeline is overengineered for Nexus's near-term scale but the
structure is instructive: separate "what needs to happen" from "where to
put it" from "make it happen."

---

## 6. Drive Replication and Cloud Storage

### The Port

The hexagonal architecture makes this clean. The `DriveStore` port doesn't
care what backs the storage. Today: btrfs adapter on local disk. Tomorrow:

| Environment | Block Device | Filesystem | Adapter |
|-------------|-------------|------------|---------|
| Bare metal (local) | Local NVMe/SSD | btrfs | Existing btrfs adapter |
| AWS | EBS volume | btrfs | Existing btrfs adapter |
| GCP | Persistent Disk | btrfs | Existing btrfs adapter |
| Azure | Managed Disk | btrfs | Existing btrfs adapter |
| Bare metal (replicated) | Longhorn-style | btrfs | Existing btrfs adapter |

Since EBS, GCP Persistent Disk, and Azure Managed Disks all present as
standard block devices, and all will run btrfs, the existing btrfs drive
adapter works unchanged. Subvolume operations (create, snapshot, send/receive)
are filesystem-level and agnostic to the underlying block device.

### What's New: Block Device Management

The new concern is **attaching the right block device to the right node**.
This is orthogonal to the drive store — it's a separate port:

```
BlockDeviceProvider (new port)
├── LocalProvider      — noop (devices already attached)
├── EBSProvider        — AWS API: attach/detach EBS volumes to EC2 instances
├── GCPDiskProvider    — GCP API: attach/detach Persistent Disks to VMs
└── LonghornProvider   — Longhorn API: replicate and attach volumes
```

The flow for VM creation with a drive on a remote node:

1. Scheduler picks target node (considering drive locality as soft
   constraint if block device is movable)
2. `BlockDeviceProvider.Attach(volume, targetNode)` — makes the block
   device available on the target node
3. Existing `DriveStore` (btrfs adapter) operates on the now-local device

For cloud environments, this is straightforward API calls. For on-prem
without network storage, drive locality becomes a hard scheduling constraint
(VM must run where its drive physically is) unless we add replication.

### On-Prem Replication (Longhorn-Style)

For bare-metal clusters that need drive mobility across nodes, the options:

- **Longhorn** — block-level replication over iSCSI, built on local disks.
  Each volume has configurable replica count. Replicas sync via TCP.
  Kubernetes-native but the engine is a standalone binary.
- **btrfs send/receive** — Nexus already uses this for backup/restore
  (feature #4). Could be extended for async replication between nodes.
  Lower-level than Longhorn but avoids an external dependency.
- **DRBD** — kernel-level block device replication. Mature, fast,
  synchronous or async. Heavier integration.

For Nexus, leveraging the existing btrfs send/receive for drive replication
would be the most natural fit — the code already exists for backup/restore
and just needs a network transport layer.

---

## 7. Implementation Phases

### Phase 1: Pairing and Node Discovery

- **Pairing mode**: new node broadcasts `_nexus._tcp` via mDNS (`brutella/dnssd`)
- **Browse endpoint**: existing cluster discovers pairable nodes on the LAN
- **Accept flow**: admin approves node, cluster sends join token over HTTPS
- **Token exchange**: node validates token, submits CSR, receives signed cert
- **Join**: node joins `hashicorp/memberlist` gossip pool with its new cert
- **Cross-network fallback**: `nexus cluster join <addr> --token <token>`
- New API endpoints: pairing status, discover, accept, token management
- New CLI: `nexus cluster pair`, `nexus cluster accept`, `nexus cluster token create`
- New daemon flag: `--pairing-mode`

### Phase 2: Encrypted Transport

- Generate WireGuard keypair on first run (stored in data dir)
- Exchange public keys via memberlist metadata
- Auto-configure WireGuard peers on node join/leave via `wgctrl-go`
- All inter-node API calls route over WireGuard interface
- No external VPN infrastructure

### Phase 3: Replicated State

- Embed `hashicorp/raft` for server nodes (3 or 5)
- FSM applies SQL mutations to local SQLite
- Reads: direct to local SQLite (stale/fast)
- Writes: through `raft.Apply()` (consistent/replicated)
- Snapshots: serialize SQLite database file
- Single-node remains valid (Raft cluster of 1)

### Phase 4: Scheduling

- Constraint-based scheduler on the leader
- Hard constraints: device affinity, drive locality, resource capacity
- Soft constraints: spread across nodes
- VM creation forwarded to leader, leader picks target node
- Optimistic concurrency for conflict resolution

### Phase 5: Drive Mobility

- `BlockDeviceProvider` port for attach/detach
- Cloud adapters: EBS, GCP Persistent Disk (thin API wrappers)
- On-prem: btrfs send/receive over WireGuard for async replication
- Drive locality becomes a soft constraint when drives are movable

### What Changes in the Codebase

The port interfaces in `internal/domain/ports.go` **do not change** for
phases 1-3. The storage adapters gain a Raft wrapper for writes. New types:

- `internal/infra/cluster/` — memberlist, WireGuard, Raft lifecycle
- `internal/infra/cluster/fsm.go` — Raft FSM wrapping SQLite mutations
- `internal/domain/ports.go` — new `BlockDeviceProvider` port (phase 5)
- `cmd/daemon.go` — `--cluster-init`, `--join`, `--server`/`--agent` flags

The `VMService` gains cluster awareness for scheduling but its core
domain logic stays the same. The single-binary, zero-dependency philosophy
is preserved throughout.

---

## Key Libraries

| Library | Purpose | License |
|---------|---------|---------|
| [brutella/dnssd](https://github.com/brutella/dnssd) | mDNS/DNS-SD for pairing mode discovery | MIT |
| [hashicorp/memberlist](https://github.com/hashicorp/memberlist) | Gossip/SWIM cluster membership (post-join) | MPL-2.0 |
| [hashicorp/raft](https://github.com/hashicorp/raft) | Consensus / replicated state | MPL-2.0 |
| [WireGuard/wgctrl-go](https://github.com/WireGuard/wgctrl-go) | Programmatic WireGuard control | MIT |

All are pure Go, well-maintained, and used in production by major
infrastructure projects.
