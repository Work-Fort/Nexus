# Clustering Design Progress

Feature #21 (Phase 1: Pairing & Node Discovery) design brainstorming is in progress.
Six sections were presented and approved on 2026-03-16. The spec file has NOT been
written yet — next step is to write it, run the review loop, and get sign-off.

Clustering is being designed as 5 separate features (#21–#25), one per phase. All 5
designs will be written sequentially, then plans, then implementation.

## Approved Design Sections

### 1. Domain Model

- `NodeInfo`: ID (nxid), Name, APIAddr, Zone, Version
- `DiscoveredNode`: NodeInfo + Source (mdns/aws/gcp/manual)
- `CSRApproval`: CSR bytes + Zone assignment
- Node states: Standalone → Initialized → Pairing → Member
- Initialized = cluster founder (has CA cert + own cert, gossip listening)

### 2. Discovery Port & Adapters

- `NodeDiscovery` interface: `Advertise()`, `Browse(onFound, onLost)`, `Stop()`
- Three adapters: mdns (brutella/dnssd), aws (EC2 tags), gcp (instance labels)
- Switchable via `--discovery-backend=mdns|aws|gcp`
- Manual join (`nexus cluster join <addr>`) bypasses discovery entirely

### 3. PKI & Certificate Authority

- CSR-based joining is the PRIMARY authorization mechanism (not tokens)
- Node submits CSR (no zone info) → admin approves with zone assignment
- Signed cert includes zone in OU field
- Zone is IMMUTABLE for the lifetime of the cert — to change zone, re-join
- Single root CA per cluster (zone intermediates deferred to future phase)
- CA files in `$NEXUS_DATA_DIR/cluster/` (ca.key, ca.crt, node.key, node.crt, pending/*.csr)
- Three security tiers via `--cluster-csr-mode`: network (default), auto-accept, offline
- Cert revocation: remove node from cluster, add serial to local blocklist

### 4. Gossip Membership

- hashicorp/memberlist (SWIM protocol) for post-join communication
- GossipMeta (≤512 bytes): NodeID, APIAddr, Zone, Version, State (ready/draining/leaving)
- Gossip starts on `cluster init`, always active once clustered
- Port 9401 (configurable), separate from HTTP API on 9400
- Graceful leave via `memberlist.Leave()`, SWIM failure detection for crashes (~5s)
- In Phase 2 (WireGuard), gossip traffic routes over encrypted tunnel automatically

### 5. API & CLI

**New endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/cluster/init` | POST | Bootstrap cluster: create CA, issue first cert, start gossip |
| `/v1/cluster/status` | GET | Cluster state: node list, this node's role, zone |
| `/v1/cluster/discover` | GET | List nodes found via discovery (pending, not yet joined) |
| `/v1/cluster/join` | POST | Joining node submits CSR + node info |
| `/v1/cluster/approve/{id}` | POST | Admin approves pending CSR, assigns zone |
| `/v1/cluster/reject/{id}` | DELETE | Admin rejects pending CSR |
| `/v1/cluster/nodes/{id}` | DELETE | Remove a member from the cluster |
| `/v1/cluster/ca` | GET | Download the cluster CA cert (public) |

**CLI:** `nexusctl cluster {init, discover, approve, reject, join, status, nodes, remove}`

**Daemon flags:** `--discovery-backend`, `--cluster-csr-mode`, `--gossip-port`

**MCP tools** mirror the REST endpoints.

### 6. Package Layout

```
internal/domain/
  ports.go              — add NodeDiscovery interface
  cluster.go            — NodeInfo, DiscoveredNode, CSRApproval, GossipMeta types

internal/app/
  cluster_service.go    — orchestrates init, join, approve, gossip lifecycle

internal/infra/cluster/
  pki/
    ca.go               — CA creation, cert signing, CSR handling
  gossip/
    gossip.go           — memberlist wrapper, metadata encoding, event callbacks
  discovery/
    mdns.go             — mDNS adapter (brutella/dnssd)
    aws.go              — AWS EC2 tag discovery
    gcp.go              — GCP instance label discovery
    noop.go             — NoopDiscovery for standalone mode

internal/infra/httpapi/
  cluster_handlers.go   — handler implementations

cmd/
  daemon.go             — wire discovery backend, cluster service, gossip port
```

- VMService is UNAWARE of clustering in Phase 1. ClusterService is a peer, not a dependency.
- Standalone mode (no `cluster init`) = ClusterService nil → 404 for cluster endpoints.

## Key Architecture Decisions

- **5 features, sequential designs**: #21 pairing, #22 WireGuard, #23 Raft, #24 scheduling, #25 drive mobility
- **Federated zones**: each zone is autonomous with its own Raft group (Phase 3)
- **Planet-scale tolerance**: architecture must not preclude hours of latency or months of disconnection between zones
- **Zone owns local state**: region/global level handles cross-zone coordination, not VM metadata
- **Approach A chosen**: Discovery port (hexagonal) + ClusterService, not monolithic cluster package

## Phase Overview (Features #21–#25)

| Feature | Phase | Scope |
|---------|-------|-------|
| #21 | Pairing & Discovery | mDNS/AWS/GCP discovery, CSR joining, PKI, gossip |
| #22 | Encrypted Transport | WireGuard tunnels, keypair generation, peer management via wgctrl-go |
| #23 | Replicated State | Embedded Raft, SQLite FSM, zone-local consensus groups |
| #24 | Scheduling | Constraint-based on leader, device/drive affinity, resource capacity |
| #25 | Drive Mobility | BlockDeviceProvider port, cloud adapters, btrfs send/receive replication |
