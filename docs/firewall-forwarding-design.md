# Automatic Firewall Forwarding for VM Networking

## Problem

CNI's bridge plugin with `ipMasq: true` handles NAT (masquerading) for
outbound VM traffic, but does not add FORWARD chain rules. Host firewalls
like UFW and firewalld set the default FORWARD policy to DROP, which blocks
all VM TCP/UDP traffic while ICMP passes (since many firewalls allow ICMP
by default).

This means VMs can ping external hosts but cannot reach any TCP/UDP service
(DNS, HTTP, etc.) on systems with a host firewall active.

## Solution

Add automatic firewall forwarding rules to `nexus-cni-exec`. Rules are
applied when the daemon initializes networking and removed on shutdown.

### Why iptables, Not Native nftables

In nftables, multiple base chains can attach to the same netfilter hook.
An ACCEPT verdict in one chain is **not terminal** — the packet continues
to the next chain. Only DROP is terminal. This means creating a separate
`table inet nexus` with ACCEPT rules would NOT bypass UFW/firewalld's
DROP in their own chain.

The `iptables` command (whether legacy or `iptables-nft` backed) inserts
rules into the **same chain** as UFW/firewalld. An ACCEPT within a single
chain IS terminal (it skips remaining rules in that chain). This is what
Docker, podman, and CNI itself use for container networking.

Using `coreos/go-iptables` works on both legacy iptables AND nftables
systems via the `iptables-nft` compatibility layer.

### Matching the Firewall Backend

Critical: `iptables-legacy` and `iptables-nft` operate on **separate
netfilter hook registrations**. Rules added via one don't affect the other.
An ACCEPT in the nft filter table does NOT prevent a DROP in the legacy
xtables filter table (and vice versa).

We must use the same backend as the host firewall. The code tries the
system default `iptables` first (which matches whatever the firewall uses),
falling back to `iptables-nft` only if the default fails. Legacy iptables
requires `CAP_NET_RAW` for raw socket access; `iptables-nft` only needs
`CAP_NET_ADMIN`.

### Architecture

**Where:** New subcommands in `nexus-cni-exec`:

- `setup-forwarding <bridge>` — add FORWARD rules
- `teardown-forwarding <bridge>` — remove FORWARD rules

**When:** Called by the daemon via `internal/infra/cni/network.go`:

- `New()` calls `setup-forwarding` at daemon start
- `Close()` calls `teardown-forwarding` at daemon shutdown

**How:** `coreos/go-iptables` Go library (wraps iptables binary).

### Firewall Rules

Creates two chains in the filter table:

**NEXUS-FORWARD** — VM ↔ internet (forwarded traffic):

```
-N NEXUS-FORWARD
-A NEXUS-FORWARD -i nexus0 -j ACCEPT
-A NEXUS-FORWARD -o nexus0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-I FORWARD 1 -j NEXUS-FORWARD
```

**NEXUS-INPUT** — VM → host services (DNS, API):

```
-N NEXUS-INPUT
-A NEXUS-INPUT -i nexus0 -j ACCEPT
-I INPUT 1 -j NEXUS-INPUT
```

Both inserted at position 1, running before UFW/firewalld rules.

### Teardown

```
-D FORWARD -j NEXUS-FORWARD
-F NEXUS-FORWARD
-X NEXUS-FORWARD
-D INPUT -j NEXUS-INPUT
-F NEXUS-INPUT
-X NEXUS-INPUT
```

### Properties

- **Idempotent:** safe to call setup/teardown multiple times
- **Clean:** own chain, no interference with existing rules
- **No new binaries:** extends existing `nexus-cni-exec`
- **Capabilities:** `CAP_NET_ADMIN` (already present) + `CAP_NET_RAW` (added for legacy iptables)

## Cleanup: Remove `nexus setup`

The `nexus setup` command group (`cmd/setup.go`) is obsolete:

- `btrfs-quotas` is handled automatically by `nexus-quota` (see line 67
  comment in `cmd/nexus-quota/main.go`)
- Firewall will be handled automatically by `nexus-cni-exec`

Remove `cmd/setup.go` and the `newSetupCmd()` registration from `cmd/root.go`.

## Integration

```
Daemon start
  └─ cni.New()
       └─ nexus-cni-exec setup-forwarding nexus0
            └─ go-iptables: create NEXUS-FORWARD chain

Daemon stop
  └─ cni.Close()
       └─ nexus-cni-exec teardown-forwarding nexus0
            └─ go-iptables: delete NEXUS-FORWARD chain
```

## Dependencies

- `github.com/coreos/go-iptables` — iptables wrapper (Go library)
