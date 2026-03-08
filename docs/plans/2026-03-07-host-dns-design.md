# Host DNS Resolution for `.nexus`

## Goal

Enable the host to resolve VMs by name via configurable DNS domains.
Split DNS — only configured domains (default `.nexus`) route to CoreDNS,
all other DNS is unaffected. Supports multiple domains so users can add
vanity TLDs (e.g. `.work-fort`) alongside the internal `.nexus` default.

## Architecture

CoreDNS dual-binds the configured zones to a loopback address
(`127.0.0.100`) for host resolution and the bridge gateway IP for VM
resolution. The daemon registers split DNS routing with systemd-resolved
via D-Bus so the host's stub resolver knows to send queries for all
configured domains to `127.0.0.100`.

```
Host app (curl myvm.nexus)
  → 127.0.0.53 (systemd-resolved stub)
  → routing domain ~nexus → 127.0.0.100 (CoreDNS, configured zones only)
  → hosts file lookup → 172.16.0.x

Host app (curl myvm.work-fort)
  → 127.0.0.53 (systemd-resolved stub)
  → routing domain ~work-fort → 127.0.0.100 (CoreDNS, same hosts file)
  → hosts file lookup → 172.16.0.x

VM (nslookup anything)
  → 172.16.0.1 (CoreDNS, gateway)
  → configured zones OR catch-all forwarder → upstream DNS
```

## Multiple Domain Support

The daemon accepts a list of DNS domains via `--dns-domains` (default
`nexus`). The first domain is the primary. `nexus` is always included —
if the user specifies `--dns-domains work-fort`, the effective list is
`[nexus, work-fort]`.

Each VM gets aliases in the hosts file for every configured domain:

```
172.16.0.2 myvm.nexus myvm.work-fort myvm
```

CoreDNS serves a combined zone matching all configured domains:

```
nexus work-fort {
    bind 127.0.0.100 172.16.0.1
    hosts /path/to/hosts { reload 2s; fallthrough }
    log
}
```

The resolved D-Bus registration includes all domains as routing-only:

```
SetLinkDomains(ifindex, [
    {"nexus", routing_only=true},
    {"work-fort", routing_only=true},
])
```

VM resolv.conf search path includes all domains:

```
search nexus work-fort
```

## Loopback Address: `127.0.0.100`

The entire `127.0.0.0/8` range is valid loopback on Linux. Known occupied
addresses:

| Address      | Owner                              |
|--------------|------------------------------------|
| `127.0.0.1`  | localhost                          |
| `127.0.0.11` | Docker embedded DNS                |
| `127.0.0.53` | systemd-resolved full stub         |
| `127.0.0.54` | systemd-resolved proxy stub (v250+)|
| `127.0.1.1`  | Debian/Ubuntu hostname convention  |

`127.0.0.100` is unoccupied, visually distinct, and easy to remember.

## CoreDNS Configuration

The configured zones bind to both the loopback and gateway. The catch-all
forwarder binds only to the gateway — the host never uses CoreDNS for
queries outside the configured domains.

**Single domain (default):**

```
nexus {
    bind 127.0.0.100 172.16.0.1
    hosts /var/lib/nexus/dns/hosts {
        reload 2s
        fallthrough
    }
    log
}

. {
    bind 172.16.0.1
    forward . 1.1.1.1 8.8.8.8
    log
}
```

**Multiple domains:**

```
nexus work-fort {
    bind 127.0.0.100 172.16.0.1
    hosts /var/lib/nexus/dns/hosts {
        reload 2s
        fallthrough
    }
    log
}

. {
    bind 172.16.0.1
    forward . 1.1.1.1 8.8.8.8
    log
}
```

Non-configured-domain queries from the host to `127.0.0.100` get REFUSED
by CoreDNS. systemd-resolved handles this correctly — it falls back to
the normal upstream DNS servers.

## Split DNS Registration via D-Bus

The daemon registers split DNS with systemd-resolved directly, using
`github.com/godbus/dbus/v5`. This works on any systemd-based distro
regardless of whether the system uses systemd-networkd (Arch, Ubuntu
Server) or NetworkManager (Ubuntu Desktop, Fedora Workstation).

### Registration (on startup, after bridge + CoreDNS are up)

1. Look up interface index: `net.InterfaceByName("nexus0")`
2. `SetLinkDNS(ifindex, [{AF_INET, 127.0.0.100}])`
3. `SetLinkDomains(ifindex, [{"nexus", true}, {"work-fort", true}, ...])`
4. `SetLinkDefaultRoute(ifindex, false)`

### Teardown (on shutdown)

1. `RevertLink(ifindex)`

### Failure handling

Best-effort. If any D-Bus call fails (resolved not running, polkit
denied, interface not found), the daemon logs a warning and continues.
VM networking is unaffected — only host-side name resolution is
unavailable.

### Self-healing on crash

If the daemon crashes without calling `RevertLink`, systemd-resolved
automatically clears per-link DNS config when the `nexus0` interface
disappears. No stale state.

## Polkit Rule

The D-Bus calls to `org.freedesktop.resolve1` require polkit
authorization. The package (AUR, .deb) ships a rule file:

```
/etc/polkit-1/rules.d/49-nexus-resolved.rules
```

```javascript
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.resolve1.") === 0 &&
        subject.local && subject.active) {
        return polkit.Result.YES;
    }
});
```

This authorizes any local active user to configure per-link DNS via
resolved. The scope is narrow — it only covers resolved's set/revert
actions, not arbitrary system changes.

## New Code

### `internal/infra/resolved/` package

Small package wrapping the D-Bus calls:

- `Register(ifname, dnsIP string, domains []string) error` — calls
  SetLinkDNS + SetLinkDomains + SetLinkDefaultRoute
- `Revert(ifname string) error` — calls RevertLink
- Uses `github.com/godbus/dbus/v5`

### `dns.Config` changes

Two new fields:

- `LoopbackIP string` — default `"127.0.0.100"`
- `Domains []string` — default `["nexus"]`

`writeCorefile()` uses all domains as the zone name(s) and adds the
loopback IP to the bind directive. The catch-all `.` block remains
gateway-only.

`writeHostsFile()` generates aliases for each domain:
`IP name.domain1 name.domain2 ... name`

`GenerateResolvConf()` uses the domain list as the search path.

### `cmd/daemon.go` changes

After `dm.Start()`:
```go
if err := resolved.Register("nexus0", loopbackIP, domains); err != nil {
    log.Warn("host dns: could not register with resolved", "err", err)
}
```

On shutdown (before `dm.Stop()`):
```go
resolved.Revert("nexus0")
```

### Configuration

- `--dns-loopback` (default `127.0.0.100`, env `NEXUS_DNS_LOOPBACK`)
- `--dns-domains` (default `nexus`, env `NEXUS_DNS_DOMAINS`) — comma-
  separated list. `nexus` is always included even if not specified.

## New Dependency

`github.com/godbus/dbus/v5` — well-maintained, used by systemd's own Go
bindings, Tailscale, Podman, and many other projects.

## Platform Support

| Platform           | Network manager    | Works? |
|--------------------|--------------------|--------|
| Arch Linux         | systemd-networkd   | Yes    |
| Ubuntu Server      | systemd-networkd   | Yes    |
| Ubuntu Desktop     | NetworkManager     | Yes    |
| Fedora Workstation | NetworkManager     | Yes    |
| Fedora Server      | systemd-networkd   | Yes    |

All platforms use systemd-resolved. The D-Bus API is the same regardless
of which network manager is active — this is the approach recommended by
the systemd project for VPN-like daemons.

## Testing

- **Unit test:** Verify `writeCorefile()` generates correct dual-bind
  config with loopback IP, single and multiple domains.
- **Unit test:** Verify `writeHostsFile()` generates aliases for all
  configured domains.
- **Unit test for resolved package:** Mock D-Bus connection, verify
  correct method calls with domain list.
- **E2E:** Difficult to test host DNS in CI (needs resolved + real
  bridge). The Corefile generation and CoreDNS loopback binding can be
  tested. Resolved registration is best-effort and tested via unit tests.
