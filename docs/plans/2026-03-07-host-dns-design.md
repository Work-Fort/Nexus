# Host DNS Resolution for `.nexus`

## Goal

Enable the host to resolve `*.nexus` domains so tools like `curl`, `ping`,
and browsers can reach VMs by name. Split DNS — only `.nexus` queries route
to CoreDNS, all other DNS is unaffected.

## Architecture

CoreDNS dual-binds the `nexus` zone to a loopback address (`127.0.0.100`)
for host resolution and the bridge gateway IP for VM resolution. The daemon
registers split DNS routing with systemd-resolved via D-Bus so the host's
stub resolver knows to send `*.nexus` queries to `127.0.0.100`.

```
Host app (curl myvm.nexus)
  → 127.0.0.53 (systemd-resolved stub)
  → routing domain ~nexus → 127.0.0.100 (CoreDNS, nexus zone only)
  → hosts file lookup → 172.16.0.x

VM (nslookup anything)
  → 172.16.0.1 (CoreDNS, gateway)
  → nexus zone OR catch-all forwarder → upstream DNS
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

The `nexus` server block binds to both the loopback and gateway. The
catch-all forwarder binds only to the gateway — the host never uses
CoreDNS for non-nexus queries.

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

Non-nexus queries from the host to `127.0.0.100` get REFUSED by CoreDNS.
systemd-resolved handles this correctly — it falls back to the normal
upstream DNS servers.

## Split DNS Registration via D-Bus

The daemon registers split DNS with systemd-resolved directly, using
`github.com/godbus/dbus/v5`. This works on any systemd-based distro
regardless of whether the system uses systemd-networkd (Arch, Ubuntu
Server) or NetworkManager (Ubuntu Desktop, Fedora Workstation).

### Registration (on startup, after bridge + CoreDNS are up)

1. Look up interface index: `net.InterfaceByName("nexus0")`
2. `SetLinkDNS(ifindex, [{AF_INET, 127.0.0.100}])`
3. `SetLinkDomains(ifindex, [{"nexus", routing_only=true}])`
4. `SetLinkDefaultRoute(ifindex, false)`

### Teardown (on shutdown)

1. `RevertLink(ifindex)`

### Failure handling

Best-effort. If any D-Bus call fails (resolved not running, polkit
denied, interface not found), the daemon logs a warning and continues.
VM networking is unaffected — only host-side `.nexus` resolution is
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

- `Register(ifname, dnsIP, domain string) error` — calls SetLinkDNS +
  SetLinkDomains + SetLinkDefaultRoute
- `Revert(ifname string) error` — calls RevertLink
- Uses `github.com/godbus/dbus/v5`

### `dns.Config` changes

New field: `LoopbackIP string` (default `"127.0.0.100"`).

`writeCorefile()` adds the loopback IP to the `nexus` server block's
`bind` directive. The catch-all `.` block remains gateway-only.

### `cmd/daemon.go` changes

After `dm.Start()`:
```go
if err := resolved.Register("nexus0", loopbackIP, "nexus"); err != nil {
    log.Warn("host dns: could not register with resolved", "err", err)
}
```

On shutdown (before `dm.Stop()`):
```go
resolved.Revert("nexus0")
```

### Configuration

New flag: `--dns-loopback` (default `127.0.0.100`, env `NEXUS_DNS_LOOPBACK`).

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
  config with loopback IP in `nexus` block only.
- **Unit test for resolved package:** Mock D-Bus connection, verify
  correct method calls and arguments.
- **E2E:** Difficult to test host DNS in CI (needs resolved + real
  bridge). The Corefile generation and CoreDNS loopback binding can be
  tested. Resolved registration is best-effort and tested via unit tests.
