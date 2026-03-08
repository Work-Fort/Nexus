// SPDX-License-Identifier: GPL-2.0-or-later

// Package resolved registers split DNS routing with systemd-resolved
// via D-Bus. This allows the host to resolve VM names (e.g. myvm.nexus)
// without affecting other DNS resolution.
package resolved

import (
	"fmt"
	"net"

	"github.com/godbus/dbus/v5"
)

const (
	resolvedDest      = "org.freedesktop.resolve1"
	resolvedPath      = "/org/freedesktop/resolve1"
	resolvedInterface = "org.freedesktop.resolve1.Manager"
)

// dnsEntry matches the D-Bus signature (iay) for SetLinkDNS.
type dnsEntry struct {
	Family  int32
	Address []byte
}

// domainEntry matches the D-Bus signature (sb) for SetLinkDomains.
type domainEntry struct {
	Domain      string
	RoutingOnly bool
}

// Register configures systemd-resolved to route queries for the given
// domains to dnsIP via the named network interface. All domains are
// registered as routing-only (tilde prefix equivalent).
func Register(ifname, dnsIP string, domains []string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifname, err)
	}

	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(resolvedDest, dbus.ObjectPath(resolvedPath))
	ifindex := int32(iface.Index)

	dns := buildDNSPayload(dnsIP)
	if err := obj.Call(resolvedInterface+".SetLinkDNS", 0, ifindex, dns).Err; err != nil {
		return fmt.Errorf("SetLinkDNS: %w", err)
	}

	doms := buildDomainsPayload(domains)
	if err := obj.Call(resolvedInterface+".SetLinkDomains", 0, ifindex, doms).Err; err != nil {
		return fmt.Errorf("SetLinkDomains: %w", err)
	}

	if err := obj.Call(resolvedInterface+".SetLinkDefaultRoute", 0, ifindex, false).Err; err != nil {
		return fmt.Errorf("SetLinkDefaultRoute: %w", err)
	}

	return nil
}

// Revert removes all resolved configuration for the named interface.
func Revert(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifname, err)
	}

	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object(resolvedDest, dbus.ObjectPath(resolvedPath))
	return obj.Call(resolvedInterface+".RevertLink", 0, int32(iface.Index)).Err
}

// buildDNSPayload creates the D-Bus payload for SetLinkDNS.
func buildDNSPayload(ip string) []dnsEntry {
	parsed := net.ParseIP(ip).To4()
	return []dnsEntry{{Family: 2, Address: parsed}} // AF_INET = 2
}

// buildDomainsPayload creates the D-Bus payload for SetLinkDomains.
func buildDomainsPayload(domains []string) []domainEntry {
	entries := make([]domainEntry, len(domains))
	for i, d := range domains {
		entries[i] = domainEntry{Domain: d, RoutingOnly: true}
	}
	return entries
}
