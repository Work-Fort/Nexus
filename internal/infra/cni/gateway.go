// SPDX-License-Identifier: GPL-2.0-or-later
package cni

import (
	"fmt"
	"net"
)

// GatewayIP returns the first usable IP in a CIDR subnet.
// For "172.16.0.0/12" this returns "172.16.0.1".
func GatewayIP(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", cidr)
	}
	gw := make(net.IP, len(ip4))
	copy(gw, ip4)
	gw[3]++
	return gw.String(), nil
}
