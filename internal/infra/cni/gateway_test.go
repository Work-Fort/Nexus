// SPDX-License-Identifier: GPL-2.0-or-later
package cni

import "testing"

func TestGatewayIP(t *testing.T) {
	tests := []struct {
		cidr    string
		want    string
		wantErr bool
	}{
		{"172.16.0.0/12", "172.16.0.1", false},
		{"10.0.0.0/24", "10.0.0.1", false},
		{"192.168.1.0/24", "192.168.1.1", false},
		{"invalid", "", true},
		{"::1/128", "", true}, // IPv6 not supported
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			got, err := GatewayIP(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GatewayIP(%q) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GatewayIP(%q) = %q, want %q", tt.cidr, got, tt.want)
			}
		})
	}
}
