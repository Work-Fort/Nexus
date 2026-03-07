// SPDX-License-Identifier: GPL-3.0-or-later
package domain

import "testing"

func TestValidRestartPolicy(t *testing.T) {
	tests := []struct {
		policy RestartPolicy
		want   bool
	}{
		{RestartPolicyNone, true},
		{RestartPolicyOnBoot, true},
		{RestartPolicyAlways, true},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidRestartPolicy(tt.policy); got != tt.want {
			t.Errorf("ValidRestartPolicy(%q) = %v, want %v", tt.policy, got, tt.want)
		}
	}
}

func TestValidRestartStrategy(t *testing.T) {
	tests := []struct {
		strategy RestartStrategy
		want     bool
	}{
		{RestartStrategyImmediate, true},
		{RestartStrategyBackoff, true},
		{RestartStrategyFixed, true},
		{"invalid", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidRestartStrategy(tt.strategy); got != tt.want {
			t.Errorf("ValidRestartStrategy(%q) = %v, want %v", tt.strategy, got, tt.want)
		}
	}
}
