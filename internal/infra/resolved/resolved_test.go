// SPDX-License-Identifier: GPL-2.0-or-later
package resolved

import (
	"testing"
)

func TestBuildDNSPayload(t *testing.T) {
	got := buildDNSPayload("127.0.0.100")
	if got[0].Family != 2 {
		t.Errorf("family = %d, want 2", got[0].Family)
	}
	if len(got[0].Address) != 4 {
		t.Errorf("address len = %d, want 4", len(got[0].Address))
	}
	want := []byte{127, 0, 0, 100}
	for i, b := range got[0].Address {
		if b != want[i] {
			t.Errorf("address[%d] = %d, want %d", i, b, want[i])
		}
	}
}

func TestBuildDomainsPayload(t *testing.T) {
	got := buildDomainsPayload([]string{"nexus", "work-fort"})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Domain != "nexus" || !got[0].RoutingOnly {
		t.Errorf("got[0] = %+v, want {nexus, true}", got[0])
	}
	if got[1].Domain != "work-fort" || !got[1].RoutingOnly {
		t.Errorf("got[1] = %+v, want {work-fort, true}", got[1])
	}
}
