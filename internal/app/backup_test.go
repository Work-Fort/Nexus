// SPDX-License-Identifier: GPL-3.0-or-later
package app

import (
	"encoding/json"
	"testing"
)

func TestManifestRoundTrip(t *testing.T) {
	m := ExportManifest{
		Version: 1,
		VM: ManifestVM{
			Name:     "worker",
			Tags:     []string{"agent"},
			Image:    "docker.io/library/alpine:latest",
			Runtime:  "io.containerd.kata.v2",
			RootSize: "10G",
			DNS: &ManifestDNS{
				Servers: []string{"172.16.0.1"},
				Search:  []string{"nexus.local"},
			},
		},
		Drives: []ManifestDrive{
			{Name: "data", Size: "5G", MountPath: "/data"},
		},
		Devices: []ManifestDevice{
			{Name: "gpu", HostPath: "/dev/vfio/42", ContainerPath: "/dev/vfio/42", Permissions: "rwm", GID: 109},
		},
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ExportManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if got.VM.Name != "worker" {
		t.Errorf("vm.name = %q, want %q", got.VM.Name, "worker")
	}
	if len(got.Drives) != 1 || got.Drives[0].Name != "data" {
		t.Error("drive not round-tripped")
	}
	if len(got.Devices) != 1 || got.Devices[0].Name != "gpu" {
		t.Error("device not round-tripped")
	}
}

func TestManifestValidation(t *testing.T) {
	tests := []struct {
		name    string
		m       ExportManifest
		wantErr bool
	}{
		{"valid", ExportManifest{Version: 1, VM: ManifestVM{Name: "x", Tags: []string{"agent"}, Image: "img", Runtime: "rt"}}, false},
		{"version 0", ExportManifest{Version: 0, VM: ManifestVM{Name: "x", Tags: []string{"agent"}, Image: "img", Runtime: "rt"}}, true},
		{"missing name", ExportManifest{Version: 1, VM: ManifestVM{Tags: []string{"agent"}, Image: "img", Runtime: "rt"}}, true},
		{"missing image", ExportManifest{Version: 1, VM: ManifestVM{Name: "x", Tags: []string{"agent"}, Runtime: "rt"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
