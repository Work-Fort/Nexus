// SPDX-License-Identifier: GPL-3.0-or-later
package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCloneDrive_E2E_HappyPath(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	src, err := bd.client.CreateDrive("project-master", "10Mi", "/work")
	if err != nil {
		t.Fatalf("create source drive: %v", err)
	}

	clone, err := bd.client.CloneDrive(src.Name, "work-item-w1", "/work", "")
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.Name != "work-item-w1" {
		t.Errorf("clone name = %q, want work-item-w1", clone.Name)
	}
	if clone.SourceVolumeRef != src.Name {
		t.Errorf("source_volume_ref echo = %q, want %q", clone.SourceVolumeRef, src.Name)
	}
	if clone.SizeBytes != src.SizeBytes {
		t.Errorf("clone size = %d, want %d", clone.SizeBytes, src.SizeBytes)
	}
	if clone.VMID != nil {
		t.Errorf("clone must be unattached, got vm_id=%v", *clone.VMID)
	}

	// Verify the clone is a real btrfs subvolume on disk and writable.
	clonePath := filepath.Join(bd.drivesDir, clone.Name)
	out, err := btrfsPropertyGet(clonePath)
	if err != nil {
		t.Fatalf("btrfs property get %s: %v: %s", clonePath, err, out)
	}
	if !strings.Contains(out, "ro=false") {
		t.Errorf("clone subvolume not writable: %q", out)
	}

	// And it is reachable via GET /v1/drives.
	drives, err := bd.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	var found bool
	for _, d := range drives {
		if d.Name == clone.Name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cloned drive not in ListDrives: %v", drives)
	}
}

func TestCloneDrive_E2E_MountPathInherited(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	if _, err := bd.client.CreateDrive("master", "10Mi", "/inherited"); err != nil {
		t.Fatalf("create source: %v", err)
	}

	clone, err := bd.client.CloneDrive("master", "child", "", "")
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.MountPath != "/inherited" {
		t.Errorf("mount_path = %q, want /inherited (inherited)", clone.MountPath)
	}
}

func TestCloneDrive_E2E_RetainSnapshot(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	src, err := bd.client.CreateDrive("master-2", "10Mi", "/m")
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	const snapName = "named-snap-e2e"
	clone, err := bd.client.CloneDrive(src.Name, "clone-2", "/c", snapName)
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.SnapshotName != snapName {
		t.Errorf("snapshot_name echo = %q, want %q", clone.SnapshotName, snapName)
	}

	// The named intermediate snapshot must exist at
	// <drivesDir>/.snapshots/<snapName> as a read-only subvolume.
	snapPath := filepath.Join(bd.drivesDir, ".snapshots", snapName)
	out, err := btrfsPropertyGet(snapPath)
	if err != nil {
		t.Fatalf("named snapshot missing at %s: %v: %s", snapPath, err, out)
	}
	if !strings.Contains(out, "ro=true") {
		t.Errorf("retained snapshot not read-only: %q", out)
	}
}

func TestCloneDrive_E2E_SourceNotFound(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	_, err := bd.client.CloneDrive("ghost", "clone", "", "")
	if err == nil {
		t.Fatal("expected error for missing source")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want a 404", err)
	}
}

func TestCloneDrive_E2E_NameConflict(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	if _, err := bd.client.CreateDrive("src", "10Mi", "/m"); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	if _, err := bd.client.CreateDrive("taken", "10Mi", "/t"); err != nil {
		t.Fatalf("seed taken: %v", err)
	}

	_, err := bd.client.CloneDrive("src", "taken", "", "")
	if err == nil {
		t.Fatal("expected error for name conflict")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("err = %v, want a 409", err)
	}
}

func TestCloneDrive_E2E_MCP_HappyPath(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	if _, err := bd.client.CreateDrive("mcp-master", "10Mi", "/m"); err != nil {
		t.Fatalf("seed source: %v", err)
	}

	res, err := bd.client.MCPCall("drive_clone", map[string]any{
		"source_volume_ref": "mcp-master",
		"name":              "mcp-child",
	})
	if err != nil {
		t.Fatalf("MCPCall: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", res.Content)
	}
	if !strings.Contains(res.Content, `"name":"mcp-child"`) {
		t.Errorf("result content missing expected name; got=%s", res.Content)
	}
	if !strings.Contains(res.Content, `"source_volume_ref":"mcp-master"`) {
		t.Errorf("result content missing source_volume_ref echo; got=%s", res.Content)
	}

	// The drive is also reachable via REST after MCP creation.
	drives, err := bd.client.ListDrives()
	if err != nil {
		t.Fatalf("list drives: %v", err)
	}
	var found bool
	for _, d := range drives {
		if d.Name == "mcp-child" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("MCP-cloned drive not in ListDrives")
	}
}

func TestCloneDrive_E2E_MCP_MissingRequired(t *testing.T) {
	requireBtrfs(t)
	bd := startBtrfsDaemon(t)

	res, err := bd.client.MCPCall("drive_clone", map[string]any{
		"name": "child-only",
		// missing source_volume_ref
	})
	if err != nil {
		t.Fatalf("MCPCall: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected isError=true for missing source_volume_ref; content=%s", res.Content)
	}
	if !strings.Contains(res.Content, "source_volume_ref") {
		t.Errorf("error content should name the missing field; got=%s", res.Content)
	}
}
