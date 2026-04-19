// SPDX-License-Identifier: GPL-3.0-or-later
package app_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/app"
	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/internal/infra/sqlite"
)

// fakeStorage is an in-memory domain.Storage for unit tests. Tracks
// calls so tests can assert the CSI-shaped sequence:
// SnapshotVolume(src, intermediate) -> CloneVolume(intermediate, dst)
// -> DeleteVolumeSnapshot(intermediate) [when retain=false].
type fakeStorage struct {
	volumes   map[string]bool
	snapshots map[string]string // snapshot -> source volume
	calls     []string
	failOn    string // method name to fail on, "" = none
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{
		volumes:   map[string]bool{},
		snapshots: map[string]string{},
	}
}

func (s *fakeStorage) CreateVolume(_ context.Context, name string, _ uint64) (string, error) {
	s.calls = append(s.calls, "CreateVolume:"+name)
	if s.failOn == "CreateVolume" {
		return "", errors.New("synthetic failure")
	}
	s.volumes[name] = true
	return "/fake/" + name, nil
}
func (s *fakeStorage) DeleteVolume(_ context.Context, name string) error {
	s.calls = append(s.calls, "DeleteVolume:"+name)
	delete(s.volumes, name)
	return nil
}
func (s *fakeStorage) VolumePath(name string) string                          { return "/fake/" + name }
func (s *fakeStorage) SendVolume(context.Context, string, io.Writer) error    { return nil }
func (s *fakeStorage) ReceiveVolume(context.Context, string, io.Reader) error { return nil }
func (s *fakeStorage) SnapshotVolume(_ context.Context, vol, snap string) error {
	s.calls = append(s.calls, "SnapshotVolume:"+vol+"->"+snap)
	if s.failOn == "SnapshotVolume" {
		return errors.New("synthetic failure")
	}
	if !s.volumes[vol] {
		return errors.New("source volume not found")
	}
	s.snapshots[snap] = vol
	return nil
}
func (s *fakeStorage) RestoreVolume(_ context.Context, _, _ string) error { return nil }
func (s *fakeStorage) CloneVolume(_ context.Context, snap, vol string) error {
	s.calls = append(s.calls, "CloneVolume:"+snap+"->"+vol)
	if s.failOn == "CloneVolume" {
		return errors.New("synthetic failure")
	}
	if _, ok := s.snapshots[snap]; !ok {
		return errors.New("snapshot not found")
	}
	if s.volumes[vol] {
		return errors.New("clone target already exists")
	}
	s.volumes[vol] = true
	return nil
}
func (s *fakeStorage) DeleteVolumeSnapshot(_ context.Context, snap string) error {
	s.calls = append(s.calls, "DeleteVolumeSnapshot:"+snap)
	delete(s.snapshots, snap)
	return nil
}
func (s *fakeStorage) SendVolumeSnapshot(context.Context, string, io.Writer) error { return nil }

// newCloneTestSvc builds a VMService backed by an in-memory sqlite
// store (which implements domain.DriveStore) and the fakeStorage.
// Returns the service, the fake, the underlying store (so tests can
// AttachDrive directly to exercise the source-attached rejection
// path), and a cleanup hook the test must defer.
func newCloneTestSvc(t *testing.T) (*app.VMService, *fakeStorage, *sqlite.Store, func()) {
	t.Helper()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	fs := newFakeStorage()
	svc := app.NewVMService(nil, nil, nil, app.WithStorage(store, fs))
	return svc, fs, store, func() { _ = store.Close() }
}

func TestCloneDrive_HappyPath(t *testing.T) {
	svc, fs, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	src, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "project-master", Size: "100Mi", MountPath: "/work",
	})
	if err != nil {
		t.Fatalf("seed source drive: %v", err)
	}

	clone, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: src.Name,
		Name:            "work-item-w1",
	})
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.Name != "work-item-w1" {
		t.Errorf("clone name = %q, want work-item-w1", clone.Name)
	}
	if clone.SizeBytes != src.SizeBytes {
		t.Errorf("clone size = %d, want %d (inherited)", clone.SizeBytes, src.SizeBytes)
	}
	if clone.MountPath != src.MountPath {
		t.Errorf("clone mount = %q, want %q (inherited from source)", clone.MountPath, src.MountPath)
	}
	if clone.VMID != "" {
		t.Errorf("clone must be unattached, got VMID=%q", clone.VMID)
	}

	// Storage call sequence after seed:
	// SnapshotVolume(src->ephemeral) -> CloneVolume(ephemeral->dst) -> DeleteVolumeSnapshot(ephemeral).
	tail := fs.calls[1:] // skip the initial CreateVolume from seed
	if len(tail) != 3 ||
		!strings.HasPrefix(tail[0], "SnapshotVolume:project-master->") ||
		!strings.HasPrefix(tail[1], "CloneVolume:") ||
		!strings.HasPrefix(tail[2], "DeleteVolumeSnapshot:") {
		t.Errorf("clone call sequence wrong: %v", tail)
	}

	got, err := svc.GetDrive(context.Background(), "work-item-w1")
	if err != nil {
		t.Fatalf("GetDrive after clone: %v", err)
	}
	if got.ID != clone.ID {
		t.Errorf("stored clone ID mismatch")
	}
}

func TestCloneDrive_MountPathOverride(t *testing.T) {
	svc, _, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	}); err != nil {
		t.Fatal(err)
	}

	clone, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "dst",
		MountPath:       "/somewhere/else",
	})
	if err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}
	if clone.MountPath != "/somewhere/else" {
		t.Errorf("override mount = %q, want /somewhere/else", clone.MountPath)
	}
}

func TestCloneDrive_RetainSnapshot(t *testing.T) {
	svc, fs, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "dst",
		SnapshotName:    "named-snap-1",
	}); err != nil {
		t.Fatalf("CloneDrive: %v", err)
	}

	// With explicit SnapshotName, the intermediate snapshot is RETAINED.
	for _, c := range fs.calls {
		if strings.HasPrefix(c, "DeleteVolumeSnapshot:") {
			t.Errorf("snapshot must be retained when SnapshotName is set, got: %v", fs.calls)
		}
	}
	if _, ok := fs.snapshots["named-snap-1"]; !ok {
		t.Errorf("named snapshot missing from fake; calls=%v", fs.calls)
	}
}

func TestCloneDrive_SourceNotFound(t *testing.T) {
	svc, _, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	_, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "ghost",
		Name:            "clone",
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCloneDrive_NameConflict(t *testing.T) {
	svc, _, _, cleanup := newCloneTestSvc(t)
	defer cleanup()

	for _, n := range []string{"src", "taken"} {
		if _, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
			Name: n, Size: "10Mi", MountPath: "/m",
		}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}

	_, err := svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "taken",
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestCloneDrive_SourceAttached_Rejected(t *testing.T) {
	svc, _, store, cleanup := newCloneTestSvc(t)
	defer cleanup()

	src, err := svc.CreateDrive(context.Background(), domain.CreateDriveParams{
		Name: "src", Size: "10Mi", MountPath: "/src",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The sqlite store enforces a FK from drives.vm_id -> vms.id, so we
	// insert a minimal VM record before attaching. CloneDrive only checks
	// src.VMID != "", so any valid VM ID is sufficient.
	fakeVM := &domain.VM{
		ID:              "vmfakeid000x",
		Name:            "vm-fake",
		State:           domain.VMStateStopped,
		RestartPolicy:   domain.RestartPolicyNone,
		RestartStrategy: domain.RestartStrategyBackoff,
		CreatedAt:       time.Now().UTC(),
	}
	if err := store.Create(context.Background(), fakeVM); err != nil {
		t.Fatalf("seed fake VM: %v", err)
	}
	if err := store.AttachDrive(context.Background(), src.ID, fakeVM.ID); err != nil {
		t.Fatal(err)
	}

	_, err = svc.CloneDrive(context.Background(), app.CloneDriveParams{
		SourceVolumeRef: "src",
		Name:            "clone",
	})
	if !errors.Is(err, domain.ErrInvalidState) {
		t.Errorf("err = %v, want ErrInvalidState", err)
	}
}
