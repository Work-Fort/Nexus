// SPDX-License-Identifier: GPL-3.0-or-later
package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/Work-Fort/Nexus/internal/domain"
)

func TestTemplateSeeding(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	all, err := store.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 seeded templates, got %d", len(all))
	}

	names := make(map[string]bool)
	for _, tmpl := range all {
		names[tmpl.Name] = true
	}
	for _, want := range []string{"alpine-openrc", "ubuntu-systemd", "arch-systemd"} {
		if !names[want] {
			t.Errorf("missing seeded template %q", want)
		}
	}
}

func TestTemplateCRUD(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	tmpl := &domain.Template{
		ID:        "tpl-custom",
		Name:      "gentoo-openrc",
		Distro:    "gentoo",
		Script:    "#!/bin/sh\nexec /sbin/init",
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	// Create
	if err := store.CreateTemplate(ctx, tmpl); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Get by ID
	got, err := store.GetTemplate(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "gentoo-openrc" {
		t.Errorf("name = %q, want gentoo-openrc", got.Name)
	}
	if got.Script != tmpl.Script {
		t.Errorf("script mismatch")
	}

	// Get by name
	got, err = store.GetTemplateByName(ctx, "gentoo-openrc")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got.ID != tmpl.ID {
		t.Errorf("id = %q, want %q", got.ID, tmpl.ID)
	}

	// Get by distro
	got, err = store.GetTemplateByDistro(ctx, "gentoo")
	if err != nil {
		t.Fatalf("get by distro: %v", err)
	}
	if got.ID != tmpl.ID {
		t.Errorf("id = %q, want %q", got.ID, tmpl.ID)
	}

	// Resolve by name
	got, err = store.ResolveTemplate(ctx, "gentoo-openrc")
	if err != nil {
		t.Fatalf("resolve by name: %v", err)
	}
	if got.ID != tmpl.ID {
		t.Errorf("resolve id = %q, want %q", got.ID, tmpl.ID)
	}

	// Resolve by ID
	got, err = store.ResolveTemplate(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("resolve by id: %v", err)
	}
	if got.Name != "gentoo-openrc" {
		t.Errorf("resolve name = %q, want gentoo-openrc", got.Name)
	}

	// List (3 seeds + 1 custom)
	all, err := store.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("list count = %d, want 4", len(all))
	}

	// Update
	if err := store.UpdateTemplate(ctx, tmpl.ID, "gentoo-openrc-v2", "gentoo", "#!/bin/sh\nexec /sbin/init --new"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = store.GetTemplate(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.Name != "gentoo-openrc-v2" {
		t.Errorf("updated name = %q, want gentoo-openrc-v2", got.Name)
	}
	if got.Script != "#!/bin/sh\nexec /sbin/init --new" {
		t.Errorf("updated script mismatch")
	}

	// Delete
	if err := store.DeleteTemplate(ctx, tmpl.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = store.GetTemplate(ctx, tmpl.ID)
	if err != domain.ErrNotFound {
		t.Errorf("get after delete: err = %v, want ErrNotFound", err)
	}
}

func TestTemplateNotFound(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	_, err := store.GetTemplate(ctx, "nonexistent")
	if err != domain.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	_, err = store.GetTemplateByName(ctx, "nonexistent")
	if err != domain.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	_, err = store.GetTemplateByDistro(ctx, "nonexistent")
	if err != domain.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	_, err = store.ResolveTemplate(ctx, "nonexistent")
	if err != domain.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCountTemplateRefs(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	// Use a seeded template (alpine)
	tmpl, err := store.GetTemplateByDistro(ctx, "alpine")
	if err != nil {
		t.Fatalf("get seeded template: %v", err)
	}

	// No refs initially
	n, err := store.CountTemplateRefs(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}

	// Create a VM that references the template
	vm := &domain.VM{
		ID:              "vm-001",
		Name:            "test-vm",
		State:           domain.VMStateCreated,
		Image:           "alpine:latest",
		Runtime:         "io.containerd.runc.v2",
		RestartPolicy:   domain.RestartPolicyNone,
		RestartStrategy: domain.RestartStrategyBackoff,
		Init:            true,
		TemplateID:      tmpl.ID,
		CreatedAt:       time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := store.Create(ctx, vm); err != nil {
		t.Fatalf("create vm: %v", err)
	}

	n, err = store.CountTemplateRefs(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
}

func TestVMInitFields(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	// Use a seeded template
	tmpl, err := store.GetTemplateByDistro(ctx, "alpine")
	if err != nil {
		t.Fatalf("get seeded template: %v", err)
	}

	vm := &domain.VM{
		ID:              "vm-001",
		Name:            "init-vm",
		State:           domain.VMStateCreated,
		Image:           "alpine:latest",
		Runtime:         "io.containerd.runc.v2",
		RestartPolicy:   domain.RestartPolicyNone,
		RestartStrategy: domain.RestartStrategyBackoff,
		Init:            true,
		TemplateID:      tmpl.ID,
		ScriptOverride:  "#!/bin/sh\necho custom",
		CreatedAt:       time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := store.Create(ctx, vm); err != nil {
		t.Fatalf("create vm: %v", err)
	}

	got, err := store.Get(ctx, vm.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Init {
		t.Error("Init = false, want true")
	}
	if got.TemplateID != tmpl.ID {
		t.Errorf("TemplateID = %q, want %q", got.TemplateID, tmpl.ID)
	}
	if got.ScriptOverride != "#!/bin/sh\necho custom" {
		t.Errorf("ScriptOverride = %q, want custom script", got.ScriptOverride)
	}
}
