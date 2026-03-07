// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"time"

	"github.com/Work-Fort/Nexus/internal/domain"
	"github.com/Work-Fort/Nexus/pkg/nxid"
)

// defaultTemplates are seeded on first run if the templates table is empty.
var defaultTemplates = []struct {
	Name   string
	Distro string
	Script string
}{
	{
		Name:   "alpine-openrc",
		Distro: "alpine",
		Script: `#!/bin/sh
if ! command -v openrc >/dev/null 2>&1; then
    apk add --no-cache openrc
    sed -i 's/^#rc_sys=""/rc_sys="lxc"/' /etc/rc.conf
    mkdir -p /run/openrc
    touch /run/openrc/softlevel
fi
exec /sbin/init`,
	},
	{
		Name:   "ubuntu-systemd",
		Distro: "ubuntu",
		Script: `#!/bin/sh
if [ ! -d /run/systemd/system ]; then
    apt-get update -qq && apt-get install -y -qq systemd-sysv dbus >/dev/null 2>&1
fi
exec /lib/systemd/systemd`,
	},
	{
		Name:   "arch-systemd",
		Distro: "arch",
		Script: `#!/bin/sh
if [ ! -d /run/systemd/system ]; then
    pacman -Sy --noconfirm systemd >/dev/null 2>&1
fi
exec /lib/systemd/systemd`,
	},
}

// seedTemplates inserts default templates if the table is empty.
func (s *Store) seedTemplates(ctx context.Context) error {
	count, err := s.q.CountTemplates(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	now := time.Now().UTC()
	for _, dt := range defaultTemplates {
		t := &domain.Template{
			ID:        nxid.New(),
			Name:      dt.Name,
			Distro:    dt.Distro,
			Script:    dt.Script,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.CreateTemplate(ctx, t); err != nil {
			return err
		}
	}
	return nil
}
