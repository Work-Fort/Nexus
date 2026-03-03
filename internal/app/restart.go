// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"time"

	"github.com/charmbracelet/log"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// RestoreVMs handles boot recovery. For each VM:
//   - policy=none + state=running → mark as stopped (daemon crashed)
//   - policy=on-boot or always → restart regardless of previous state
func (s *VMService) RestoreVMs(ctx context.Context) {
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		log.Error("restore: list vms", "err", err)
		return
	}

	var restored, cleaned int
	for _, vm := range vms {
		switch vm.RestartPolicy {
		case domain.RestartPolicyOnBoot, domain.RestartPolicyAlways:
			// Best-effort stop stale task (may still be alive in containerd).
			if err := s.runtime.Stop(ctx, vm.ID); err != nil {
				log.Debug("restore: stop stale task", "id", vm.ID, "err", err)
			}
			if err := s.runtime.Start(ctx, vm.ID); err != nil {
				log.Error("restore: start vm", "id", vm.ID, "name", vm.Name, "err", err)
				// Mark as stopped so state is honest.
				s.store.UpdateState(ctx, vm.ID, domain.VMStateStopped, time.Now().UTC()) //nolint:errcheck
				continue
			}
			if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateRunning, time.Now().UTC()); err != nil {
				log.Error("restore: update state", "id", vm.ID, "err", err)
				continue
			}
			restored++
			log.Info("vm restored", "id", vm.ID, "name", vm.Name, "policy", vm.RestartPolicy)

		case domain.RestartPolicyNone:
			if vm.State == domain.VMStateRunning {
				// Daemon crashed — mark as stopped.
				if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateStopped, time.Now().UTC()); err != nil {
					log.Error("restore: mark stopped", "id", vm.ID, "err", err)
					continue
				}
				// Best-effort stop stale task.
				if err := s.runtime.Stop(ctx, vm.ID); err != nil {
					log.Debug("restore: stop stale task", "id", vm.ID, "err", err)
				}
				cleaned++
				log.Info("vm marked stopped", "id", vm.ID, "name", vm.Name)
			}
		}
	}

	if restored > 0 || cleaned > 0 {
		log.Info("boot recovery complete", "restored", restored, "cleaned", cleaned)
	}
}
