// SPDX-License-Identifier: GPL-3.0-or-later
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

	// Network migration: detect CNI config drift and rebuild namespaces.
	if s.network.ConfigChanged() {
		if s.config.NetworkAutoMigrate {
			s.migrateNetworks(ctx, vms)
		} else {
			log.Warn("network config changed but auto-migrate is disabled")
			if err := s.network.SaveConfigHash(); err != nil {
				log.Error("save config hash", "err", err)
			}
		}
	} else {
		// Config unchanged — ensure hash file exists for next comparison.
		if err := s.network.SaveConfigHash(); err != nil {
			log.Error("save config hash", "err", err)
		}
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

// migrateNetworks tears down and rebuilds network namespaces for all VMs
// when the CNI config has changed.
func (s *VMService) migrateNetworks(ctx context.Context, vms []*domain.VM) {
	var migrated, failed int
	for _, vm := range vms {
		if vm.NetNSPath == "" {
			continue
		}

		prevIP := vm.IP

		// Teardown old namespace (best-effort).
		if err := s.network.Teardown(ctx, vm.ID); err != nil {
			log.Warn("migrate: teardown", "id", vm.ID, "name", vm.Name, "err", err)
		}

		// Setup new namespace with current config.
		var opts []domain.SetupOpt
		if prevIP != "" {
			opts = append(opts, domain.WithPreferredIP(prevIP))
		}
		info, err := s.network.Setup(ctx, vm.ID, opts...)
		if err != nil {
			log.Error("migrate: setup", "id", vm.ID, "name", vm.Name, "err", err)
			// Clear network fields so state is honest.
			s.store.UpdateNetwork(ctx, vm.ID, "", "", "") //nolint:errcheck
			failed++
			continue
		}

		// Update DB with new network info.
		if err := s.store.UpdateNetwork(ctx, vm.ID, info.IP, info.Gateway, info.NetNSPath); err != nil {
			log.Error("migrate: update network", "id", vm.ID, "err", err)
			failed++
			continue
		}

		// Update in-memory VM for subsequent RestoreVMs logic.
		vm.IP = info.IP
		vm.Gateway = info.Gateway
		vm.NetNSPath = info.NetNSPath

		// Update DNS record.
		s.dns.AddRecord(ctx, vm.Name, info.IP) //nolint:errcheck

		migrated++
		if info.IP != prevIP {
			log.Info("vm network migrated", "id", vm.ID, "name", vm.Name, "old_ip", prevIP, "new_ip", info.IP)
		} else {
			log.Info("vm network migrated", "id", vm.ID, "name", vm.Name, "ip", info.IP)
		}
	}

	// Save the new config hash now that migration is complete.
	if err := s.network.SaveConfigHash(); err != nil {
		log.Error("migrate: save config hash", "err", err)
	}

	log.Info("network migration complete", "migrated", migrated, "failed", failed)
}

// Shutdown gracefully stops all running VMs so containerd tasks are cleaned up.
// Called during daemon shutdown to prevent orphaned tasks.
func (s *VMService) Shutdown(ctx context.Context) {
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		log.Error("shutdown: list vms", "err", err)
		return
	}

	var stopped int
	for _, vm := range vms {
		if vm.State != domain.VMStateRunning {
			continue
		}
		if err := s.runtime.Stop(ctx, vm.ID); err != nil {
			log.Warn("shutdown: stop vm", "id", vm.ID, "name", vm.Name, "err", err)
		} else {
			stopped++
		}
	}
	if stopped > 0 {
		log.Info("shutdown: stopped running vms", "count", stopped)
	}
}

// backoffState tracks per-VM restart backoff.
type backoffState struct {
	lastFailure time.Time
	delay       time.Duration
}

const (
	backoffInitial    = 1 * time.Second
	backoffMax        = 60 * time.Second
	backoffReset      = 30 * time.Second
	fixedRestartDelay = 5 * time.Second
)

// StartCrashMonitor runs the crash monitoring loop in a goroutine. It
// subscribes to containerd task exit events and restarts VMs with
// restart_policy=always using their configured strategy. Cancel ctx to stop.
func (s *VMService) StartCrashMonitor(ctx context.Context) {
	backoffs := make(map[string]*backoffState)

	go func() {
		err := s.runtime.WatchExits(ctx, func(containerID string, exitCode uint32) {
			vm, err := s.store.Get(ctx, containerID)
			if err != nil {
				log.Debug("crash monitor: vm not found", "container_id", containerID)
				return
			}
			if vm.RestartPolicy != domain.RestartPolicyAlways {
				// Not auto-restart — just mark as stopped.
				s.store.UpdateState(ctx, vm.ID, domain.VMStateStopped, time.Now().UTC()) //nolint:errcheck
				log.Info("vm exited", "id", vm.ID, "name", vm.Name, "exit_code", exitCode)
				return
			}

			// Apply restart strategy.
			switch vm.RestartStrategy {
			case domain.RestartStrategyFixed:
				select {
				case <-time.After(fixedRestartDelay):
				case <-ctx.Done():
					return
				}

			case domain.RestartStrategyBackoff:
				bs, ok := backoffs[vm.ID]
				if !ok {
					bs = &backoffState{delay: backoffInitial}
					backoffs[vm.ID] = bs
				}
				if time.Since(bs.lastFailure) > backoffReset {
					bs.delay = backoffInitial // stable long enough, reset
				}
				bs.lastFailure = time.Now()

				select {
				case <-time.After(bs.delay):
				case <-ctx.Done():
					return
				}

				// Double delay for next time, capped.
				bs.delay *= 2
				if bs.delay > backoffMax {
					bs.delay = backoffMax
				}

			case domain.RestartStrategyImmediate:
				// No delay.
			}

			if err := s.runtime.Start(ctx, vm.ID); err != nil {
				log.Error("crash monitor: restart failed", "id", vm.ID, "name", vm.Name, "err", err)
				return
			}
			if err := s.store.UpdateState(ctx, vm.ID, domain.VMStateRunning, time.Now().UTC()); err != nil {
				log.Error("crash monitor: update state", "id", vm.ID, "err", err)
				return
			}
			log.Info("vm restarted", "id", vm.ID, "name", vm.Name, "exit_code", exitCode, "strategy", vm.RestartStrategy)
		})
		if err != nil && ctx.Err() == nil {
			log.Error("crash monitor stopped", "err", err)
		}
	}()
}
