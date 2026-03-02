// SPDX-License-Identifier: Apache-2.0

// Package app contains application use-cases that orchestrate domain ports.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/charmbracelet/log"
	"github.com/google/uuid"

	"github.com/Work-Fort/Nexus/internal/domain"
)

// SharkfinWebhook is the payload Sharkfin POSTs on mentions and DMs.
type SharkfinWebhook struct {
	Event       string `json:"event"`
	Recipient   string `json:"recipient"`
	Channel     string `json:"channel"`
	ChannelType string `json:"channel_type"`
	From        string `json:"from"`
	MessageID   int64  `json:"message_id"`
	SentAt      string `json:"sent_at"`
}

// VMServiceConfig holds configurable defaults for the VM service.
type VMServiceConfig struct {
	DefaultImage   string
	DefaultRuntime string
}

// VMService orchestrates VM lifecycle operations.
type VMService struct {
	store   domain.VMStore
	runtime domain.Runtime
	network domain.Network
	config  VMServiceConfig
}

// NewVMService creates a VMService with the given ports and config.
func NewVMService(store domain.VMStore, runtime domain.Runtime, network domain.Network, opts ...func(*VMService)) *VMService {
	svc := &VMService{
		store:   store,
		runtime: runtime,
		network: network,
		config: VMServiceConfig{
			DefaultImage:   "docker.io/library/alpine:latest",
			DefaultRuntime: "io.containerd.runc.v2",
		},
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// WithConfig sets the VMService configuration.
func WithConfig(cfg VMServiceConfig) func(*VMService) {
	return func(s *VMService) {
		s.config = cfg
	}
}

// CreateVM validates parameters, creates a container via the runtime, and
// persists the VM record.
func (s *VMService) CreateVM(ctx context.Context, params domain.CreateVMParams) (*domain.VM, error) {
	if !domain.ValidRole(params.Role) {
		return nil, fmt.Errorf("invalid role %q: %w", params.Role, domain.ErrValidation)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("name is required: %w", domain.ErrValidation)
	}
	if params.Image == "" {
		params.Image = s.config.DefaultImage
	}
	if params.Runtime == "" {
		params.Runtime = s.config.DefaultRuntime
	}

	vm := &domain.VM{
		ID:        uuid.New().String(),
		Name:      params.Name,
		Role:      params.Role,
		State:     domain.VMStateCreated,
		Image:     params.Image,
		Runtime:   params.Runtime,
		CreatedAt: time.Now().UTC(),
	}

	netInfo, err := s.network.Setup(ctx, vm.ID)
	if err != nil {
		return nil, fmt.Errorf("network setup: %w", err)
	}
	vm.IP = netInfo.IP
	vm.Gateway = netInfo.Gateway
	vm.NetNSPath = netInfo.NetNSPath

	var createOpts []domain.CreateOpt
	if netInfo.NetNSPath != "" {
		createOpts = append(createOpts, domain.WithNetNS(netInfo.NetNSPath))
	}

	if err := s.runtime.Create(ctx, vm.ID, vm.Image, vm.Runtime, createOpts...); err != nil {
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck // best-effort rollback
		return nil, fmt.Errorf("runtime create: %w", err)
	}

	if err := s.store.Create(ctx, vm); err != nil {
		s.runtime.Delete(ctx, vm.ID)    //nolint:errcheck // best-effort rollback
		s.network.Teardown(ctx, vm.ID) //nolint:errcheck // best-effort rollback
		return nil, fmt.Errorf("store create: %w", err)
	}

	log.Info("vm created", "id", vm.ID, "name", vm.Name, "role", vm.Role, "ip", vm.IP)
	return vm, nil
}

// GetVM retrieves a VM by ID.
func (s *VMService) GetVM(ctx context.Context, id string) (*domain.VM, error) {
	return s.store.Get(ctx, id)
}

// ListVMs returns VMs matching the filter.
func (s *VMService) ListVMs(ctx context.Context, filter domain.VMFilter) ([]*domain.VM, error) {
	return s.store.List(ctx, filter)
}

// StartVM starts a created or stopped VM.
func (s *VMService) StartVM(ctx context.Context, id string) error {
	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		return domain.ErrInvalidState
	}

	if err := s.runtime.Start(ctx, id); err != nil {
		return fmt.Errorf("runtime start: %w", err)
	}

	if err := s.store.UpdateState(ctx, id, domain.VMStateRunning, time.Now().UTC()); err != nil {
		return fmt.Errorf("store update: %w", err)
	}

	log.Info("vm started", "id", id)
	return nil
}

// StopVM stops a running VM.
func (s *VMService) StopVM(ctx context.Context, id string) error {
	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if vm.State != domain.VMStateRunning {
		return domain.ErrInvalidState
	}

	if err := s.runtime.Stop(ctx, id); err != nil {
		return fmt.Errorf("runtime stop: %w", err)
	}

	if err := s.store.UpdateState(ctx, id, domain.VMStateStopped, time.Now().UTC()); err != nil {
		return fmt.Errorf("store update: %w", err)
	}

	log.Info("vm stopped", "id", id)
	return nil
}

// DeleteVM stops the container if running, then removes it and its store record.
func (s *VMService) DeleteVM(ctx context.Context, id string) error {
	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if vm.State == domain.VMStateRunning {
		if err := s.runtime.Stop(ctx, id); err != nil {
			log.Warn("runtime stop before delete failed", "id", id, "err", err)
		}
	}
	if err := s.runtime.Delete(ctx, id); err != nil {
		log.Warn("runtime delete failed", "id", id, "err", err)
	}

	if err := s.network.Teardown(ctx, id); err != nil {
		log.Warn("network teardown failed", "id", id, "err", err)
	}

	if err := s.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("store delete: %w", err)
	}

	log.Info("vm deleted", "id", id)
	return nil
}

// ExecVM runs a command in a running VM.
func (s *VMService) ExecVM(ctx context.Context, id string, cmd []string) (*domain.ExecResult, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("cmd is required: %w", domain.ErrValidation)
	}

	vm, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if vm.State != domain.VMStateRunning {
		return nil, domain.ErrInvalidState
	}

	return s.runtime.Exec(ctx, id, cmd)
}

// ResetNetwork deletes the bridge and clears CNI state. Refuses if any VMs exist.
func (s *VMService) ResetNetwork(ctx context.Context) error {
	vms, err := s.store.List(ctx, domain.VMFilter{})
	if err != nil {
		return fmt.Errorf("list vms: %w", err)
	}
	if len(vms) > 0 {
		return fmt.Errorf("%d VM(s) exist, delete them first: %w", len(vms), domain.ErrNetworkInUse)
	}
	return s.network.ResetNetwork(ctx)
}

// HandleWebhook processes a Sharkfin webhook. It finds or creates an agent
// VM for the recipient, and ensures it's running.
func (s *VMService) HandleWebhook(ctx context.Context, wh SharkfinWebhook) error {
	log.Info("webhook received", "event", wh.Event, "recipient", wh.Recipient, "from", wh.From, "channel", wh.Channel)

	vm, err := s.store.GetByName(ctx, wh.Recipient)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("lookup recipient: %w", err)
	}

	if vm == nil {
		vm, err = s.CreateVM(ctx, domain.CreateVMParams{
			Name:  wh.Recipient,
			Role:  domain.VMRoleAgent,
			Image: s.config.DefaultImage,
		})
		if err != nil {
			return fmt.Errorf("create agent: %w", err)
		}
	}

	switch vm.State {
	case domain.VMStateRunning:
		log.Info("agent already running", "name", wh.Recipient)
		return nil
	case domain.VMStateCreated, domain.VMStateStopped:
		if err := s.StartVM(ctx, vm.ID); err != nil {
			return fmt.Errorf("start agent: %w", err)
		}
		log.Info("agent started", "name", wh.Recipient)
		return nil
	default:
		return fmt.Errorf("unexpected state %q for %s", vm.State, wh.Recipient)
	}
}
