// SPDX-License-Identifier: GPL-3.0-or-later

package app

import (
	"context"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

// HealthStatus represents the health state of a component or the system.
type HealthStatus string

const (
	StatusHealthy   HealthStatus = "healthy"
	StatusDegraded  HealthStatus = "degraded"
	StatusUnhealthy HealthStatus = "unhealthy"
)

// CheckResult holds the outcome of a single health check invocation.
type CheckResult struct {
	Status  HealthStatus `json:"status"`
	Message string       `json:"message"`
}

// HealthCheck defines a named, periodic health probe.
type HealthCheck interface {
	Name() string
	Interval() time.Duration
	Check(ctx context.Context) CheckResult
}

// HealthReport is the aggregate health state across all registered checks.
type HealthReport struct {
	Status HealthStatus           `json:"status"`
	Checks map[string]CheckResult `json:"checks"`
}

// HealthService manages health checks with periodic background evaluation.
type HealthService struct {
	checks  []HealthCheck
	results map[string]CheckResult
	mu      sync.RWMutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewHealthService creates a HealthService with the given checks.
// All check results are initialized to "pending" until Start is called.
func NewHealthService(checks ...HealthCheck) *HealthService {
	results := make(map[string]CheckResult, len(checks))
	for _, c := range checks {
		results[c.Name()] = CheckResult{Status: "pending", Message: "not yet checked"}
	}
	return &HealthService{
		checks:  checks,
		results: results,
	}
}

// Start runs all checks once synchronously, then starts periodic background
// goroutines that re-evaluate each check on its own interval.
func (h *HealthService) Start(ctx context.Context) {
	// Run all checks once synchronously so Status() is immediately useful.
	for _, c := range h.checks {
		result := c.Check(ctx)
		h.mu.Lock()
		h.results[c.Name()] = result
		h.mu.Unlock()
		log.Info("health check initial result", "check", c.Name(), "status", result.Status, "message", result.Message)
	}

	ctx, h.cancel = context.WithCancel(ctx)

	for _, c := range h.checks {
		h.wg.Add(1)
		go h.runCheck(ctx, c)
	}
}

// Stop cancels background goroutines and waits for them to finish.
func (h *HealthService) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
	h.wg.Wait()
}

// Status returns an aggregate health report from cached check results.
// Aggregation: any unhealthy -> unhealthy, any degraded -> degraded, else healthy.
func (h *HealthService) Status() HealthReport {
	h.mu.RLock()
	defer h.mu.RUnlock()

	checks := make(map[string]CheckResult, len(h.results))
	aggregate := StatusHealthy
	for name, r := range h.results {
		checks[name] = r
		switch {
		case r.Status == StatusUnhealthy:
			aggregate = StatusUnhealthy
		case r.Status == StatusDegraded && aggregate != StatusUnhealthy:
			aggregate = StatusDegraded
		}
	}

	return HealthReport{
		Status: aggregate,
		Checks: checks,
	}
}

// runCheck periodically evaluates a health check and updates the cached result.
// It logs when a check's status changes.
func (h *HealthService) runCheck(ctx context.Context, c HealthCheck) {
	defer h.wg.Done()
	ticker := time.NewTicker(c.Interval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result := c.Check(ctx)

			h.mu.Lock()
			prev := h.results[c.Name()]
			h.results[c.Name()] = result
			h.mu.Unlock()

			if prev.Status != result.Status {
				log.Info("health check status changed", "check", c.Name(), "from", prev.Status, "to", result.Status, "message", result.Message)
			}
		}
	}
}
