// Package operator implements the Starfly CRD operator.
package operator

import (
	"context"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// FabricConnection bridges the operator controller to a running Starfly fabric.
// The controller uses this interface to read current state and apply convergence actions.
type FabricConnection interface {
	// CurrentManifest returns the fabric's current soul manifest.
	CurrentManifest(ctx context.Context) (*soul.SoulManifest, error)

	// ApplyAction executes a single convergence action against the fabric.
	ApplyAction(ctx context.Context, action soul.ConvergenceAction) error

	// ApplyPlan executes an entire convergence plan with dependency ordering
	// and first-failure-stops semantics. Consumers should prefer this over
	// looping ApplyAction directly — it encapsulates ordering and error handling.
	// Returns an ApplyResult summarizing what was applied.
	ApplyPlan(ctx context.Context, plan *soul.ConvergencePlan) (*ApplyResult, error)

	// Health returns the current health status of the fabric.
	Health(ctx context.Context) (*HealthStatus, error)
}

// ApplyResult summarizes a plan execution.
type ApplyResult struct {
	// ActionsApplied is the number of actions successfully applied.
	ActionsApplied int
	// ActionsTotal is the total number of actions in the plan.
	ActionsTotal int
	// Duration is how long the plan execution took.
	Duration time.Duration
}

// HealthStatus represents the fabric's operational health.
type HealthStatus struct {
	// Healthy is true if the fabric is operational.
	Healthy bool
	// TrustDomainsActive is the count of active trust domains.
	TrustDomainsActive int
	// SigningKeysActive is the count of active signing keys.
	SigningKeysActive int
	// SSFStreamsActive is the count of active SSF streams.
	SSFStreamsActive int
	// SoulSequence is the current soul manifest sequence.
	SoulSequence uint64
	// Message is an optional status message.
	Message string
}
