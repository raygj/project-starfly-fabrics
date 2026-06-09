package operator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// ExecutePlan executes convergence actions in dependency order via ApplyAction.
// This is the standalone function form — FabricConnection.ApplyPlan delegates here.
// Actions are applied sequentially: signing keys first, then trust domains,
// then SSF streams, then revocations. On failure, remaining actions are skipped.
func ExecutePlan(ctx context.Context, conn FabricConnection, plan *soul.ConvergencePlan) (*ApplyResult, error) {
	result := &ApplyResult{ActionsTotal: len(plan.Actions)}
	if plan.IsEmpty() {
		return result, nil
	}

	start := time.Now()

	// Sort actions by priority: keys → domains → streams → revocations.
	ordered := sortActions(plan.Actions)
	result.ActionsTotal = len(ordered)

	for _, action := range ordered {
		slog.Info("applying convergence action",
			"type", action.Type,
			"target", action.Target,
			"description", action.Description,
		)

		if err := conn.ApplyAction(ctx, action); err != nil {
			result.Duration = time.Since(start)
			return result, fmt.Errorf("action %s (%s) failed after %d/%d applied: %w",
				action.Type, action.Target, result.ActionsApplied, result.ActionsTotal, err)
		}
		result.ActionsApplied++
	}

	result.Duration = time.Since(start)
	slog.Info("convergence plan applied",
		"actions_applied", result.ActionsApplied,
		"duration", result.Duration,
	)
	return result, nil
}

// sortActions orders actions by execution priority.
// The order ensures dependencies are satisfied:
// 1. Signing key changes (keys must exist before trust domains reference them)
// 2. Trust domain changes
// 3. SSF stream changes
// 4. Revocation handling
func sortActions(actions []soul.ConvergenceAction) []soul.ConvergenceAction {
	sorted := make([]soul.ConvergenceAction, 0, len(actions))

	// Phase 1: Signing keys.
	for _, a := range actions {
		if a.Type == soul.ActionRotateSigningKey {
			sorted = append(sorted, a)
		}
	}

	// Phase 2: Trust domains.
	for _, a := range actions {
		switch a.Type {
		case soul.ActionAddTrustDomain, soul.ActionUpdateTrustDomain, soul.ActionRemoveTrustDomain:
			sorted = append(sorted, a)
		}
	}

	// Phase 3: SSF streams.
	for _, a := range actions {
		switch a.Type {
		case soul.ActionAddSSFStream, soul.ActionRemoveSSFStream:
			sorted = append(sorted, a)
		}
	}

	// Phase 4: Federation peers.
	for _, a := range actions {
		switch a.Type {
		case soul.ActionAddPeer, soul.ActionRemovePeer:
			sorted = append(sorted, a)
		}
	}

	// Phase 5: Revocations.
	for _, a := range actions {
		switch a.Type {
		case soul.ActionImportRevocations, soul.ActionResetRevocations:
			sorted = append(sorted, a)
		}
	}

	return sorted
}
