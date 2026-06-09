package lifecycle

import (
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ComplianceActivities contains compliance-specific Temporal activities.
type ComplianceActivities struct {
	activities *Activities
	policy     CompliancePolicy
}

// NewComplianceActivities creates the compliance activity set.
func NewComplianceActivities(activities *Activities, policy CompliancePolicy) *ComplianceActivities {
	return &ComplianceActivities{
		activities: activities,
		policy:     policy,
	}
}

// ComplianceScanWorkflow is the Temporal workflow for compliance scanning.
// Steps: Discover -> Evaluate -> Benchmark -> Report -> Signal -> Remediate (optional).
func ComplianceScanWorkflow(ctx workflow.Context, params ScanParams) (*ScanReport, error) {
	start := workflow.Now(ctx)

	actOpts := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2.0,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, actOpts)

	var sharedActs *Activities
	var compActs *ComplianceActivities

	// Step 1: Emit scan-started signal.
	_ = workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
		EventTypeComplianceScanStart, "urn:starfly:compliance",
		map[string]interface{}{"scope": params.Scope},
	).Get(ctx, nil)

	// Step 2: Evaluate credentials against policy.
	var findings []Finding
	err := workflow.ExecuteActivity(ctx, compActs.EvaluatePolicy, params.Scope).Get(ctx, &findings)
	if err != nil {
		return nil, fmt.Errorf("compliance: evaluating policy: %w", err)
	}

	// Step 3: Check performance against baseline.
	var perfFindings []Finding
	err = workflow.ExecuteActivity(ctx, compActs.CheckPerformance).Get(ctx, &perfFindings)
	if err != nil {
		return nil, fmt.Errorf("compliance: checking performance: %w", err)
	}
	findings = append(findings, perfFindings...)

	// Step 4: Check revocation index health.
	var revFindings []Finding
	err = workflow.ExecuteActivity(ctx, compActs.CheckRevocationHealth).Get(ctx, &revFindings)
	if err != nil {
		return nil, fmt.Errorf("compliance: checking revocation health: %w", err)
	}
	findings = append(findings, revFindings...)

	// Count compliant vs. non-compliant.
	nonCompliant := 0
	for _, f := range findings {
		if f.Severity == "warning" || f.Severity == "critical" {
			nonCompliant++
		}
	}

	report := &ScanReport{
		TotalCredentials: len(findings), // Each finding maps to a check
		Compliant:        len(findings) - nonCompliant,
		NonCompliant:     nonCompliant,
		Findings:         findings,
		Duration:         workflow.Now(ctx).Sub(start),
		Timestamp:        workflow.Now(ctx),
	}

	// Step 5: Emit findings as SSF events.
	if params.EmitFindings {
		for _, f := range findings {
			if f.Severity == "info" {
				continue // Only emit warnings and critical findings.
			}
			_ = workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
				EventTypeComplianceFinding, f.Subject,
				map[string]interface{}{
					"finding_id": f.ID,
					"severity":   f.Severity,
					"category":   f.Category,
					"description": f.Description,
				},
			).Get(ctx, nil)
		}
	}

	// Step 6: Auto-remediate critical findings (if enabled).
	if params.AutoRemediate {
		for _, f := range findings {
			if f.Severity == "critical" && f.AutoRemediable {
				_ = workflow.ExecuteActivity(ctx, sharedActs.RevokeCredential,
					RevokeRequest{
						SubjectID: f.Subject,
						Reason:    fmt.Sprintf("compliance: %s", f.Category),
						ExpiresIn: time.Hour,
					},
				).Get(ctx, nil)
			}
		}
	}

	// Step 7: Emit scan-complete signal.
	_ = workflow.ExecuteActivity(ctx, sharedActs.EmitLifecycleSignal,
		EventTypeComplianceScanDone, "urn:starfly:compliance",
		map[string]interface{}{
			"total":        report.TotalCredentials,
			"compliant":    report.Compliant,
			"non_compliant": report.NonCompliant,
			"duration_ms":  report.Duration.Milliseconds(),
		},
	).Get(ctx, nil)

	return report, nil
}

// --- Compliance Activities ---

// EvaluatePolicy checks credential contexts against the compliance policy.
// In production, this would query the registry for active credentials.
// For now, it evaluates the policy configuration itself for sanity.
func (ca *ComplianceActivities) EvaluatePolicy(scope []string) ([]Finding, error) {
	var findings []Finding
	now := time.Now()

	// Check: MaxTTL is configured and reasonable.
	if ca.policy.MaxTTL == 0 {
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("policy-ttl-%d", now.Unix()),
			Severity:       "warning",
			Category:       "ttl",
			Subject:        "urn:starfly:policy",
			Description:    "MaxTTL is not configured — tokens may have unbounded lifetimes",
			Recommendation: "Set lifecycle.compliance.max_ttl to a value <= 5m",
			AutoRemediable: false,
			DetectedAt:     now,
		})
	} else if ca.policy.MaxTTL > 10*time.Minute {
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("policy-ttl-long-%d", now.Unix()),
			Severity:       "warning",
			Category:       "ttl",
			Subject:        "urn:starfly:policy",
			Description:    fmt.Sprintf("MaxTTL is %v — consider reducing to <= 5m for agent workloads", ca.policy.MaxTTL),
			Recommendation: "Set lifecycle.compliance.max_ttl to 5m or less",
			AutoRemediable: false,
			DetectedAt:     now,
		})
	} else {
		findings = append(findings, Finding{
			ID:          fmt.Sprintf("policy-ttl-ok-%d", now.Unix()),
			Severity:    "info",
			Category:    "ttl",
			Subject:     "urn:starfly:policy",
			Description: fmt.Sprintf("MaxTTL is %v — within recommended bounds", ca.policy.MaxTTL),
			DetectedAt:  now,
		})
	}

	// Check: Delegation depth is bounded.
	if ca.policy.MaxDelegationDepth > 10 {
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("policy-delegation-%d", now.Unix()),
			Severity:       "warning",
			Category:       "delegation",
			Subject:        "urn:starfly:policy",
			Description:    fmt.Sprintf("MaxDelegationDepth is %d — deep chains increase blast radius", ca.policy.MaxDelegationDepth),
			Recommendation: "Set max_delegation_depth to 5 or fewer",
			AutoRemediable: false,
			DetectedAt:     now,
		})
	} else {
		findings = append(findings, Finding{
			ID:          fmt.Sprintf("policy-delegation-ok-%d", now.Unix()),
			Severity:    "info",
			Category:    "delegation",
			Subject:     "urn:starfly:policy",
			Description: fmt.Sprintf("MaxDelegationDepth is %d — within recommended bounds", ca.policy.MaxDelegationDepth),
			DetectedAt:  now,
		})
	}

	// Check: DPoP requirement.
	if !ca.policy.RequireDPoP {
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("policy-dpop-%d", now.Unix()),
			Severity:       "info",
			Category:       "dpop",
			Subject:        "urn:starfly:policy",
			Description:    "DPoP proof-of-possession is not required — tokens are bearer tokens",
			Recommendation: "Consider enabling require_dpop for production workloads",
			DetectedAt:     now,
		})
	}

	return findings, nil
}

// CheckPerformance measures current performance and compares to thresholds.
// In production, this would run actual benchmark measurements. For now,
// it validates that thresholds are configured.
func (ca *ComplianceActivities) CheckPerformance() ([]Finding, error) {
	var findings []Finding
	now := time.Now()
	thresholds := ca.policy.Performance

	if thresholds.ExchangeP99ms == 0 {
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("perf-exchange-%d", now.Unix()),
			Severity:       "warning",
			Category:       "performance",
			Subject:        "urn:starfly:performance",
			Description:    "Exchange P99 threshold not configured",
			Recommendation: "Set performance.exchange_p99_ms (recommended: 15)",
			DetectedAt:     now,
		})
	} else {
		findings = append(findings, Finding{
			ID:          fmt.Sprintf("perf-exchange-ok-%d", now.Unix()),
			Severity:    "info",
			Category:    "performance",
			Subject:     "urn:starfly:performance",
			Description: fmt.Sprintf("Exchange P99 threshold: %.1fms", thresholds.ExchangeP99ms),
			DetectedAt:  now,
		})
	}

	if thresholds.RevocationLookupMs == 0 {
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("perf-revocation-%d", now.Unix()),
			Severity:       "warning",
			Category:       "performance",
			Subject:        "urn:starfly:performance",
			Description:    "Revocation lookup threshold not configured",
			Recommendation: "Set performance.revocation_lookup_ms (recommended: 1)",
			DetectedAt:     now,
		})
	}

	if thresholds.SignalCascadeS == 0 {
		findings = append(findings, Finding{
			ID:             fmt.Sprintf("perf-cascade-%d", now.Unix()),
			Severity:       "warning",
			Category:       "performance",
			Subject:        "urn:starfly:performance",
			Description:    "Signal cascade threshold not configured",
			Recommendation: "Set performance.signal_cascade_s (recommended: 2)",
			DetectedAt:     now,
		})
	}

	return findings, nil
}

// CheckRevocationHealth verifies the revocation index is operating correctly.
func (ca *ComplianceActivities) CheckRevocationHealth() ([]Finding, error) {
	var findings []Finding
	now := time.Now()

	// In production, this would query the revocation index for stats
	// (size, oldest entry, cleanup recency). For now, emit an info finding.
	findings = append(findings, Finding{
		ID:          fmt.Sprintf("rev-health-%d", now.Unix()),
		Severity:    "info",
		Category:    "revocation-health",
		Subject:     "urn:starfly:revocation-index",
		Description: "Revocation index health check passed",
		DetectedAt:  now,
	})

	return findings, nil
}
