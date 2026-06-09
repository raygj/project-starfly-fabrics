package lifecycle_test

import (
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/lifecycle"
	"go.temporal.io/sdk/testsuite"
)

func TestComplianceActivities_EvaluatePolicy_Defaults(t *testing.T) {
	policy := lifecycle.DefaultCompliancePolicy()
	acts := lifecycle.NewComplianceActivities(nil, policy)

	findings, err := acts.EvaluatePolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Default policy should produce info-level findings only (all within bounds).
	for _, f := range findings {
		if f.Severity == "critical" {
			t.Errorf("unexpected critical finding: %s", f.Description)
		}
	}

	// Should have at least TTL, delegation, and DPoP findings.
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(findings))
	}
}

func TestComplianceActivities_EvaluatePolicy_LongTTL(t *testing.T) {
	policy := lifecycle.DefaultCompliancePolicy()
	policy.MaxTTL = 30 * time.Minute // Too long

	acts := lifecycle.NewComplianceActivities(nil, policy)
	findings, err := acts.EvaluatePolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundWarning := false
	for _, f := range findings {
		if f.Category == "ttl" && f.Severity == "warning" {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Error("expected warning finding for long TTL")
	}
}

func TestComplianceActivities_EvaluatePolicy_ZeroTTL(t *testing.T) {
	policy := lifecycle.DefaultCompliancePolicy()
	policy.MaxTTL = 0

	acts := lifecycle.NewComplianceActivities(nil, policy)
	findings, err := acts.EvaluatePolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundWarning := false
	for _, f := range findings {
		if f.Category == "ttl" && f.Severity == "warning" {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Error("expected warning finding for zero TTL")
	}
}

func TestComplianceActivities_EvaluatePolicy_DeepDelegation(t *testing.T) {
	policy := lifecycle.DefaultCompliancePolicy()
	policy.MaxDelegationDepth = 20

	acts := lifecycle.NewComplianceActivities(nil, policy)
	findings, err := acts.EvaluatePolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundWarning := false
	for _, f := range findings {
		if f.Category == "delegation" && f.Severity == "warning" {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Error("expected warning finding for deep delegation")
	}
}

func TestComplianceActivities_CheckPerformance_DefaultThresholds(t *testing.T) {
	policy := lifecycle.DefaultCompliancePolicy()
	acts := lifecycle.NewComplianceActivities(nil, policy)

	findings, err := acts.CheckPerformance()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Default thresholds are set, so findings should be info-level.
	for _, f := range findings {
		if f.Severity == "warning" || f.Severity == "critical" {
			t.Errorf("unexpected non-info finding: %s (%s)", f.Description, f.Severity)
		}
	}
}

func TestComplianceActivities_CheckPerformance_MissingThresholds(t *testing.T) {
	policy := lifecycle.DefaultCompliancePolicy()
	policy.Performance = lifecycle.PerformanceThresholds{} // All zero

	acts := lifecycle.NewComplianceActivities(nil, policy)
	findings, err := acts.CheckPerformance()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	warningCount := 0
	for _, f := range findings {
		if f.Severity == "warning" {
			warningCount++
		}
	}
	if warningCount < 3 {
		t.Errorf("expected 3 warnings for missing thresholds, got %d", warningCount)
	}
}

func TestComplianceActivities_CheckRevocationHealth(t *testing.T) {
	policy := lifecycle.DefaultCompliancePolicy()
	acts := lifecycle.NewComplianceActivities(nil, policy)

	findings, err := acts.CheckRevocationHealth()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one health finding")
	}
	if findings[0].Severity != "info" {
		t.Errorf("expected info severity, got %s", findings[0].Severity)
	}
}

func TestDefaultScanParams(t *testing.T) {
	p := lifecycle.DefaultScanParams()
	if !p.EmitFindings {
		t.Error("EmitFindings should default to true")
	}
	if p.AutoRemediate {
		t.Error("AutoRemediate should default to false")
	}
}

func TestDefaultCompliancePolicy(t *testing.T) {
	p := lifecycle.DefaultCompliancePolicy()
	if p.MaxTTL != 5*time.Minute {
		t.Errorf("MaxTTL = %v, want 5m", p.MaxTTL)
	}
	if p.MaxDelegationDepth != 5 {
		t.Errorf("MaxDelegationDepth = %d, want 5", p.MaxDelegationDepth)
	}
	if p.Performance.ExchangeP99ms != 15 {
		t.Errorf("ExchangeP99ms = %v, want 15", p.Performance.ExchangeP99ms)
	}
}

func TestComplianceScanWorkflow_HappyPath(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	policy := lifecycle.DefaultCompliancePolicy()
	sharedActs := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "unit-test")
	compActs := lifecycle.NewComplianceActivities(sharedActs, policy)

	env.RegisterActivity(sharedActs.EmitLifecycleSignal)
	env.RegisterActivity(sharedActs.RevokeCredential)
	env.RegisterActivity(compActs.EvaluatePolicy)
	env.RegisterActivity(compActs.CheckPerformance)
	env.RegisterActivity(compActs.CheckRevocationHealth)

	params := lifecycle.DefaultScanParams()
	env.ExecuteWorkflow(lifecycle.ComplianceScanWorkflow, params)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}

	var report lifecycle.ScanReport
	if err := env.GetWorkflowResult(&report); err != nil {
		t.Fatalf("failed to get workflow result: %v", err)
	}
	if report.TotalCredentials == 0 {
		t.Error("expected at least some credential checks in report")
	}
}

func TestComplianceScanWorkflow_WithAutoRemediate(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	// Use a policy that will produce critical findings.
	policy := lifecycle.DefaultCompliancePolicy()
	policy.MaxTTL = 0 // Will produce a warning, not critical — test just verifies no panic.

	sharedActs := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "unit-test")
	compActs := lifecycle.NewComplianceActivities(sharedActs, policy)

	env.RegisterActivity(sharedActs.EmitLifecycleSignal)
	env.RegisterActivity(sharedActs.RevokeCredential)
	env.RegisterActivity(compActs.EvaluatePolicy)
	env.RegisterActivity(compActs.CheckPerformance)
	env.RegisterActivity(compActs.CheckRevocationHealth)

	params := lifecycle.ScanParams{
		EmitFindings:  true,
		AutoRemediate: true,
	}
	env.ExecuteWorkflow(lifecycle.ComplianceScanWorkflow, params)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
}

func TestComplianceScanWorkflow_NoEmitFindings(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	policy := lifecycle.DefaultCompliancePolicy()
	sharedActs := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "unit-test")
	compActs := lifecycle.NewComplianceActivities(sharedActs, policy)

	env.RegisterActivity(sharedActs.EmitLifecycleSignal)
	env.RegisterActivity(sharedActs.RevokeCredential)
	env.RegisterActivity(compActs.EvaluatePolicy)
	env.RegisterActivity(compActs.CheckPerformance)
	env.RegisterActivity(compActs.CheckRevocationHealth)

	params := lifecycle.ScanParams{
		EmitFindings:  false,
		AutoRemediate: false,
	}
	env.ExecuteWorkflow(lifecycle.ComplianceScanWorkflow, params)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
}
