package lifecycle_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"crypto"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/lifecycle"
	"go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
	"go.temporal.io/sdk/testsuite"
)

// ── slogAdapter coverage via NewClient ───────────────────────────────

func TestNewClient_EmptyHostPort(t *testing.T) {
	_, err := lifecycle.NewClient(lifecycle.ClientConfig{})
	if err == nil {
		t.Fatal("expected error for empty host_port")
	}
}

func TestNewClient_DefaultNamespace(t *testing.T) {
	// Temporal Dial is lazy, so this will succeed even with unreachable addr.
	c, err := lifecycle.NewClient(lifecycle.ClientConfig{
		HostPort: "192.0.2.1:7233",
	})
	if err != nil {
		// Some environments may fail on dial.
		t.Skipf("NewClient returned error (may be env-specific): %v", err)
	}
	if c != nil {
		c.Close()
	}
}

func TestNewClientFromSDK(t *testing.T) {
	// Use testsuite to get an SDK client-like mock.
	// NewClientFromSDK wraps it.
	c := lifecycle.NewClientFromSDK(nil, "test-ns")
	if c == nil {
		t.Fatal("NewClientFromSDK returned nil")
	}
}

// ── MintExecutionScopedToken error path ──────────────────────────────

func TestMintExecutionScopedToken_ExchangeError(t *testing.T) {
	exch := &mockExchanger{
		exchangeFn: func(_ context.Context, _ *core.TokenExchangeRequest) (*core.TokenExchangeResponse, error) {
			return nil, fmt.Errorf("signing unavailable")
		},
	}

	acts := lifecycle.NewActivities(exch, &mockTransmitter{}, newMockRevocationIndex(), "unit-abc")

	_, err := acts.MintExecutionScopedToken(context.Background(), core.ExecutionScope{
		Method: "POST",
		URI:    "/internal/signing-key",
		Nonce:  "nonce-1",
	})
	if err == nil {
		t.Fatal("expected error when exchange fails")
	}
}

// ── CheckRevocationStatus error path ─────────────────────────────────

type errorRevocationIndex struct {
	mockRevocationIndex
}

func (m *errorRevocationIndex) IsRevoked(_ context.Context, _ string) (*core.RevocationEntry, error) {
	return nil, fmt.Errorf("database error")
}

func TestCheckRevocationStatus_Error(t *testing.T) {
	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, &errorRevocationIndex{mockRevocationIndex{entries: make(map[string]*core.RevocationEntry)}}, "u1")

	_, err := acts.CheckRevocationStatus(context.Background(), "agent-x")
	if err == nil {
		t.Fatal("expected error from revocation index")
	}
}

// ── StartFromConfig with non-empty HostPort ──────────────────────────

func TestStartFromConfig_WithHost(t *testing.T) {
	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "u1")

	c, w, err := lifecycle.StartFromConfig(lifecycle.ClientConfig{
		HostPort:  "192.0.2.1:7233",
		Namespace: "starfly-test",
	}, acts)
	if err != nil {
		// Temporal dial may or may not fail based on environment.
		t.Skipf("StartFromConfig returned error (env-specific): %v", err)
	}
	if w != nil {
		w.Stop()
	}
	if c != nil {
		c.Close()
	}
}

// ── RotationWorkflow with rollback on exec-token mint failure ────────

func TestRotationWorkflow_MintExecTokenFails(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	failingExch := &mockExchanger{
		exchangeFn: func(_ context.Context, _ *core.TokenExchangeRequest) (*core.TokenExchangeResponse, error) {
			return nil, fmt.Errorf("signing key unavailable")
		},
	}

	km := newMockKeyManager("old-key")
	sharedActs := lifecycle.NewActivities(failingExch, &mockTransmitter{}, newMockRevocationIndex(), "unit-test")
	rotActs := lifecycle.NewRotationActivities(km, sharedActs)

	env.RegisterActivity(sharedActs.EmitLifecycleSignal)
	env.RegisterActivity(sharedActs.MintExecutionScopedToken)
	env.RegisterActivity(rotActs.GenerateAndPublishKey)
	env.RegisterActivity(rotActs.SwapSigningKey)
	env.RegisterActivity(rotActs.VerifyNewKey)
	env.RegisterActivity(rotActs.RemoveKey)
	env.RegisterActivity(rotActs.RollbackToKey)

	params := lifecycle.RotationParams{
		KeyType:            "RSA-2048",
		GracePeriod:        time.Millisecond,
		PropagationTimeout: time.Millisecond,
	}

	env.ExecuteWorkflow(lifecycle.RotationWorkflow, params)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err == nil {
		t.Fatal("expected workflow error from mint failure")
	}
}

// ── RotationWorkflow with default params ─────────────────────────────

func TestRotationWorkflow_DefaultParams(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	km := newMockKeyManager("old-key")
	sharedActs := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "unit-test")
	rotActs := lifecycle.NewRotationActivities(km, sharedActs)

	env.RegisterActivity(sharedActs.EmitLifecycleSignal)
	env.RegisterActivity(sharedActs.MintExecutionScopedToken)
	env.RegisterActivity(rotActs.GenerateAndPublishKey)
	env.RegisterActivity(rotActs.SwapSigningKey)
	env.RegisterActivity(rotActs.VerifyNewKey)
	env.RegisterActivity(rotActs.RemoveKey)
	env.RegisterActivity(rotActs.RollbackToKey)

	// Empty params — should be filled with defaults.
	params := lifecycle.RotationParams{}

	env.ExecuteWorkflow(lifecycle.RotationWorkflow, params)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
}

// ── RollbackToKey error on ActivateKey ───────────────────────────────

func TestRollbackToKey_ActivateError(t *testing.T) {
	km := newMockKeyManager("active-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	err := acts.RollbackToKey("nonexistent-key", "active-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key rollback")
	}
}

// ── DefaultPerformanceThresholds ─────────────────────────────────────

func TestDefaultPerformanceThresholds(t *testing.T) {
	th := lifecycle.DefaultPerformanceThresholds()
	if th.ExchangeP99ms != 15 {
		t.Errorf("ExchangeP99ms = %v, want 15", th.ExchangeP99ms)
	}
	if th.RevocationLookupMs != 1 {
		t.Errorf("RevocationLookupMs = %v, want 1", th.RevocationLookupMs)
	}
	if th.SignalCascadeS != 2 {
		t.Errorf("SignalCascadeS = %v, want 2", th.SignalCascadeS)
	}
}

// ── sha256Hex coverage (via ExecutionScopeForSwap) ───────────────────

func TestExecutionScopeForSwap_NonceUnique(t *testing.T) {
	s1 := lifecycle.ExecutionScopeForSwap("k1", "h1")
	s2 := lifecycle.ExecutionScopeForSwap("k2", "h2")
	if s1.Nonce == s2.Nonce {
		t.Error("nonces should be unique")
	}
}

// ── slogAdapter coverage ─────────────────────────────────────────────
// NewClient creates a slogAdapter internally. We can't access it directly
// from outside the package, but we can verify the adapter works by
// verifying NewClient doesn't panic when logging.

// ── Client methods via mock SDK client ───────────────────────────────

func TestClient_Inner(t *testing.T) {
	mc := tmocks.NewClient(t)
	c := lifecycle.NewClientFromSDK(mc, "test-ns")
	if c.Inner() == nil {
		t.Error("Inner() should return the underlying mock client")
	}
}

func TestClient_Close(t *testing.T) {
	mc := tmocks.NewClient(t)
	mc.On("Close").Return()
	c := lifecycle.NewClientFromSDK(mc, "test-ns")
	c.Close()
	mc.AssertCalled(t, "Close")
}

func TestClient_StartWorkflow(t *testing.T) {
	mc := tmocks.NewClient(t)
	mc.On("ExecuteWorkflow",
		context.Background(),
		client.StartWorkflowOptions{TaskQueue: lifecycle.TaskQueue},
		"TestWorkflow",
		"arg1",
	).Return(nil, nil)

	c := lifecycle.NewClientFromSDK(mc, "test-ns")
	_, err := c.StartWorkflow(context.Background(), client.StartWorkflowOptions{}, "TestWorkflow", "arg1")
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}
}

func TestClient_StartWorkflow_WithTaskQueue(t *testing.T) {
	mc := tmocks.NewClient(t)
	mc.On("ExecuteWorkflow",
		context.Background(),
		client.StartWorkflowOptions{TaskQueue: "custom-queue"},
		"TestWorkflow",
	).Return(nil, nil)

	c := lifecycle.NewClientFromSDK(mc, "test-ns")
	_, err := c.StartWorkflow(context.Background(), client.StartWorkflowOptions{TaskQueue: "custom-queue"}, "TestWorkflow")
	if err != nil {
		t.Fatalf("StartWorkflow: %v", err)
	}
}

func TestClient_SignalWorkflow(t *testing.T) {
	mc := tmocks.NewClient(t)
	mc.On("SignalWorkflow",
		context.Background(),
		"wf-id", "", "signal-name", "payload",
	).Return(nil)

	c := lifecycle.NewClientFromSDK(mc, "test-ns")
	err := c.SignalWorkflow(context.Background(), "wf-id", "signal-name", "payload")
	if err != nil {
		t.Fatalf("SignalWorkflow: %v", err)
	}
}

// ── ComplianceScanWorkflow with critical findings + auto-remediate ────

func TestComplianceScanWorkflow_CriticalAutoRemediate(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	policy := lifecycle.DefaultCompliancePolicy()
	policy.RequireDPoP = true // Changes DPoP finding
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

// ── RotationWorkflow swap-failed rollback ────────────────────────────

func TestRotationWorkflow_SwapFails(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	km := &failActivateKeyManager{initial: "old-key"}
	sharedActs := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "unit-test")
	rotActs := lifecycle.NewRotationActivities(km, sharedActs)

	env.RegisterActivity(sharedActs.EmitLifecycleSignal)
	env.RegisterActivity(sharedActs.MintExecutionScopedToken)
	env.RegisterActivity(rotActs.GenerateAndPublishKey)
	env.RegisterActivity(rotActs.SwapSigningKey)
	env.RegisterActivity(rotActs.VerifyNewKey)
	env.RegisterActivity(rotActs.RemoveKey)
	env.RegisterActivity(rotActs.RollbackToKey)

	params := lifecycle.RotationParams{
		KeyType:            "RSA-2048",
		GracePeriod:        time.Millisecond,
		PropagationTimeout: time.Millisecond,
	}

	env.ExecuteWorkflow(lifecycle.RotationWorkflow, params)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err == nil {
		t.Fatal("expected workflow error from swap failure")
	}
}

// failActivateKeyManager always fails ActivateKey.
type failActivateKeyManager struct {
	initial string
	keys    map[string]bool
}

func (m *failActivateKeyManager) ActiveKid() string { return m.initial }
func (m *failActivateKeyManager) AddKey(kid string, _ crypto.Signer, _ crypto.PublicKey) error {
	if m.keys == nil {
		m.keys = make(map[string]bool)
	}
	m.keys[kid] = true
	return nil
}
func (m *failActivateKeyManager) ActivateKey(_ string) error {
	return fmt.Errorf("activation failed")
}
func (m *failActivateKeyManager) RemoveKey(kid string) error {
	delete(m.keys, kid)
	return nil
}

// ── StartFromConfig with mock ────────────────────────────────────────

func TestStartFromConfig_WithValidHost(t *testing.T) {
	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "u1")

	c, w, err := lifecycle.StartFromConfig(lifecycle.ClientConfig{
		HostPort:  "192.0.2.1:7233",
		Namespace: "test",
	}, acts)
	if err != nil {
		t.Skipf("Temporal dial failed (expected in test envs): %v", err)
	}
	if c == nil || w == nil {
		t.Skip("StartFromConfig returned nil (lazy dial)")
	}
	w.Stop()
	c.Close()
}
