package lifecycle_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/lifecycle"
	"go.temporal.io/sdk/testsuite"
)

// mockKeyManager implements lifecycle.SigningKeyManager for testing.
type mockKeyManager struct {
	mu        sync.Mutex
	activeKid string
	keys      map[string]struct {
		priv crypto.Signer
		pub  crypto.PublicKey
	}
}

func newMockKeyManager(initialKid string) *mockKeyManager {
	km := &mockKeyManager{
		activeKid: initialKid,
		keys: make(map[string]struct {
			priv crypto.Signer
			pub  crypto.PublicKey
		}),
	}
	// Add initial key.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	km.keys[initialKid] = struct {
		priv crypto.Signer
		pub  crypto.PublicKey
	}{priv, &priv.PublicKey}
	return km
}

func (m *mockKeyManager) ActiveKid() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeKid
}

func (m *mockKeyManager) AddKey(kid string, priv crypto.Signer, pub crypto.PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[kid] = struct {
		priv crypto.Signer
		pub  crypto.PublicKey
	}{priv, pub}
	return nil
}

func (m *mockKeyManager) ActivateKey(kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[kid]; !ok {
		return fmt.Errorf("key %s not found", kid)
	}
	m.activeKid = kid
	return nil
}

func (m *mockKeyManager) RemoveKey(kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if kid == m.activeKid {
		return fmt.Errorf("cannot remove active key %s", kid)
	}
	delete(m.keys, kid)
	return nil
}

func TestRotationActivities_GenerateAndPublishKey_RSA(t *testing.T) {
	km := newMockKeyManager("old-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	kid, err := acts.GenerateAndPublishKey("RSA-2048")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kid == "" {
		t.Fatal("empty kid returned")
	}
	// Key should be in keyring but not active.
	if km.ActiveKid() == kid {
		t.Error("new key should not be active yet")
	}
}

func TestRotationActivities_GenerateAndPublishKey_EC(t *testing.T) {
	km := newMockKeyManager("old-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	kid, err := acts.GenerateAndPublishKey("EC-P256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kid == "" {
		t.Fatal("empty kid returned")
	}
}

func TestRotationActivities_GenerateAndPublishKey_UnsupportedType(t *testing.T) {
	km := newMockKeyManager("old-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	_, err := acts.GenerateAndPublishKey("DSA-1024")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestRotationActivities_SwapSigningKey(t *testing.T) {
	km := newMockKeyManager("old-key")
	// Add new key to keyring.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = km.AddKey("new-key", priv, &priv.PublicKey)

	acts := lifecycle.NewRotationActivities(km, nil)

	oldKid, err := acts.SwapSigningKey("new-key", "exec-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if oldKid != "old-key" {
		t.Errorf("old kid = %q, want old-key", oldKid)
	}
	if km.ActiveKid() != "new-key" {
		t.Errorf("active kid = %q, want new-key", km.ActiveKid())
	}
}

func TestRotationActivities_SwapSigningKey_NotFound(t *testing.T) {
	km := newMockKeyManager("old-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	_, err := acts.SwapSigningKey("nonexistent", "exec-token")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestRotationActivities_VerifyNewKey(t *testing.T) {
	km := newMockKeyManager("active-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	if err := acts.VerifyNewKey("active-key"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRotationActivities_VerifyNewKey_Mismatch(t *testing.T) {
	km := newMockKeyManager("actual-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	if err := acts.VerifyNewKey("expected-key"); err == nil {
		t.Fatal("expected error for key mismatch")
	}
}

func TestRotationActivities_RemoveKey(t *testing.T) {
	km := newMockKeyManager("active-key")
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = km.AddKey("old-key", priv, &priv.PublicKey)

	acts := lifecycle.NewRotationActivities(km, nil)

	if err := acts.RemoveKey("old-key"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRotationActivities_RemoveActiveKey(t *testing.T) {
	km := newMockKeyManager("active-key")
	acts := lifecycle.NewRotationActivities(km, nil)

	if err := acts.RemoveKey("active-key"); err == nil {
		t.Fatal("expected error when removing active key")
	}
}

func TestRotationActivities_RollbackToKey(t *testing.T) {
	km := newMockKeyManager("old-key")
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = km.AddKey("new-key", priv, &priv.PublicKey)
	_ = km.ActivateKey("new-key")

	acts := lifecycle.NewRotationActivities(km, nil)

	if err := acts.RollbackToKey("old-key", "new-key"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if km.ActiveKid() != "old-key" {
		t.Errorf("active kid = %q, want old-key", km.ActiveKid())
	}
}

func TestExecutionScopeForSwap(t *testing.T) {
	scope := lifecycle.ExecutionScopeForSwap("kid-123", "hash-abc")
	if scope.Method != "POST" {
		t.Errorf("method = %q, want POST", scope.Method)
	}
	if scope.URI != "/internal/signing-key" {
		t.Errorf("URI = %q, want /internal/signing-key", scope.URI)
	}
	if scope.PayloadHash != "hash-abc" {
		t.Errorf("payload_hash = %q, want hash-abc", scope.PayloadHash)
	}
	if scope.Nonce == "" {
		t.Error("nonce should not be empty")
	}
}

func TestRotationWorkflow_HappyPath(t *testing.T) {
	suite := &testsuite.WorkflowTestSuite{}
	env := suite.NewTestWorkflowEnvironment()

	// Register activities.
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

	params := lifecycle.RotationParams{
		KeyType:            "RSA-2048",
		GracePeriod:        time.Millisecond,
		PropagationTimeout: time.Millisecond,
	}

	env.ExecuteWorkflow(lifecycle.RotationWorkflow, params)

	if !env.IsWorkflowCompleted() {
		t.Fatal("workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("workflow failed: %v", err)
	}
}

func TestDefaultRotationParams(t *testing.T) {
	p := lifecycle.DefaultRotationParams()
	if p.KeyType != "RSA-2048" {
		t.Errorf("KeyType = %q, want RSA-2048", p.KeyType)
	}
	if p.GracePeriod != 5*time.Minute {
		t.Errorf("GracePeriod = %v, want 5m", p.GracePeriod)
	}
	if p.PropagationTimeout != 30*time.Second {
		t.Errorf("PropagationTimeout = %v, want 30s", p.PropagationTimeout)
	}
}
