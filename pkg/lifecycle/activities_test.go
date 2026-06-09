package lifecycle_test

import (
	"context"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/lifecycle"
)

// mockExchanger implements core.TokenExchanger for testing.
type mockExchanger struct {
	exchangeFn func(ctx context.Context, req *core.TokenExchangeRequest) (*core.TokenExchangeResponse, error)
}

func (m *mockExchanger) Exchange(ctx context.Context, req *core.TokenExchangeRequest) (*core.TokenExchangeResponse, error) {
	if m.exchangeFn != nil {
		return m.exchangeFn(ctx, req)
	}
	return &core.TokenExchangeResponse{
		AccessToken:     "test-token",
		IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
		TokenType:       "Bearer",
		ExpiresIn:       30,
	}, nil
}

// mockTransmitter implements core.SignalTransmitter for testing.
type mockTransmitter struct {
	transmitted []*core.SecurityEvent
}

func (m *mockTransmitter) CreateStream(_ context.Context, _ *core.StreamConfig) (*core.Stream, error) {
	return &core.Stream{ID: "test"}, nil
}
func (m *mockTransmitter) DeleteStream(_ context.Context, _ string) error { return nil }
func (m *mockTransmitter) TransmitEvent(_ context.Context, event *core.SecurityEvent) error {
	m.transmitted = append(m.transmitted, event)
	return nil
}
func (m *mockTransmitter) GetStreamStatus(_ context.Context, _ string) (*core.StreamStatus, error) {
	return &core.StreamStatus{Status: "enabled"}, nil
}

// mockRevocationIndex implements core.RevocationIndex for testing.
type mockRevocationIndex struct {
	entries map[string]*core.RevocationEntry
}

func newMockRevocationIndex() *mockRevocationIndex {
	return &mockRevocationIndex{entries: make(map[string]*core.RevocationEntry)}
}

func (m *mockRevocationIndex) Revoke(_ context.Context, subjectID, reason string, expiresAt time.Time) error {
	m.entries[subjectID] = &core.RevocationEntry{
		SubjectID: subjectID,
		Reason:    reason,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
	}
	return nil
}

func (m *mockRevocationIndex) IsRevoked(_ context.Context, subjectID string) (*core.RevocationEntry, error) {
	entry, ok := m.entries[subjectID]
	if !ok {
		return nil, nil
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(m.entries, subjectID)
		return nil, nil
	}
	return entry, nil
}

func (m *mockRevocationIndex) Cleanup(_ context.Context) (int, error) { return 0, nil }

func (m *mockRevocationIndex) Hash() string             { return "" }
func (m *mockRevocationIndex) Export() ([]byte, error)   { return nil, nil }
func (m *mockRevocationIndex) Import(_ []byte) error     { return nil }

func TestMintExecutionScopedToken(t *testing.T) {
	var capturedReq *core.TokenExchangeRequest
	exch := &mockExchanger{
		exchangeFn: func(_ context.Context, req *core.TokenExchangeRequest) (*core.TokenExchangeResponse, error) {
			capturedReq = req
			return &core.TokenExchangeResponse{
				AccessToken:     "scoped-token-123",
				IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
				TokenType:       "Bearer",
				ExpiresIn:       30,
			}, nil
		},
	}

	acts := lifecycle.NewActivities(exch, &mockTransmitter{}, newMockRevocationIndex(), "unit-abc")

	scope := core.ExecutionScope{
		Method:      "POST",
		URI:         "/internal/signing-key",
		PayloadHash: "abc123",
		Nonce:       "nonce-1",
	}

	token, err := acts.MintExecutionScopedToken(context.Background(), scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "scoped-token-123" {
		t.Errorf("got token %q, want %q", token, "scoped-token-123")
	}
	if capturedReq == nil {
		t.Fatal("exchange was not called")
	}
	if capturedReq.ExecutionScope == nil {
		t.Fatal("execution scope not passed to exchange")
	}
	if capturedReq.ExecutionScope.Method != "POST" {
		t.Errorf("got method %q, want POST", capturedReq.ExecutionScope.Method)
	}
	if capturedReq.ExecutionScope.URI != "/internal/signing-key" {
		t.Errorf("got URI %q, want /internal/signing-key", capturedReq.ExecutionScope.URI)
	}
}

func TestEmitLifecycleSignal(t *testing.T) {
	tx := &mockTransmitter{}
	acts := lifecycle.NewActivities(&mockExchanger{}, tx, newMockRevocationIndex(), "unit-abc")

	err := acts.EmitLifecycleSignal(context.Background(),
		lifecycle.EventTypeRotationComplete,
		"spiffe://example.com/starfly",
		map[string]interface{}{"old_kid": "k1", "new_kid": "k2"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tx.transmitted) != 1 {
		t.Fatalf("got %d transmitted events, want 1", len(tx.transmitted))
	}

	evt := tx.transmitted[0]
	if evt.Issuer != "unit-abc" {
		t.Errorf("issuer = %q, want unit-abc", evt.Issuer)
	}
	if _, ok := evt.Events[lifecycle.EventTypeRotationComplete]; !ok {
		t.Error("event type not found in events map")
	}
	if evt.SubjectID.URI != "spiffe://example.com/starfly" {
		t.Errorf("subject URI = %q, want spiffe://example.com/starfly", evt.SubjectID.URI)
	}
}

func TestRevokeCredential(t *testing.T) {
	revIdx := newMockRevocationIndex()
	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, revIdx, "unit-abc")

	err := acts.RevokeCredential(context.Background(), lifecycle.RevokeRequest{
		SubjectID: "agent-007",
		Reason:    "key-rotation",
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry, ok := revIdx.entries["agent-007"]
	if !ok {
		t.Fatal("subject not found in revocation index")
	}
	if entry.Reason != "key-rotation" {
		t.Errorf("reason = %q, want key-rotation", entry.Reason)
	}
}

func TestRevokeCredentialDefaultExpiry(t *testing.T) {
	revIdx := newMockRevocationIndex()
	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, revIdx, "unit-abc")

	err := acts.RevokeCredential(context.Background(), lifecycle.RevokeRequest{
		SubjectID: "agent-008",
		Reason:    "expired",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry := revIdx.entries["agent-008"]
	// Default expiry should be ~24 hours from now.
	if time.Until(entry.ExpiresAt) < 23*time.Hour {
		t.Errorf("default expiry too short: %v", entry.ExpiresAt)
	}
}

func TestCheckRevocationStatus_NotRevoked(t *testing.T) {
	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "unit-abc")

	result, err := acts.CheckRevocationStatus(context.Background(), "agent-clean")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Revoked {
		t.Error("expected not revoked")
	}
}

func TestCheckRevocationStatus_Revoked(t *testing.T) {
	revIdx := newMockRevocationIndex()
	revIdx.entries["agent-bad"] = &core.RevocationEntry{
		SubjectID: "agent-bad",
		Reason:    "compromised",
		RevokedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, revIdx, "unit-abc")

	result, err := acts.CheckRevocationStatus(context.Background(), "agent-bad")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Revoked {
		t.Error("expected revoked")
	}
	if result.Reason != "compromised" {
		t.Errorf("reason = %q, want compromised", result.Reason)
	}
}

func TestNewActivities(t *testing.T) {
	acts := lifecycle.NewActivities(&mockExchanger{}, &mockTransmitter{}, newMockRevocationIndex(), "unit-test")
	if acts == nil {
		t.Fatal("NewActivities returned nil")
	}
}
