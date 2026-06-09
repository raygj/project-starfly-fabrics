package federation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ─────────────────────────────────────────────────────────────────────
// MOCKS
// ─────────────────────────────────────────────────────────────────────

type revokeCall struct {
	subjectID string
	reason    string
	expiresAt time.Time
}

type mockRevocationIndex struct {
	mu      sync.Mutex
	revoked []revokeCall
}

func (m *mockRevocationIndex) Revoke(_ context.Context, subjectID, reason string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked = append(m.revoked, revokeCall{
		subjectID: subjectID,
		reason:    reason,
		expiresAt: expiresAt,
	})
	return nil
}

func (m *mockRevocationIndex) calls() []revokeCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]revokeCall, len(m.revoked))
	copy(out, m.revoked)
	return out
}

type mockSyncBus struct {
	mu      sync.Mutex
	flashed []*core.Signal
}

func (m *mockSyncBus) Flash(_ context.Context, signal *core.Signal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flashed = append(m.flashed, signal)
	return nil
}

func (m *mockSyncBus) signals() []*core.Signal {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*core.Signal, len(m.flashed))
	copy(out, m.flashed)
	return out
}

// ─────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────

func testPeers() []PeerSignalConfig {
	return []PeerSignalConfig{
		{FabricID: "fabric-east", Endpoint: "https://east.example.com/v1/signals/events"},
		{FabricID: "fabric-west", Endpoint: "https://west.example.com/v1/signals/events"},
	}
}

func validSignal() RevocationSignal {
	return RevocationSignal{
		SubjectID:    "spiffe://east.example.com/workload/api",
		Reason:       "session-revoked",
		RevokedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		EventJTI:     "evt-001",
		SourceFabric: "fabric-east",
		TrustDomain:  "east.example.com",
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// ─────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────

func TestNewInboundHandler_CreatesTrustedPeerMap(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	if !h.IsTrustedPeer("fabric-east") {
		t.Fatal("expected fabric-east to be trusted")
	}
	if !h.IsTrustedPeer("fabric-west") {
		t.Fatal("expected fabric-west to be trusted")
	}
	if h.IsTrustedPeer("fabric-unknown") {
		t.Fatal("expected fabric-unknown to NOT be trusted")
	}

	state := h.State()
	if len(state) != 2 {
		t.Fatalf("expected 2 peer states, got %d", len(state))
	}
}

func TestReceiveRevocation_TrustedPeerSucceeds(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundLogger(quietLogger()),
	)

	err := h.ReceiveRevocation(context.Background(), validSignal())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReceiveRevocation_UntrustedPeerReturnsError(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	sig := validSignal()
	sig.SourceFabric = "fabric-rogue"

	err := h.ReceiveRevocation(context.Background(), sig)
	if err == nil {
		t.Fatal("expected error for untrusted peer")
	}
	if !errorContains(err, "untrusted peer") {
		t.Fatalf("expected 'untrusted peer' error, got: %v", err)
	}
}

func TestReceiveRevocation_CallsRevokeOnIndex(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rev.calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(calls))
	}
	if calls[0].subjectID != sig.SubjectID {
		t.Errorf("expected subject_id %q, got %q", sig.SubjectID, calls[0].subjectID)
	}
	expectedReason := "federated:session-revoked from:fabric-east"
	if calls[0].reason != expectedReason {
		t.Errorf("expected reason %q, got %q", expectedReason, calls[0].reason)
	}
	if !calls[0].expiresAt.Equal(sig.ExpiresAt) {
		t.Errorf("expected expiresAt %v, got %v", sig.ExpiresAt, calls[0].expiresAt)
	}
}

func TestReceiveRevocation_FlashesToSyncBus(t *testing.T) {
	rev := &mockRevocationIndex{}
	bus := &mockSyncBus{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundSyncBus(bus),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	signals := bus.signals()
	if len(signals) != 1 {
		t.Fatalf("expected 1 flash, got %d", len(signals))
	}
	if signals[0].Type != "federation.revocation" {
		t.Errorf("expected type federation.revocation, got %q", signals[0].Type)
	}
	if signals[0].Source != sig.SourceFabric {
		t.Errorf("expected source %q, got %q", sig.SourceFabric, signals[0].Source)
	}
	payload := signals[0].Payload
	if payload["subject_id"] != sig.SubjectID {
		t.Errorf("payload subject_id mismatch")
	}
	if payload["event_jti"] != sig.EventJTI {
		t.Errorf("payload event_jti mismatch")
	}
}

func TestReceiveRevocation_NilSyncBusStillWorks(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		// No sync bus
		WithInboundLogger(quietLogger()),
	)

	err := h.ReceiveRevocation(context.Background(), validSignal())
	if err != nil {
		t.Fatalf("unexpected error with nil sync bus: %v", err)
	}

	calls := rev.calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(calls))
	}
}

func TestReceiveRevocation_EmptySubjectIDReturnsError(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	sig := validSignal()
	sig.SubjectID = ""

	err := h.ReceiveRevocation(context.Background(), sig)
	if err == nil {
		t.Fatal("expected error for empty subject_id")
	}
	if !errorContains(err, "empty subject_id") {
		t.Fatalf("expected 'empty subject_id' error, got: %v", err)
	}
}

func TestReceiveRevocation_ExpiredExpiresAtReturnsError(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	sig := validSignal()
	sig.ExpiresAt = time.Now().Add(-1 * time.Hour) // in the past

	err := h.ReceiveRevocation(context.Background(), sig)
	if err == nil {
		t.Fatal("expected error for expired signal")
	}
	if !errorContains(err, "expires_at is in the past") {
		t.Fatalf("expected expiry error, got: %v", err)
	}
}

func TestIsTrustedPeer_ReturnsCorrectResults(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	tests := []struct {
		fabricID string
		want     bool
	}{
		{"fabric-east", true},
		{"fabric-west", true},
		{"fabric-rogue", false},
		{"", false},
		{"FABRIC-EAST", false}, // case-sensitive
	}

	for _, tt := range tests {
		got := h.IsTrustedPeer(tt.fabricID)
		if got != tt.want {
			t.Errorf("IsTrustedPeer(%q) = %v, want %v", tt.fabricID, got, tt.want)
		}
	}
}

func TestVerifyPeerIdentity_MatchingIDsPass(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	err := h.VerifyPeerIdentity("fabric-east", "fabric-east")
	if err != nil {
		t.Fatalf("expected nil error for matching IDs, got: %v", err)
	}
}

func TestVerifyPeerIdentity_MismatchedIDsFail(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	err := h.VerifyPeerIdentity("fabric-east", "fabric-rogue")
	if err == nil {
		t.Fatal("expected error for mismatched IDs")
	}
	if !errorContains(err, "peer identity mismatch") {
		t.Fatalf("expected 'peer identity mismatch' error, got: %v", err)
	}
}

func TestVerifyPeerIdentity_EmptyCertFabricIDFails(t *testing.T) {
	h := NewInboundHandler(testPeers(), WithInboundLogger(quietLogger()))

	err := h.VerifyPeerIdentity("fabric-east", "")
	if err == nil {
		t.Fatal("expected error for empty cert fabric ID")
	}
	if !errorContains(err, "mTLS identity required") {
		t.Fatalf("expected 'mTLS identity required' error, got: %v", err)
	}
}

func TestReceiveRevocation_MTLSRequired_RejectsEmptyCertFabricID(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundRequireMTLS(true),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	// CertFabricID is empty by default.
	err := h.ReceiveRevocation(context.Background(), sig)
	if err == nil {
		t.Fatal("expected error when mTLS required but CertFabricID empty")
	}
	if !errorContains(err, "mTLS identity required") {
		t.Fatalf("expected 'mTLS identity required' error, got: %v", err)
	}

	// Verify no revocation was applied.
	if len(rev.calls()) != 0 {
		t.Error("revocation should not have been applied")
	}
}

func TestReceiveRevocation_MTLSRequired_AcceptsMatchingCertFabricID(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundRequireMTLS(true),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	sig.CertFabricID = sig.SourceFabric // matching
	err := h.ReceiveRevocation(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rev.calls()) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(rev.calls()))
	}
}

func TestReceiveRevocation_MTLSRequired_RejectsMismatchedCertFabricID(t *testing.T) {
	h := NewInboundHandler(testPeers(),
		WithInboundRequireMTLS(true),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	sig.CertFabricID = "fabric-rogue" // does not match SourceFabric
	err := h.ReceiveRevocation(context.Background(), sig)
	if err == nil {
		t.Fatal("expected error for mismatched cert identity")
	}
	if !errorContains(err, "peer identity mismatch") {
		t.Fatalf("expected 'peer identity mismatch' error, got: %v", err)
	}
}

func TestReceiveRevocation_NoMTLS_StillVerifiesIfCertPresent(t *testing.T) {
	h := NewInboundHandler(testPeers(),
		// requireMTLS is false (default)
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	sig.CertFabricID = "fabric-rogue" // mismatch, should still be caught

	err := h.ReceiveRevocation(context.Background(), sig)
	if err == nil {
		t.Fatal("expected error for mismatched cert even without requireMTLS")
	}
	if !errorContains(err, "peer identity mismatch") {
		t.Fatalf("expected 'peer identity mismatch' error, got: %v", err)
	}
}

func TestReceiveRevocation_NoMTLS_AcceptsNoCert(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		// requireMTLS is false (default)
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	// CertFabricID is empty — should be accepted in dev mode
	err := h.ReceiveRevocation(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error in non-mTLS mode: %v", err)
	}

	if len(rev.calls()) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(rev.calls()))
	}
}

func TestReceiveRevocation_ConcurrentSafe(t *testing.T) {
	rev := &mockRevocationIndex{}
	bus := &mockSyncBus{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundSyncBus(bus),
		WithInboundLogger(quietLogger()),
	)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			sig := validSignal()
			sig.EventJTI = fmt.Sprintf("evt-concurrent-%d", n)
			_ = h.ReceiveRevocation(context.Background(), sig)
		}(i)
	}

	wg.Wait()

	calls := rev.calls()
	if len(calls) != goroutines {
		t.Fatalf("expected %d revoke calls, got %d", goroutines, len(calls))
	}

	signals := bus.signals()
	if len(signals) != goroutines {
		t.Fatalf("expected %d flash signals, got %d", goroutines, len(signals))
	}

	// Verify peer state was updated.
	state := h.State()
	eastState := state["fabric-east"]
	if eastState == nil {
		t.Fatal("expected state for fabric-east")
	}
	if eastState.ReceivedCount != int64(goroutines) {
		t.Errorf("expected ReceivedCount %d, got %d", goroutines, eastState.ReceivedCount)
	}
}

// ─────────────────────────────────────────────────────────────────────
// JTI DEDUP TESTS
// ─────────────────────────────────────────────────────────────────────

func TestReceiveRevocation_DuplicateJTI_SecondCallIsIdempotent(t *testing.T) {
	rev := &mockRevocationIndex{}
	bus := &mockSyncBus{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundSyncBus(bus),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	sig.EventJTI = "evt-dedup-001"

	// First call — should apply revocation.
	if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
		t.Fatalf("first call unexpected error: %v", err)
	}

	// Second call — same JTI, should be deduped (return nil, no revocation).
	if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
		t.Fatalf("second call unexpected error: %v", err)
	}

	// Revocation index should have been called exactly once.
	calls := rev.calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 revoke call (dedup), got %d", len(calls))
	}

	// Sync bus should have been flashed exactly once.
	signals := bus.signals()
	if len(signals) != 1 {
		t.Fatalf("expected 1 flash (dedup), got %d", len(signals))
	}

	// Dedup counter should be 1.
	if hits := h.DedupHits(); hits != 1 {
		t.Errorf("expected 1 dedup hit, got %d", hits)
	}
}

func TestReceiveRevocation_ConcurrentDuplicateJTI(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundLogger(quietLogger()),
	)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// All goroutines send the same JTI.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			sig := validSignal()
			sig.EventJTI = "evt-concurrent-dedup"
			_ = h.ReceiveRevocation(context.Background(), sig)
		}()
	}

	wg.Wait()

	// Exactly one revocation should have been applied.
	calls := rev.calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 revoke call (concurrent dedup), got %d", len(calls))
	}

	// Dedup counter should be goroutines-1.
	if hits := h.DedupHits(); hits != int64(goroutines-1) {
		t.Errorf("expected %d dedup hits, got %d", goroutines-1, hits)
	}
}

func TestReceiveRevocation_EmptyJTI_SkipsDedup(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	sig.EventJTI = "" // empty JTI — should not be deduplicated

	// Both calls should apply revocation (no dedup for empty JTI).
	if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
		t.Fatalf("first call unexpected error: %v", err)
	}
	if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
		t.Fatalf("second call unexpected error: %v", err)
	}

	calls := rev.calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 revoke calls (empty JTI, no dedup), got %d", len(calls))
	}

	// Dedup counter should remain 0.
	if hits := h.DedupHits(); hits != 0 {
		t.Errorf("expected 0 dedup hits for empty JTI, got %d", hits)
	}
}

func TestReceiveRevocation_DedupEviction(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundLogger(quietLogger()),
	)
	// Use a small maxSeen to test eviction.
	h.maxSeen = 10

	// Fill the seen set to capacity+1 to trigger eviction.
	for i := 0; i <= 10; i++ {
		sig := validSignal()
		sig.EventJTI = fmt.Sprintf("evt-evict-%d", i)
		if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
			t.Fatalf("unexpected error on signal %d: %v", i, err)
		}
	}

	// After eviction of 10% (1 entry), evt-evict-0 should be evicted.
	// Resending it should succeed (not be deduped).
	sig := validSignal()
	sig.EventJTI = "evt-evict-0"
	if err := h.ReceiveRevocation(context.Background(), sig); err != nil {
		t.Fatalf("unexpected error re-sending evicted JTI: %v", err)
	}

	// Total revoke calls: 11 original (i=0..10) + 1 re-send after eviction = 12.
	calls := rev.calls()
	if len(calls) != 12 {
		t.Fatalf("expected 12 total revoke calls, got %d", len(calls))
	}
}

// ─────────────────────────────────────────────────────────────────────
// ZERO EXPIRY TESTS
// ─────────────────────────────────────────────────────────────────────

func TestReceiveRevocation_ZeroExpiresAt_AppliesDefaultTTL(t *testing.T) {
	rev := &mockRevocationIndex{}
	h := NewInboundHandler(testPeers(),
		WithInboundRevocation(rev),
		WithInboundLogger(quietLogger()),
	)

	sig := validSignal()
	sig.ExpiresAt = time.Time{} // zero value
	sig.EventJTI = "evt-zero-expiry"

	before := time.Now()
	err := h.ReceiveRevocation(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after := time.Now()

	calls := rev.calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 revoke call, got %d", len(calls))
	}

	// The applied expiry should be approximately 24h from now.
	expiresAt := calls[0].expiresAt
	expectedMin := before.Add(24 * time.Hour)
	expectedMax := after.Add(24 * time.Hour)

	if expiresAt.Before(expectedMin) || expiresAt.After(expectedMax) {
		t.Errorf("expiresAt = %v, want between %v and %v (24h from now)", expiresAt, expectedMin, expectedMax)
	}
}

// ─────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────

func errorContains(err error, substr string) bool {
	if err == nil {
		return false
	}
	return containsString(err.Error(), substr)
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
