package signals

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── Mock policy for receiver tests ──────────────────────────────────

type mockPolicy struct {
	decision *core.PolicyDecision
	err      error
}

func (m *mockPolicy) Evaluate(context.Context, *core.PolicyInput) (*core.PolicyDecision, error) {
	return m.decision, m.err
}

func (m *mockPolicy) LoadBundle(context.Context, string) error {
	return nil
}

func allowSignalPolicy() *mockPolicy {
	return &mockPolicy{
		decision: &core.PolicyDecision{Allowed: true, Claims: map[string]interface{}{}},
	}
}

func allowWithRevocationPolicy() *mockPolicy {
	return &mockPolicy{
		decision: &core.PolicyDecision{
			Allowed: true,
			Claims:  map[string]interface{}{"revoke_tokens": true},
		},
	}
}

func denySignalPolicy(reason string) *mockPolicy {
	return &mockPolicy{
		decision: &core.PolicyDecision{Allowed: false, Reason: reason},
	}
}

// ── Tests ───────────────────────────────────────────────────────────

func TestReceiver_ReceiveEvent_Allowed(t *testing.T) {
	auditor := &mockAuditor{}
	bus := &mockSyncBus{}

	rx := NewReceiver(
		WithReceiverPolicy(allowSignalPolicy()),
		WithReceiverAuditor(auditor),
		WithReceiverSyncBus(bus, "unit-1"),
	)

	event := NewSecurityEvent("issuer-1", "audience-1", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{"reason": "admin"})

	err := rx.ReceiveEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// Should have flashed to sync bus.
	if len(bus.flashes) != 1 {
		t.Fatalf("bus flash count = %d, want 1", len(bus.flashes))
	}
	if bus.flashes[0].Type != "caep_signal" {
		t.Errorf("signal type = %q, want %q", bus.flashes[0].Type, "caep_signal")
	}

	// Should have audit events.
	if len(auditor.events) == 0 {
		t.Error("expected audit events")
	}
}

func TestReceiver_ReceiveEvent_Denied(t *testing.T) {
	auditor := &mockAuditor{}

	rx := NewReceiver(
		WithReceiverPolicy(denySignalPolicy("untrusted issuer")),
		WithReceiverAuditor(auditor),
	)

	event := NewSecurityEvent("bad-issuer", "audience-1", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	err := rx.ReceiveEvent(context.Background(), event)
	if err == nil {
		t.Fatal("expected error for denied signal")
	}
	if !errors.Is(err, ErrSignalDenied) {
		t.Fatalf("expected ErrSignalDenied, got %v", err)
	}

	// Should have a denied audit event.
	var found bool
	for _, ev := range auditor.events {
		if ev.Decision == "denied" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected denied audit event")
	}
}

func TestReceiver_ReceiveEvent_NilEvent(t *testing.T) {
	rx := NewReceiver()
	err := rx.ReceiveEvent(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil event")
	}
	if !errors.Is(err, ErrInvalidSET) {
		t.Fatalf("expected ErrInvalidSET, got %v", err)
	}
}

func TestReceiver_ReceiveEvent_EmptyEvents(t *testing.T) {
	rx := NewReceiver()
	event := &core.SecurityEvent{
		Issuer: "test",
		JTI:    "test-jti",
		Events: map[string]map[string]interface{}{},
	}
	err := rx.ReceiveEvent(context.Background(), event)
	if err == nil {
		t.Error("expected error for empty events")
	}
}

func TestReceiver_ReceiveEvent_NoPolicy(t *testing.T) {
	// Without a policy engine, all events are accepted.
	rx := NewReceiver()

	event := NewSecurityEvent("issuer", "audience", nil)
	AddEvent(event, EventCredentialChange, map[string]interface{}{"change_type": "revoke"})

	err := rx.ReceiveEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("expected success without policy, got: %v", err)
	}
}

func TestReceiver_ReceiveEvent_PolicyError(t *testing.T) {
	rx := NewReceiver(
		WithReceiverPolicy(&mockPolicy{err: errors.New("OPA unavailable")}),
	)

	event := NewSecurityEvent("issuer", "audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	err := rx.ReceiveEvent(context.Background(), event)
	if err == nil {
		t.Fatal("expected error when policy evaluation fails")
	}
}

func TestReceiver_ReceiveEvent_Revocation(t *testing.T) {
	revIdx := NewRevocationIndex()
	auditor := &mockAuditor{}

	rx := NewReceiver(
		WithReceiverPolicy(allowWithRevocationPolicy()),
		WithReceiverRevocation(revIdx),
		WithReceiverAuditor(auditor),
	)

	subjectID := "spiffe://example.com/workload-revoked"
	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: subjectID,
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{"reason": "admin_action"})

	err := rx.ReceiveEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// Subject should now be revoked.
	entry, err := revIdx.IsRevoked(context.Background(), subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry == nil {
		t.Error("expected subject to be revoked after CAEP session-revoked event")
	}

	// Should have a revocation audit event.
	var found bool
	for _, ev := range auditor.events {
		if ev.Action == "token_revoked" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected token_revoked audit event")
	}
}

func TestReceiver_ReceiveEvent_RevocationNoSubject(t *testing.T) {
	revIdx := NewRevocationIndex()

	rx := NewReceiver(
		WithReceiverPolicy(allowWithRevocationPolicy()),
		WithReceiverRevocation(revIdx),
	)

	// Event without a subject identifier — revocation is a no-op.
	event := NewSecurityEvent("issuer", "audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	err := rx.ReceiveEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// Nothing should be revoked.
	if revIdx.Len() != 0 {
		t.Errorf("revocation index length = %d, want 0", revIdx.Len())
	}
}

func TestReceiver_ReceiveSET_DevMode(t *testing.T) {
	// Create a transmitter to sign a SET.
	tx, err := NewTransmitter(WithTransmitterIssuer("test-issuer"))
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	event := NewSecurityEvent("test-issuer", "test-audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	})
	AddEvent(event, EventCredentialChange, map[string]interface{}{"change_type": "revoke"})

	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET error: %v", err)
	}

	// Receiver in dev mode — should accept without JWKS resolver.
	rx := NewReceiver(WithReceiverDevMode(true))

	err = rx.ReceiveSET(context.Background(), signed)
	if err != nil {
		t.Fatalf("ReceiveSET error: %v", err)
	}
}

func TestReceiver_ReceiveSET_InvalidJWT(t *testing.T) {
	rx := NewReceiver(WithReceiverDevMode(true))

	err := rx.ReceiveSET(context.Background(), []byte("not-a-jwt"))
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
	if !errors.Is(err, ErrInvalidSET) {
		t.Fatalf("expected ErrInvalidSET, got %v", err)
	}
}

func TestReceiver_ReceiveSET_NoJWKSResolver(t *testing.T) {
	// Non-dev mode without JWKS resolver should fail.
	rx := NewReceiver(WithReceiverDevMode(false))

	// Create a minimal JWT.
	tx, err := NewTransmitter()
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}
	event := NewSecurityEvent("issuer", "audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})
	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET error: %v", err)
	}

	err = rx.ReceiveSET(context.Background(), signed)
	if err == nil {
		t.Error("expected error without JWKS resolver")
	}
}

func TestReceiver_SyncBusError(t *testing.T) {
	bus := &mockSyncBus{err: errors.New("NATS down")}
	rx := NewReceiver(
		WithReceiverSyncBus(bus, "unit-1"),
	)

	event := NewSecurityEvent("issuer", "audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	// Should succeed even when sync bus fails.
	err := rx.ReceiveEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("expected success with sync bus error, got: %v", err)
	}
}

func TestReceiver_CAEP_Cascade_Revocation(t *testing.T) {
	// Full cascade: receive CAEP event → policy says revoke → revocation index populated → exchange denied.
	revIdx := NewRevocationIndex()

	rx := NewReceiver(
		WithReceiverPolicy(allowWithRevocationPolicy()),
		WithReceiverRevocation(revIdx),
		WithReceiverDevMode(true),
	)

	// Simulate a CAEP device-compliance-change with not-compliant status.
	subjectID := "spiffe://example.com/workload-compromised"
	event := NewSecurityEvent("external-idp", "starfly", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: subjectID,
	})
	AddEvent(event, EventDeviceComplianceChange, map[string]interface{}{
		"current_status": ComplianceNotCompliant,
	})

	err := rx.ReceiveEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// Subject should be revoked.
	revokeEntry, err := revIdx.IsRevoked(context.Background(), subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if revokeEntry == nil {
		t.Error("expected subject to be revoked after CAEP compliance event")
	}

	// Now the exchange engine (via RevocationChecker) would deny exchanges for this subject.
	// Verified by TestExchange_RevokedSubject in exchange_test.go.
}

func TestReceiver_ReceiveSET_ExtractsClaims(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("test-issuer"))
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	event := NewSecurityEvent("test-issuer", "test-audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	})
	event.TransactionID = "txn-12345"
	AddEvent(event, EventCredentialChange, map[string]interface{}{
		"change_type":     ChangeTypeRevoke,
		"credential_type": "jwt",
	})

	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET error: %v", err)
	}

	// Track what the receiver sees.
	var receivedEvent *core.SecurityEvent
	capturePolicy := &mockPolicy{
		decision: &core.PolicyDecision{Allowed: true, Claims: map[string]interface{}{}},
	}

	rx := NewReceiver(
		WithReceiverDevMode(true),
		WithReceiverPolicy(capturePolicy),
	)

	// Wrap ReceiveEvent to capture the parsed event.
	parsedEvent, parseErr := rx.parseSET(context.Background(), signed)
	if parseErr != nil {
		t.Fatalf("parseSET error: %v", parseErr)
	}
	receivedEvent = parsedEvent

	if receivedEvent.Issuer != "test-issuer" {
		t.Errorf("Issuer = %q, want %q", receivedEvent.Issuer, "test-issuer")
	}
	if receivedEvent.JTI == "" {
		t.Error("JTI should not be empty")
	}
	if receivedEvent.TransactionID != "txn-12345" {
		t.Errorf("TransactionID = %q, want %q", receivedEvent.TransactionID, "txn-12345")
	}
	if receivedEvent.SubjectID == nil {
		t.Fatal("SubjectID should not be nil")
	}
	if receivedEvent.SubjectID.Format != "spiffe" {
		t.Errorf("SubjectID.Format = %q, want %q", receivedEvent.SubjectID.Format, "spiffe")
	}

	eventClaims, ok := receivedEvent.Events[EventCredentialChange]
	if !ok {
		t.Fatal("EventCredentialChange not found in parsed events")
	}
	if eventClaims["change_type"] != ChangeTypeRevoke {
		t.Errorf("change_type = %v, want %q", eventClaims["change_type"], ChangeTypeRevoke)
	}
}

// ── Mock JWKS resolver ──────────────────────────────────────────────

type mockJWKSResolver struct {
	key crypto.PublicKey
	err error
}

func (m *mockJWKSResolver) ResolveKey(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return m.key, m.err
}

func (m *mockJWKSResolver) Prefetch(_ context.Context, _ []string) error { return nil }

func (m *mockJWKSResolver) Stats() core.JWKSCacheStats { return core.JWKSCacheStats{} }

// ── Option function tests ───────────────────────────────────────────

func TestWithReceiverJWKS(t *testing.T) {
	resolver := &mockJWKSResolver{}
	rx := NewReceiver(WithReceiverJWKS(resolver))
	if rx.jwksResolver == nil {
		t.Error("expected jwksResolver to be set")
	}
}

func TestWithReceiverOnSignal(t *testing.T) {
	called := false
	fn := func(_, _, _ string) { called = true }
	rx := NewReceiver(WithReceiverOnSignal(fn))
	if rx.onSignal == nil {
		t.Fatal("expected onSignal to be set")
	}
	rx.onSignal("t", "s", "r")
	if !called {
		t.Error("expected onSignal to be callable")
	}
}

func TestWithReceiverRevocationGrace(t *testing.T) {
	rx := NewReceiver(WithReceiverRevocationGrace(5 * time.Minute))
	if rx.revocationGrace != 5*time.Minute {
		t.Errorf("revocationGrace = %v, want 5m", rx.revocationGrace)
	}
}

// ── onSignal callback tests ─────────────────────────────────────────

func TestReceiver_ReceiveEvent_OnSignal_SpiffeSubject(t *testing.T) {
	var gotET, gotSub, gotRes string
	rx := NewReceiver(
		WithReceiverOnSignal(func(et, sub, res string) {
			gotET = et
			gotSub = sub
			gotRes = res
		}),
	)

	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
	if gotET != EventSessionRevoked {
		t.Errorf("eventType = %q, want %q", gotET, EventSessionRevoked)
	}
	if gotSub != "spiffe://example.com/workload-1" {
		t.Errorf("subject = %q, want spiffe subject", gotSub)
	}
	if gotRes != "accepted" {
		t.Errorf("result = %q, want accepted", gotRes)
	}
}

func TestReceiver_ReceiveEvent_OnSignal_URISubject(t *testing.T) {
	var gotSub string
	rx := NewReceiver(
		WithReceiverOnSignal(func(_, sub, _ string) { gotSub = sub }),
	)

	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format: "uri",
		URI:    "wimse://example.com/ns/default/sa/app",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
	if gotSub != "wimse://example.com/ns/default/sa/app" {
		t.Errorf("subject = %q, want URI subject", gotSub)
	}
}

func TestReceiver_ReceiveEvent_OnSignal_FallbackToIssuer(t *testing.T) {
	var gotSub string
	rx := NewReceiver(
		WithReceiverOnSignal(func(_, sub, _ string) { gotSub = sub }),
	)

	event := NewSecurityEvent("issuer-fallback", "audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
	if gotSub != "issuer-fallback" {
		t.Errorf("subject = %q, want issuer as fallback", gotSub)
	}
}

// ── Policy revocation edge cases ────────────────────────────────────

func TestReceiver_ReceiveEvent_PolicyRevokeFalse(t *testing.T) {
	revIdx := NewRevocationIndex()
	rx := NewReceiver(
		WithReceiverPolicy(&mockPolicy{
			decision: &core.PolicyDecision{
				Allowed: true,
				Claims:  map[string]interface{}{"revoke_tokens": false},
			},
		}),
		WithReceiverRevocation(revIdx),
	)

	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/no-revoke",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
	if revIdx.Len() != 0 {
		t.Errorf("revocation index should be empty, got %d", revIdx.Len())
	}
}

func TestReceiver_ReceiveEvent_PolicyRevokeNonBool(t *testing.T) {
	revIdx := NewRevocationIndex()
	rx := NewReceiver(
		WithReceiverPolicy(&mockPolicy{
			decision: &core.PolicyDecision{
				Allowed: true,
				Claims:  map[string]interface{}{"revoke_tokens": "yes"},
			},
		}),
		WithReceiverRevocation(revIdx),
	)

	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/no-revoke",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
	if revIdx.Len() != 0 {
		t.Errorf("revocation index should be empty for non-bool, got %d", revIdx.Len())
	}
}

// ── handleRevocation edge cases ─────────────────────────────────────

func TestReceiver_HandleRevocation_URISubject(t *testing.T) {
	revIdx := NewRevocationIndex()
	rx := NewReceiver(
		WithReceiverPolicy(allowWithRevocationPolicy()),
		WithReceiverRevocation(revIdx),
	)

	uri := "wimse://example.com/ns/default/sa/app"
	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format: "uri",
		URI:    uri,
	})
	AddEvent(event, EventCredentialChange, map[string]interface{}{"change_type": "revoke"})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}

	entry, err := revIdx.IsRevoked(context.Background(), uri)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if entry == nil {
		t.Error("expected URI subject to be revoked")
	}
}

func TestReceiver_HandleRevocation_NoRevocationIndex(t *testing.T) {
	rx := NewReceiver(
		WithReceiverPolicy(allowWithRevocationPolicy()),
	)

	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
}

// ── evaluatePolicy edge cases ───────────────────────────────────────

func TestReceiver_EvaluatePolicy_URISubject(t *testing.T) {
	rx := NewReceiver(WithReceiverPolicy(allowSignalPolicy()))

	event := NewSecurityEvent("issuer", "audience", &core.SubjectIdentifier{
		Format: "uri",
		URI:    "wimse://example.com/ns/default/sa/app",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})

	if err := rx.ReceiveEvent(context.Background(), event); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
}

// ── parseSET non-dev mode tests ─────────────────────────────────────

func TestReceiver_ParseSET_NonDevMode_FullPath(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("test-issuer"))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}

	event := NewSecurityEvent("test-issuer", "test-audience", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://example.com/workload-1",
	})
	AddEvent(event, EventSessionRevoked, map[string]interface{}{"reason": "test"})

	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET: %v", err)
	}

	pubJWK, err := tx.signKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	var rawPub rsa.PublicKey
	if err := jwk.Export(pubJWK, &rawPub); err != nil {
		t.Fatalf("Export: %v", err)
	}

	resolver := &mockJWKSResolver{key: &rawPub}
	rx := NewReceiver(WithReceiverJWKS(resolver))

	parsed, err := rx.parseSET(context.Background(), signed)
	if err != nil {
		t.Fatalf("parseSET: %v", err)
	}
	if parsed.Issuer != "test-issuer" {
		t.Errorf("Issuer = %q, want test-issuer", parsed.Issuer)
	}
	if parsed.SubjectID == nil || parsed.SubjectID.SpiffeID != "spiffe://example.com/workload-1" {
		t.Error("SubjectID not parsed correctly")
	}
}

func TestReceiver_ParseSET_NonDevMode_ResolveKeyError(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("test-issuer"))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}

	event := NewSecurityEvent("test-issuer", "test-audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})
	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET: %v", err)
	}

	resolver := &mockJWKSResolver{err: errors.New("key not found")}
	rx := NewReceiver(WithReceiverJWKS(resolver))

	_, err = rx.parseSET(context.Background(), signed)
	if err == nil {
		t.Fatal("expected error for key resolution failure")
	}
	if !errors.Is(err, ErrUnknownIssuer) {
		t.Errorf("expected ErrUnknownIssuer, got %v", err)
	}
}

func TestReceiver_ParseSET_NonDevMode_WrongKey(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("test-issuer"))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}

	event := NewSecurityEvent("test-issuer", "test-audience", nil)
	AddEvent(event, EventSessionRevoked, map[string]interface{}{})
	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET: %v", err)
	}

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	resolver := &mockJWKSResolver{key: &wrongKey.PublicKey}
	rx := NewReceiver(WithReceiverJWKS(resolver))

	_, err = rx.parseSET(context.Background(), signed)
	if err == nil {
		t.Fatal("expected error for wrong public key")
	}
	if !errors.Is(err, ErrInvalidSET) {
		t.Errorf("expected ErrInvalidSET, got %v", err)
	}
}

func TestReceiver_ReceiveSET_NonDevMode_EndToEnd(t *testing.T) {
	tx, err := NewTransmitter(WithTransmitterIssuer("e2e-issuer"))
	if err != nil {
		t.Fatalf("NewTransmitter: %v", err)
	}

	event := NewSecurityEvent("e2e-issuer", "e2e-audience", &core.SubjectIdentifier{
		Format: "uri",
		URI:    "wimse://example.com/ns/default/sa/app",
	})
	event.TransactionID = "txn-e2e"
	AddEvent(event, EventCredentialChange, map[string]interface{}{"change_type": "revoke"})

	signed, err := tx.signSET(event)
	if err != nil {
		t.Fatalf("signSET: %v", err)
	}

	pubJWK, err := tx.signKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	var rawPub rsa.PublicKey
	if err := jwk.Export(pubJWK, &rawPub); err != nil {
		t.Fatalf("Export: %v", err)
	}

	var gotET string
	rx := NewReceiver(
		WithReceiverJWKS(&mockJWKSResolver{key: &rawPub}),
		WithReceiverOnSignal(func(et, _, _ string) { gotET = et }),
	)

	if err := rx.ReceiveSET(context.Background(), signed); err != nil {
		t.Fatalf("ReceiveSET: %v", err)
	}
	if gotET != EventCredentialChange {
		t.Errorf("onSignal eventType = %q, want %q", gotET, EventCredentialChange)
	}
}
