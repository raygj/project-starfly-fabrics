package signals_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
	"github.com/starfly-fabrics/starfly/pkg/signals"
)

// ── Mock collaborators for integration test ─────────────────────────

type mockIdentity struct{}

func (m *mockIdentity) ValidateWorkload(_ context.Context, _ string, _ string) (*core.WorkloadIdentity, error) {
	return &core.WorkloadIdentity{
		ID:          "spiffe://production.example.com/workload-target",
		TrustDomain: "production.example.com",
		Attestation: &core.AttestationEvidence{Method: "k8s-sa"},
		Claims:      map[string]interface{}{"namespace": "default", "serviceaccount": "app"},
	}, nil
}

type mockPolicy struct {
	decision *core.PolicyDecision
}

func (m *mockPolicy) Evaluate(context.Context, *core.PolicyInput) (*core.PolicyDecision, error) {
	return m.decision, nil
}

func (m *mockPolicy) LoadBundle(context.Context, string) error {
	return nil
}

type mockAuditor struct {
	events []*core.AuditEvent
}

func (m *mockAuditor) Log(_ context.Context, event *core.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

// ── Integration Test: CAEP Cascade ──────────────────────────────────

// TestCAEPCascade_SessionRevoked_DeniesExchange demonstrates the full cascade:
//
//  1. External IdP sends a CAEP session-revoked event
//  2. Receiver validates the event and evaluates policy
//  3. Policy says "revoke_tokens: true"
//  4. Receiver adds subject to revocation index
//  5. Exchange engine checks revocation index → denies token exchange
//
// This must complete in under 2 seconds.
func TestCAEPCascade_SessionRevoked_DeniesExchange(t *testing.T) {
	start := time.Now()
	ctx := context.Background()

	// ── Setup shared components ──

	revIdx := signals.NewRevocationIndex()
	auditor := &mockAuditor{}

	// Signal policy: allow all signals, revoke tokens on session-revoked.
	signalPolicy := &mockPolicy{
		decision: &core.PolicyDecision{
			Allowed: true,
			Claims:  map[string]interface{}{"revoke_tokens": true},
		},
	}

	// Exchange policy: allow all exchanges.
	exchangePolicy := &mockPolicy{
		decision: &core.PolicyDecision{Allowed: true, Claims: map[string]interface{}{}},
	}

	// ── Create receiver with revocation index ──

	receiver := signals.NewReceiver(
		signals.WithReceiverPolicy(signalPolicy),
		signals.WithReceiverRevocation(revIdx),
		signals.WithReceiverAuditor(auditor),
		signals.WithReceiverDevMode(true),
	)

	// ── Create exchange engine with revocation checker ──

	exchEngine, err := exchange.New(
		&mockIdentity{},
		exchangePolicy,
		auditor,
		exchange.WithRevocationChecker(revIdx),
	)
	if err != nil {
		t.Fatalf("creating exchange engine: %v", err)
	}

	// ── Step 1: Inject CAEP session-revoked event ──

	subjectID := "spiffe://production.example.com/workload-target"
	event := signals.NewSecurityEvent("external-idp.example.com", "starfly", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: subjectID,
	})
	signals.AddEvent(event, signals.EventSessionRevoked, map[string]interface{}{
		"reason":    "admin_action",
		"initiator": "security-team",
	})

	err = receiver.ReceiveEvent(ctx, event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// ── Step 2: Verify subject is revoked ──

	entry, err := revIdx.IsRevoked(ctx, subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry == nil {
		t.Fatal("expected subject to be revoked after CAEP event")
	}

	// ── Step 3: Attempt token exchange — should be denied ──

	_, err = exchEngine.Exchange(ctx, &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "some-token",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:         "https://api.target.example.com",
		Scope:            "read:data",
	})

	if err == nil {
		t.Fatal("expected exchange to be denied for revoked subject")
	}
	if !errors.Is(err, exchange.ErrSubjectRevoked) {
		t.Fatalf("expected ErrSubjectRevoked, got: %v", err)
	}

	// ── Step 4: Verify timing constraint ──

	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("cascade took %v, must complete in < 2s", elapsed)
	}

	t.Logf("CAEP cascade completed in %v", elapsed)

	// ── Step 5: Verify audit trail ──

	var receivedEvent, revokedToken, deniedExchange bool
	for _, ev := range auditor.events {
		switch ev.Action {
		case "event_received":
			receivedEvent = true
		case "token_revoked":
			revokedToken = true
		case "token_exchange":
			if ev.Decision == "denied" {
				deniedExchange = true
			}
		}
	}

	if !receivedEvent {
		t.Error("expected event_received audit event")
	}
	if !revokedToken {
		t.Error("expected token_revoked audit event")
	}
	if !deniedExchange {
		t.Error("expected denied token_exchange audit event")
	}
}

// TestCAEPCascade_DeviceNonCompliant_DeniesExchange tests CAEP device-compliance-change
// with not-compliant status triggering token revocation.
func TestCAEPCascade_DeviceNonCompliant_DeniesExchange(t *testing.T) {
	start := time.Now()
	ctx := context.Background()

	revIdx := signals.NewRevocationIndex()
	auditor := &mockAuditor{}

	receiver := signals.NewReceiver(
		signals.WithReceiverPolicy(&mockPolicy{
			decision: &core.PolicyDecision{
				Allowed: true,
				Claims:  map[string]interface{}{"revoke_tokens": true},
			},
		}),
		signals.WithReceiverRevocation(revIdx),
		signals.WithReceiverAuditor(auditor),
		signals.WithReceiverDevMode(true),
	)

	exchEngine, err := exchange.New(
		&mockIdentity{},
		&mockPolicy{decision: &core.PolicyDecision{Allowed: true, Claims: map[string]interface{}{}}},
		auditor,
		exchange.WithRevocationChecker(revIdx),
	)
	if err != nil {
		t.Fatalf("creating exchange engine: %v", err)
	}

	// Inject CAEP device-compliance-change with not-compliant.
	subjectID := "spiffe://production.example.com/workload-target"
	event := signals.NewSecurityEvent("mdm.enterprise.com", "starfly", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: subjectID,
	})
	signals.AddEvent(event, signals.EventDeviceComplianceChange, map[string]interface{}{
		"current_status":  signals.ComplianceNotCompliant,
		"previous_status": signals.ComplianceCompliant,
	})

	err = receiver.ReceiveEvent(ctx, event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// Exchange should be denied.
	_, err = exchEngine.Exchange(ctx, &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "some-token",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:         "https://api.target.example.com",
	})

	if !errors.Is(err, exchange.ErrSubjectRevoked) {
		t.Fatalf("expected ErrSubjectRevoked, got: %v", err)
	}

	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("cascade took %v, must complete in < 2s", elapsed)
	}
	t.Logf("Device compliance cascade completed in %v", elapsed)
}

// TestCAEPCascade_AllowedEvent_ExchangeSucceeds verifies that non-revocation
// events don't block exchanges.
func TestCAEPCascade_AllowedEvent_ExchangeSucceeds(t *testing.T) {
	ctx := context.Background()

	revIdx := signals.NewRevocationIndex()
	auditor := &mockAuditor{}

	// Policy allows signal but does NOT revoke tokens.
	receiver := signals.NewReceiver(
		signals.WithReceiverPolicy(&mockPolicy{
			decision: &core.PolicyDecision{
				Allowed: true,
				Claims:  map[string]interface{}{}, // no revoke_tokens
			},
		}),
		signals.WithReceiverRevocation(revIdx),
		signals.WithReceiverAuditor(auditor),
		signals.WithReceiverDevMode(true),
	)

	exchEngine, err := exchange.New(
		&mockIdentity{},
		&mockPolicy{decision: &core.PolicyDecision{Allowed: true, Claims: map[string]interface{}{}}},
		auditor,
		exchange.WithRevocationChecker(revIdx),
	)
	if err != nil {
		t.Fatalf("creating exchange engine: %v", err)
	}

	// Inject credential-change event (not a revocation trigger per our policy).
	event := signals.NewSecurityEvent("external-idp", "starfly", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: "spiffe://production.example.com/workload-target",
	})
	signals.AddEvent(event, signals.EventCredentialChange, map[string]interface{}{
		"change_type": signals.ChangeTypeUpdate,
	})

	err = receiver.ReceiveEvent(ctx, event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// Exchange should succeed — no revocation.
	resp, err := exchEngine.Exchange(ctx, &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "some-token",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:         "https://api.target.example.com",
	})
	if err != nil {
		t.Fatalf("exchange should succeed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}

// TestCAEPCascade_Transmitter_To_Receiver_To_Revocation tests the full
// transmitter → receiver → revocation pipeline using signed SETs.
func TestCAEPCascade_Transmitter_To_Receiver_To_Revocation(t *testing.T) {
	start := time.Now()
	ctx := context.Background()

	revIdx := signals.NewRevocationIndex()
	auditor := &mockAuditor{}

	// Create transmitter.
	tx, err := signals.NewTransmitter(
		signals.WithTransmitterIssuer("starfly-unit-1"),
		signals.WithTransmitterAuditor(auditor),
	)
	if err != nil {
		t.Fatalf("NewTransmitter error: %v", err)
	}

	// Create receiver in dev mode (accepts signed SETs without JWKS lookup).
	receiver := signals.NewReceiver(
		signals.WithReceiverPolicy(&mockPolicy{
			decision: &core.PolicyDecision{
				Allowed: true,
				Claims:  map[string]interface{}{"revoke_tokens": true},
			},
		}),
		signals.WithReceiverRevocation(revIdx),
		signals.WithReceiverAuditor(auditor),
		signals.WithReceiverDevMode(true),
	)

	// Transmitter creates and signs an event.
	subjectID := "spiffe://production.example.com/workload-compromised"
	event := signals.NewSecurityEvent("starfly-unit-1", "starfly-unit-2", &core.SubjectIdentifier{
		Format:   "spiffe",
		SpiffeID: subjectID,
	})
	signals.AddEvent(event, signals.EventSessionRevoked, map[string]interface{}{
		"reason": "credential_compromise",
	})

	// Sign the SET (simulate what TransmitEvent does internally).
	// Use TransmitEvent with no streams — the event gets signed but not delivered.
	err = tx.TransmitEvent(ctx, event)
	if err != nil {
		t.Fatalf("TransmitEvent error: %v", err)
	}

	// Receiver processes the event directly (simulating delivery).
	err = receiver.ReceiveEvent(ctx, event)
	if err != nil {
		t.Fatalf("ReceiveEvent error: %v", err)
	}

	// Subject should be revoked.
	revokeEntry, revokeErr := revIdx.IsRevoked(ctx, subjectID)
	if revokeErr != nil {
		t.Fatalf("IsRevoked error: %v", revokeErr)
	}
	if revokeEntry == nil {
		t.Fatal("expected subject to be revoked")
	}

	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("full pipeline took %v, must complete in < 2s", elapsed)
	}
	t.Logf("Full transmitter → receiver → revocation pipeline completed in %v", elapsed)
}
