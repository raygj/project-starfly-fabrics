package exchange

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── SA-007: Attestation exchange integration tests ──────────────────

func TestExchange_WithAttestation_AddsJWTClaims(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.Attestation = &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
			Metadata: map[string]string{"namespace": "prod"},
		},
		Workload: &core.ServerAttestWorkload{
			PID:        1234,
			BinaryHash: "sha256:abc123def456",
			Namespace:  "prod",
			PodName:    "my-agent-xyz",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	// Parse the minted JWT and verify attestation claims.
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Check assurance_level claim.
	var assurance string
	if err := token.Get("assurance_level", &assurance); err != nil {
		t.Fatalf("missing assurance_level claim: %v", err)
	}
	if assurance != "software" {
		t.Errorf("assurance_level = %q, want software", assurance)
	}

	// Check attestation claim structure.
	var attestMap map[string]interface{}
	if err := token.Get("attestation", &attestMap); err != nil {
		t.Fatalf("missing attestation claim: %v", err)
	}

	platform, ok := attestMap["platform"].(map[string]interface{})
	if !ok {
		t.Fatal("missing attestation.platform")
	}
	if platform["source"] != "k8s-sa" {
		t.Errorf("attestation.platform.source = %v", platform["source"])
	}

	if attestMap["agent_version"] != "v0.1.0" {
		t.Errorf("attestation.agent_version = %v", attestMap["agent_version"])
	}

	workload, ok := attestMap["workload"].(map[string]interface{})
	if !ok {
		t.Fatal("missing attestation.workload")
	}
	if workload["binary_hash"] != "sha256:abc123def456" {
		t.Errorf("attestation.workload.binary_hash = %v", workload["binary_hash"])
	}

	// Verify audit event was emitted.
	var foundAttest bool
	for _, ev := range auditor.events {
		if ev.Action == "attestation_evaluated" {
			foundAttest = true
			if ev.Metadata["source"] != "k8s-sa" {
				t.Errorf("audit source = %v", ev.Metadata["source"])
			}
			if ev.Metadata["assurance_level"] != "software" {
				t.Errorf("audit assurance_level = %v", ev.Metadata["assurance_level"])
			}
		}
	}
	if !foundAttest {
		t.Error("no attestation_evaluated audit event found")
	}
}

func hardwareAttestationRequest() *core.TokenExchangeRequest {
	req := validRequest()
	req.Attestation = &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		Hardware: []*core.ServerAttestHardware{
			{Type: "tpm2", Quote: []byte("q"), Nonce: []byte("n")},
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}
	return req
}

// HARDEN-003: in dev mode, hardware header claims are passed through as-is.
func TestExchange_WithHardwareAttestation_DevMode_AssuranceLevelHardware(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithDevMode(true))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	resp, err := engine.Exchange(context.Background(), hardwareAttestationRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}
	var assurance string
	if err := token.Get("assurance_level", &assurance); err != nil {
		t.Fatalf("missing assurance_level: %v", err)
	}
	if assurance != "hardware" {
		t.Errorf("assurance_level = %q, want hardware", assurance)
	}
}

// HARDEN-003: in production, hardware assurance from the header is capped to "software".
func TestExchange_WithHardwareAttestation_ProdMode_AssuranceCapped(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}) // devMode defaults false
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	resp, err := engine.Exchange(context.Background(), hardwareAttestationRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}
	var assurance string
	if err := token.Get("assurance_level", &assurance); err != nil {
		t.Fatalf("missing assurance_level: %v", err)
	}
	if assurance != "software" {
		t.Errorf("assurance_level = %q, want software (hardware capped in prod mode)", assurance)
	}
}

func TestExchange_WithoutAttestation_NoAttestationClaims(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	// No attestation set — backward compat.

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var dummy string
	if err := token.Get("assurance_level", &dummy); err == nil {
		t.Error("assurance_level should not be present without attestation")
	}
	var dummy2 map[string]interface{}
	if err := token.Get("attestation", &dummy2); err == nil {
		t.Error("attestation claim should not be present without attestation")
	}
}

func TestExchange_WithStaleAttestation_ReturnsError(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.Attestation = &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().Add(-10 * time.Minute), // stale
	}

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for stale attestation")
	}

	// Verify audit event for invalid attestation.
	var foundInvalid bool
	for _, ev := range auditor.events {
		if ev.Action == "attestation_invalid" {
			foundInvalid = true
			if ev.Decision != "denied" {
				t.Errorf("audit decision = %q, want denied", ev.Decision)
			}
		}
	}
	if !foundInvalid {
		t.Error("no attestation_invalid audit event found")
	}
}

func TestExchange_AttestationContextPassedToPolicy(t *testing.T) {
	// Use a policy that captures the input so we can inspect it.
	var capturedInput *core.PolicyInput
	policy := &mockPolicy{
		decision: &core.PolicyDecision{Allowed: true},
	}
	capturePolicy := &capturingPolicy{
		inner:    policy,
		captured: &capturedInput,
	}

	engine, err := New(goodIdentity(), capturePolicy, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.Attestation = &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		Workload: &core.ServerAttestWorkload{
			BinaryHash: "sha256:abc123",
			Namespace:  "prod",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}

	_, err = engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if capturedInput == nil {
		t.Fatal("policy was not called")
	}

	attestCtx, ok := capturedInput.Context["attestation"]
	if !ok {
		t.Fatal("attestation not in policy context")
	}

	// Marshal/unmarshal to inspect structure.
	data, _ := json.Marshal(attestCtx)
	var attestMap map[string]interface{}
	_ = json.Unmarshal(data, &attestMap)

	if attestMap["assurance_level"] != "software" {
		t.Errorf("assurance_level = %v", attestMap["assurance_level"])
	}
	platform := attestMap["platform"].(map[string]interface{})
	if platform["source"] != "k8s-sa" {
		t.Errorf("platform.source = %v", platform["source"])
	}
	workload := attestMap["workload"].(map[string]interface{})
	if workload["binary_hash"] != "sha256:abc123" {
		t.Errorf("workload.binary_hash = %v", workload["binary_hash"])
	}
}

// capturingPolicy wraps a policy mock and captures the input.
type capturingPolicy struct {
	inner    *mockPolicy
	captured **core.PolicyInput
}

func (c *capturingPolicy) Evaluate(_ context.Context, input *core.PolicyInput) (*core.PolicyDecision, error) {
	*c.captured = input
	return c.inner.decision, c.inner.err
}

func (c *capturingPolicy) LoadBundle(context.Context, string) error {
	return nil
}
