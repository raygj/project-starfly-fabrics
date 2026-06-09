package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// testExchangePolicy is a minimal exchange policy for testing.
const testExchangePolicy = `
package starfly.exchange

import future.keywords.in

default allow := false

allow if {
    valid_subject
    trusted_target
}

valid_subject if {
    input.subject.attestation != null
    input.subject.attestation.method != ""
    input.subject.trust_domain != ""
}

trusted_target if {
    some td in data.trust_domains
    td.name == input.target
    td.enabled == true
}

reason := "subject has no attestation evidence" if {
    not valid_subject
}

reason := "target is not a trusted trust domain" if {
    valid_subject
    not trusted_target
}

claims := {"exchanged": true} if {
    allow
}
`

// testSignalsPolicy is a minimal signals policy for testing.
const testSignalsPolicy = `
package starfly.signals

default allow := false

allow if {
    input.subject.attestation != null
    input.subject.attestation.method != ""
}

reason := "subject has no attestation evidence" if {
    not allow
}
`

// testTrustDomainsData provides trust domain configuration for the test policies.
const testTrustDomainsData = `
{
    "trust_domains": [
        {"name": "cluster-a.example.com", "enabled": true},
        {"name": "cluster-b.example.com", "enabled": true},
        {"name": "disabled.example.com", "enabled": false}
    ]
}
`

// writePolicyBundle writes Rego files and a data.json to a temp directory.
func writePolicyBundle(t testing.TB, dir string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, "exchange.rego"), []byte(testExchangePolicy), 0644); err != nil {
		t.Fatalf("writing exchange.rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signals.rego"), []byte(testSignalsPolicy), 0644); err != nil {
		t.Fatalf("writing signals.rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(testTrustDomainsData), 0644); err != nil {
		t.Fatalf("writing data.json: %v", err)
	}
}

func validSubject() *core.WorkloadIdentity {
	return &core.WorkloadIdentity{
		ID:          "spiffe://cluster-a.example.com/workload/api",
		TrustDomain: "cluster-a.example.com",
		Attestation: &core.AttestationEvidence{
			Method:    "k8s-sa",
			Timestamp: time.Now(),
			NodeID:    "node-1",
			Namespace: "default",
		},
		Claims: map[string]interface{}{
			"pod": "api-server-abc123",
		},
	}
}

func TestEvaluate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	engine := New(nil, core.PolicyConfig{})
	if err := engine.LoadBundle(ctx, dir); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}

	tests := []struct {
		name        string
		input       *core.PolicyInput
		wantAllowed bool
		wantReason  string
		wantClaims  bool
	}{
		{
			name: "allow valid exchange",
			input: &core.PolicyInput{
				Action:  "exchange",
				Subject: validSubject(),
				Target:  "cluster-b.example.com",
				Context: map[string]interface{}{"scope": ""},
			},
			wantAllowed: true,
			wantReason:  "",
			wantClaims:  true,
		},
		{
			name: "deny missing attestation",
			input: &core.PolicyInput{
				Action: "exchange",
				Subject: &core.WorkloadIdentity{
					ID:          "spiffe://cluster-a.example.com/workload/api",
					TrustDomain: "cluster-a.example.com",
					// No attestation
				},
				Target:  "cluster-b.example.com",
				Context: map[string]interface{}{},
			},
			wantAllowed: false,
			wantReason:  "subject has no attestation evidence",
		},
		{
			name: "deny untrusted target",
			input: &core.PolicyInput{
				Action:  "exchange",
				Subject: validSubject(),
				Target:  "unknown.example.com",
				Context: map[string]interface{}{},
			},
			wantAllowed: false,
			wantReason:  "target is not a trusted trust domain",
		},
		{
			name: "deny invalid action (no policy package)",
			input: &core.PolicyInput{
				Action:  "nonexistent",
				Subject: validSubject(),
				Target:  "cluster-b.example.com",
				Context: map[string]interface{}{},
			},
			wantAllowed: false,
			wantReason:  "no policy found",
		},
		{
			name: "allow signal with valid attestation",
			input: &core.PolicyInput{
				Action:  "signals",
				Subject: validSubject(),
				Target:  "",
				Context: map[string]interface{}{},
			},
			wantAllowed: true,
			wantReason:  "",
		},
		{
			name: "deny signal without attestation",
			input: &core.PolicyInput{
				Action: "signals",
				Subject: &core.WorkloadIdentity{
					ID:          "spiffe://cluster-a.example.com/workload/api",
					TrustDomain: "cluster-a.example.com",
				},
				Target:  "",
				Context: map[string]interface{}{},
			},
			wantAllowed: false,
			wantReason:  "subject has no attestation evidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Evaluate(ctx, tt.input)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}

			if decision.Allowed != tt.wantAllowed {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllowed)
			}

			if decision.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", decision.Reason, tt.wantReason)
			}

			if tt.wantClaims && decision.Claims == nil {
				t.Error("expected Claims to be non-nil")
			}
			if !tt.wantClaims && decision.Claims != nil {
				t.Errorf("expected Claims to be nil, got %v", decision.Claims)
			}
		})
	}
}

func TestLoadBundle_NonExistentPath(t *testing.T) {
	engine := New(nil, core.PolicyConfig{})
	err := engine.LoadBundle(context.Background(), "/nonexistent/path/to/policies")
	if err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}
}

func TestLoadBundle_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	engine := New(nil, core.PolicyConfig{})
	err := engine.LoadBundle(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for empty directory, got nil")
	}
}

func TestLoadBundle_InvalidRego(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.rego"), []byte("this is not valid rego!!!"), 0644); err != nil {
		t.Fatal(err)
	}
	engine := New(nil, core.PolicyConfig{})
	err := engine.LoadBundle(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for invalid Rego, got nil")
	}
}

func TestEvaluate_NoCompiler(t *testing.T) {
	engine := New(nil, core.PolicyConfig{})
	decision, err := engine.Evaluate(context.Background(), &core.PolicyInput{
		Action: "exchange",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("expected deny when no compiler loaded")
	}
	if decision.Reason != "no policy found" {
		t.Errorf("Reason = %q, want %q", decision.Reason, "no policy found")
	}
}

// testAuditor captures audit events for testing.
type testAuditor struct {
	events []*core.AuditEvent
}

func (a *testAuditor) Log(_ context.Context, event *core.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

func TestLoadBundle_SignedBundle_Valid(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	privPEM, pubPEM := generateTestKeyPair(t)
	keyFile := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyFile, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}
	signTestBundle(t, dir, privPEM, "starfly")

	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "starfly",
	}
	engine := New(nil, cfg)
	if err := engine.LoadBundle(context.Background(), dir); err != nil {
		t.Fatalf("LoadBundle with valid signed bundle: %v", err)
	}

	// Verify the engine works after loading a signed bundle.
	decision, err := engine.Evaluate(context.Background(), &core.PolicyInput{
		Action:  "exchange",
		Subject: validSubject(),
		Target:  "cluster-b.example.com",
		Context: map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected allow for valid signed bundle + valid input")
	}
}

func TestLoadBundle_SignedBundle_Tampered(t *testing.T) {
	dir := t.TempDir()
	writePolicyBundle(t, dir)

	privPEM, pubPEM := generateTestKeyPair(t)
	keyFile := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyFile, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}
	signTestBundle(t, dir, privPEM, "starfly")

	// Tamper after signing.
	if err := os.WriteFile(filepath.Join(dir, "exchange.rego"), []byte("package starfly.exchange\ndefault allow := true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	auditor := &testAuditor{}
	cfg := core.PolicyConfig{
		BundlePath:    dir,
		SigningKeyFile: keyFile,
		SigningKeyID:   "starfly",
	}
	engine := New(auditor, cfg)
	err := engine.LoadBundle(context.Background(), dir)
	if err == nil {
		t.Fatal("expected LoadBundle to reject tampered signed bundle")
	}

	// Verify audit event was emitted.
	if len(auditor.events) == 0 {
		t.Fatal("expected audit event for bundle rejection")
	}
	ev := auditor.events[0]
	if ev.Type != "policy" || ev.Action != "bundle_rejected" {
		t.Errorf("audit event = {type:%q, action:%q}, want {type:\"policy\", action:\"bundle_rejected\"}", ev.Type, ev.Action)
	}
}

