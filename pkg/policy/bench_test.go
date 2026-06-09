package policy

import (
	"context"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// BenchmarkPolicyEvaluate measures a real OPA engine with a compiled Rego
// bundle evaluating an exchange action (3 queries: allow, reason, claims).
func BenchmarkPolicyEvaluate(b *testing.B) {
	ctx := context.Background()
	dir := b.TempDir()
	writePolicyBundle(b, dir)

	engine := New(nil, core.PolicyConfig{})
	if err := engine.LoadBundle(ctx, dir); err != nil {
		b.Fatalf("LoadBundle: %v", err)
	}

	input := &core.PolicyInput{
		Action: "exchange",
		Subject: &core.WorkloadIdentity{
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
		},
		Target:  "cluster-b.example.com",
		Context: map[string]interface{}{"scope": ""},
	}

	b.ResetTimer()
	for b.Loop() {
		decision, err := engine.Evaluate(ctx, input)
		if err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
		if !decision.Allowed {
			b.Fatalf("expected allow, got deny: %s", decision.Reason)
		}
	}
}
