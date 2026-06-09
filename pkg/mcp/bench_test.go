package mcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/starfly-fabrics/starfly/pkg/audit"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// benchSetup creates a reusable benchmark environment.
type benchSetup struct {
	privKey  *rsa.PrivateKey
	cfg      Config
	token    string
	body     []byte
	registry *Registry
	wt       *WorkflowTracker
	ledger   *audit.ECTLedger
}

func newBenchSetup(b *testing.B) *benchSetup {
	b.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:            "bench-tool",
		ResourceURI:       "https://mcp.example.com/tools/bench",
		RequiredCapabilities: []string{"read"},
		MaxBlastRadius:    "workspace:*",
		AllowedOperations: []string{"query", "read", "write"},
		AllowedTargets:    []string{"postgresql://analytics.prod:5432/metrics"},
		RequiresExecution: true,
	})

	wt := NewWorkflowTracker()
	ledger := audit.NewECTLedger()

	body := []byte(`{"query":"SELECT count(*) FROM events WHERE ts > now() - interval '1 hour'"}`)
	h := sha256.Sum256(body)
	inpHash := base64.RawURLEncoding.EncodeToString(h[:])

	builder := jwt.New()
	claims := map[string]interface{}{
		"sub":          "wimse://dev.local/agent/bench-agent",
		"iss":          "starfly-unit-1",
		"aud":          []string{"https://mcp.example.com/tools/bench"},
		"exp":          time.Now().Add(5 * time.Minute),
		"iat":          time.Now(),
		"caps":         []interface{}{"read", "write"},
		"blast_radius": "workspace:dev",
		"exec_act":     "query",
		"inp_hash":     inpHash,
		"target":       "postgresql://analytics.prod:5432/metrics",
		"wid":          "bench-wf-001",
		"nonce":        "bench-nonce",
	}
	for k, v := range claims {
		_ = builder.Set(k, v)
	}
	signed, err := jwt.Sign(builder, jwt.WithKey(jwa.RS256(), privKey))
	if err != nil {
		b.Fatalf("sign token: %v", err)
	}

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
		SigningKey:         privKey,
		SigningKeyID:       "bench-kid",
		Issuer:             "wimse://bench.local",
		WorkflowTracker:    wt,
		ECTLedger:          ledger,
	}

	return &benchSetup{
		privKey:  privKey,
		cfg:      cfg,
		token:    string(signed),
		body:     body,
		registry: registry,
		wt:       wt,
		ledger:   ledger,
	}
}

// BenchmarkFullPipeline benchmarks the complete 5-phase verification pipeline.
// Target: <5ms
func BenchmarkFullPipeline(b *testing.B) {
	s := newBenchSetup(b)
	ctx := context.Background()
	opts := &VerifyOptions{RequestBody: s.body}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyToolCall(ctx, s.cfg, s.token, "bench-tool", opts)
		if err != nil {
			b.Fatalf("VerifyToolCall: %v", err)
		}
	}
}

// BenchmarkIdentityPhase benchmarks Phase 1: JWT signature verification.
// Target: <2ms
func BenchmarkIdentityPhase(b *testing.B) {
	s := newBenchSetup(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := jwt.Parse([]byte(s.token),
			jwt.WithKey(jwa.RS256(), &s.privKey.PublicKey),
			jwt.WithValidate(true),
		)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

// BenchmarkAuthorizationPhase benchmarks Phase 2: audience + capabilities + blast radius + OPA.
// Target: <1ms
func BenchmarkAuthorizationPhase(b *testing.B) {
	s := newBenchSetup(b)

	// Pre-extract claims to isolate authorization checks.
	parsed, _ := jwt.Parse([]byte(s.token),
		jwt.WithKey(jwa.RS256(), &s.privKey.PublicKey),
		jwt.WithValidate(true),
	)
	claims := extractClaims(parsed)
	tool, _ := s.registry.Get("bench-tool")
	ctx := context.Background()
	policy := s.cfg.Policy

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Audience check.
		if claims.Audience != tool.ResourceURI {
			b.Fatal("audience mismatch")
		}
		// Capability check.
		if err := checkCapabilities(claims.Capabilities, tool.RequiredCapabilities); err != nil {
			b.Fatal(err)
		}
		// Blast radius check.
		if !blastRadiusFits(claims.BlastRadius, tool.MaxBlastRadius) {
			b.Fatal("blast radius")
		}
		// OPA policy.
		dec, _ := policy.Evaluate(ctx, &core.PolicyInput{Action: "mcp_tool_call"})
		if !dec.Allowed {
			b.Fatal("policy denied")
		}
	}
}

// BenchmarkExecutionBinding benchmarks Phase 3: exec_act + inp_hash + target.
// Target: <0.1ms
func BenchmarkExecutionBinding(b *testing.B) {
	s := newBenchSetup(b)

	parsed, _ := jwt.Parse([]byte(s.token),
		jwt.WithKey(jwa.RS256(), &s.privKey.PublicKey),
		jwt.WithValidate(true),
	)
	claims := extractClaims(parsed)
	tool, _ := s.registry.Get("bench-tool")
	opts := &VerifyOptions{RequestBody: s.body}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifyExecutionBinding(claims, tool, opts); err != nil {
			b.Fatalf("execution binding: %v", err)
		}
	}
}

// BenchmarkRevocationCheck benchmarks Phase 4: O(1) revocation index lookup.
// Target: <0.001ms
func BenchmarkRevocationCheck(b *testing.B) {
	s := newBenchSetup(b)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry, err := s.cfg.RevocationChecker.IsRevoked(ctx, "wimse://dev.local/agent/bench-agent")
		if err != nil {
			b.Fatal(err)
		}
		if entry != nil {
			b.Fatal("unexpected revocation")
		}
	}
}

// BenchmarkECTGeneration benchmarks Phase 5: post-execution ECT signing.
// Target: <2ms
func BenchmarkECTGeneration(b *testing.B) {
	s := newBenchSetup(b)
	responseBody := []byte(`{"rows":42,"elapsed_ms":12}`)

	claims := &VerifiedClaims{
		Subject:  "wimse://dev.local/agent/bench-agent",
		Issuer:   "starfly-unit-1",
		Audience: "https://mcp.example.com/tools/bench",
		ToolID:   "bench-tool",
		Execution: &core.ExecutionScope{
			ExecAct:    "query",
			InputHash:  "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
			Target:     "postgresql://analytics.prod:5432/metrics",
			WorkflowID: "bench-wf-001",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateECT(&ECTRequest{
			Claims:       claims,
			ToolID:       "bench-tool",
			ResponseBody: responseBody,
			DurationMS:   12,
		}, s.cfg.Issuer, s.privKey, "bench-kid")
		if err != nil {
			b.Fatalf("GenerateECT: %v", err)
		}
	}
}

// BenchmarkInputHash benchmarks the SHA-256 + base64url computation for inp_hash.
func BenchmarkInputHash(b *testing.B) {
	body := []byte(`{"query":"SELECT count(*) FROM events WHERE ts > now() - interval '1 hour'"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = computeInputHash(body)
	}
}

// BenchmarkLedgerAppend benchmarks ECT ledger append (hash chain computation).
func BenchmarkLedgerAppend(b *testing.B) {
	ledger := audit.NewECTLedger()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ledger.Append(&audit.ECTLedgerEntry{
			JTI:     fmt.Sprintf("task-%010d", i),
			Issuer:  "wimse://bench.local",
			Subject: "wimse://dev.local/agent/bench",
			ToolID:  "bench-tool",
			ExecAct: "query",
		})
	}
}

// BenchmarkLedgerLookup benchmarks O(1) JTI lookup in a populated ledger.
func BenchmarkLedgerLookup(b *testing.B) {
	ledger := audit.NewECTLedger()

	// Pre-populate with 10K entries.
	for i := 0; i < 10000; i++ {
		_, _ = ledger.Append(&audit.ECTLedgerEntry{
			JTI: fmt.Sprintf("task-%010d", i),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ledger.Lookup("task-0000005000")
	}
}

// BenchmarkWorkflowRecordTask benchmarks DAG task recording.
func BenchmarkWorkflowRecordTask(b *testing.B) {
	wt := NewWorkflowTracker()
	now := time.Now()

	// Record a root task for parent references.
	_ = wt.RecordTask("bench-wf", "root", now, []string{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = wt.RecordTask("bench-wf",
			fmt.Sprintf("task-%010d", i),
			now.Add(time.Duration(i)*time.Millisecond),
			[]string{"root"})
	}
}
