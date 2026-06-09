package exchange

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// mintActorToken creates a signed actor token for delegation tests.
func mintActorToken(t *testing.T, engine *Engine, claims map[string]interface{}) string {
	t.Helper()

	now := time.Now().UTC()
	builder := jwt.NewBuilder().
		Subject("wimse://parent.example.com/agent/agent-a").
		Issuer("starfly").
		Audience([]string{"starfly"}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute))

	token, err := builder.Build()
	if err != nil {
		t.Fatalf("building actor token: %v", err)
	}

	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			t.Fatalf("setting claim %q: %v", k, err)
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), engine.signKey))
	if err != nil {
		t.Fatalf("signing actor token: %v", err)
	}
	return string(signed)
}

func TestExchange_Delegation_HappyPath(t *testing.T) {
	policyClaims := map[string]interface{}{
		"caps":         []interface{}{"read"},
		"blast_radius": "namespace",
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"delegation_depth": 3,
		"caps":             []interface{}{"read", "write", "list"},
		"blast_radius":     "cluster",
		"td":               "parent.example.com",
	})

	req := validRequest()
	req.ActorToken = actorToken

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the issued token.
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Verify delegation_depth decremented (3 → 2).
	var depth float64
	if err := token.Get("delegation_depth", &depth); err != nil {
		t.Fatalf("getting delegation_depth: %v", err)
	}
	if int(depth) != 2 {
		t.Errorf("delegation_depth = %v, want 2", depth)
	}

	// Verify obo chain contains parent.
	var obo []interface{}
	if err := token.Get("obo", &obo); err != nil {
		t.Fatalf("getting obo: %v", err)
	}
	if len(obo) != 1 {
		t.Fatalf("obo chain length = %d, want 1", len(obo))
	}
	if obo[0] != "wimse://parent.example.com/agent/agent-a" {
		t.Errorf("obo[0] = %v, want parent agent ID", obo[0])
	}
}

func TestExchange_Delegation_DepthExhausted(t *testing.T) {
	policyClaims := map[string]interface{}{
		"caps": []interface{}{"read"},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	// Parent has depth=0 — cannot delegate further.
	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"delegation_depth": 0,
		"caps":             []interface{}{"read"},
	})

	req := validRequest()
	req.ActorToken = actorToken

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected delegation denied error")
	}
	if !errors.Is(err, ErrDelegationDenied) {
		t.Fatalf("expected ErrDelegationDenied, got %v", err)
	}
	if !contains(err.Error(), "depth exhausted") {
		t.Errorf("error = %q, want containing 'depth exhausted'", err.Error())
	}
}

func TestExchange_Delegation_CapabilityEscalation(t *testing.T) {
	// Child requests "admin" which parent doesn't have.
	policyClaims := map[string]interface{}{
		"caps": []interface{}{"admin"},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"delegation_depth": 2,
		"caps":             []interface{}{"read", "write"},
	})

	req := validRequest()
	req.ActorToken = actorToken

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected delegation denied for capability escalation")
	}
	if !errors.Is(err, ErrDelegationDenied) {
		t.Fatalf("expected ErrDelegationDenied, got %v", err)
	}
	if !contains(err.Error(), "admin") {
		t.Errorf("error should mention the escalated capability: %v", err)
	}
}

func TestExchange_Delegation_BlastRadiusExpansion(t *testing.T) {
	// Child requests "fabric" which is broader than parent's "namespace".
	policyClaims := map[string]interface{}{
		"caps":         []interface{}{"read"},
		"blast_radius": "fabric",
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"delegation_depth": 2,
		"caps":             []interface{}{"read"},
		"blast_radius":     "namespace",
	})

	req := validRequest()
	req.ActorToken = actorToken

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected delegation denied for blast radius expansion")
	}
	if !errors.Is(err, ErrDelegationDenied) {
		t.Fatalf("expected ErrDelegationDenied, got %v", err)
	}
}

func TestExchange_Delegation_MultiHop(t *testing.T) {
	// Simulate A→B→C: parent already has an obo chain.
	policyClaims := map[string]interface{}{
		"caps":         []interface{}{"read"},
		"blast_radius": "namespace",
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"delegation_depth": 2,
		"caps":             []interface{}{"read", "write"},
		"blast_radius":     "cluster",
		"obo":              []interface{}{"wimse://root.example.com/agent/agent-root"},
	})

	req := validRequest()
	req.ActorToken = actorToken

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Depth should decrement (2 → 1).
	var depth float64
	if err := token.Get("delegation_depth", &depth); err != nil {
		t.Fatalf("getting delegation_depth: %v", err)
	}
	if int(depth) != 1 {
		t.Errorf("delegation_depth = %v, want 1", depth)
	}

	// OBO chain should have 2 entries: root + parent.
	var obo []interface{}
	if err := token.Get("obo", &obo); err != nil {
		t.Fatalf("getting obo: %v", err)
	}
	if len(obo) != 2 {
		t.Fatalf("obo chain length = %d, want 2", len(obo))
	}
	if obo[0] != "wimse://root.example.com/agent/agent-root" {
		t.Errorf("obo[0] = %v, want root agent", obo[0])
	}
	if obo[1] != "wimse://parent.example.com/agent/agent-a" {
		t.Errorf("obo[1] = %v, want parent agent", obo[1])
	}
}

func TestExchange_Delegation_InvalidActorToken(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ActorToken = "not-a-valid-jwt"

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid actor token")
	}
	if !errors.Is(err, ErrActorTokenInvalid) {
		t.Fatalf("expected ErrActorTokenInvalid, got %v", err)
	}

	// Should have an audit event for the invalid actor token.
	var found bool
	for _, ev := range auditor.events {
		if ev.Decision == "denied" && ev.Action == "token_exchange" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected denied audit event for invalid actor token")
	}
}

func TestExchange_Delegation_NarrowedCapsPassthrough(t *testing.T) {
	// Parent has [read, write, list]. Child requests [read] — strict subset.
	policyClaims := map[string]interface{}{
		"caps": []interface{}{"read"},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"delegation_depth": 1,
		"caps":             []interface{}{"read", "write", "list"},
	})

	req := validRequest()
	req.ActorToken = actorToken

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Token should have narrowed caps.
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var caps []interface{}
	if err := token.Get("caps", &caps); err != nil {
		t.Fatalf("getting caps: %v", err)
	}
	if len(caps) != 1 || caps[0] != "read" {
		t.Errorf("caps = %v, want [read]", caps)
	}

	// Depth should be 0 (1 → 0, terminal agent).
	var depth float64
	if err := token.Get("delegation_depth", &depth); err != nil {
		t.Fatalf("getting delegation_depth: %v", err)
	}
	if int(depth) != 0 {
		t.Errorf("delegation_depth = %v, want 0 (terminal)", depth)
	}
}

func TestExchange_NoDelegation_NoOBOClaims(t *testing.T) {
	// Without an actor token, no delegation claims should be present.
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// delegation_depth and obo should NOT be present.
	var depth float64
	if err := token.Get("delegation_depth", &depth); err == nil {
		t.Error("delegation_depth should not be present on non-delegated token")
	}
	var obo []interface{}
	if err := token.Get("obo", &obo); err == nil {
		t.Error("obo should not be present on non-delegated token")
	}
}

// ── Blast radius hierarchy tests ─────────────────────────────────

func TestBlastRadius_Hierarchy(t *testing.T) {
	tests := []struct {
		child  string
		parent string
		want   bool
	}{
		{"function", "namespace", true},      // narrower
		{"namespace", "namespace", true},      // equal
		{"namespace", "cluster", true},        // narrower
		{"cluster", "namespace", false},       // broader
		{"fabric", "namespace", false},        // much broader
		{"function", "fabric", true},          // much narrower
		{"namespace:trading", "cluster", true},       // qualified, narrower
		{"namespace:dev", "namespace:prod", true},    // same level (equal)
		{"cluster", "workspace:dev", true},           // same level (alias)
		{"trust_domain", "fabric", true},             // narrower
		{"custom-thing", "custom-thing", true},       // unknown, exact match
		{"custom-thing", "namespace", false},         // unknown vs known
	}

	for _, tt := range tests {
		got := isBlastRadiusNarrowerOrEqual(tt.child, tt.parent)
		if got != tt.want {
			t.Errorf("isBlastRadiusNarrowerOrEqual(%q, %q) = %v, want %v",
				tt.child, tt.parent, got, tt.want)
		}
	}
}

// ── Delegation audit trail test ──────────────────────────────────

func TestExchange_Delegation_ActorTokenMissingSubject(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	builder := jwt.NewBuilder().
		Issuer("starfly").
		Audience([]string{"starfly"}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute))
	token, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), engine.signKey))
	if err != nil {
		t.Fatal(err)
	}

	req := validRequest()
	req.ActorToken = string(signed)

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for actor token without subject")
	}
	if !errors.Is(err, ErrDelegationDenied) {
		t.Fatalf("expected ErrDelegationDenied, got %v", err)
	}
}

func TestExchange_Delegation_UnrestrictedDepth(t *testing.T) {
	policyClaims := map[string]interface{}{
		"caps": []interface{}{"read"},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatal(err)
	}

	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"caps": []interface{}{"read", "write"},
	})

	req := validRequest()
	req.ActorToken = actorToken

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatal(err)
	}

	var depth float64
	if err := token.Get("delegation_depth", &depth); err == nil {
		t.Error("delegation_depth should not be present for unrestricted delegation")
	}

	var obo []interface{}
	if err := token.Get("obo", &obo); err != nil {
		t.Fatalf("missing obo claim: %v", err)
	}
	if len(obo) != 1 {
		t.Errorf("obo length = %d, want 1", len(obo))
	}
}

func TestExchange_Delegation_AuditsDenial(t *testing.T) {
	policyClaims := map[string]interface{}{
		"caps": []interface{}{"admin"},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	actorToken := mintActorToken(t, engine, map[string]interface{}{
		"delegation_depth": 1,
		"caps":             []interface{}{"read"},
	})

	req := validRequest()
	req.ActorToken = actorToken

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected delegation denied")
	}

	// Check audit event for delegation denial.
	var found bool
	for _, ev := range auditor.events {
		if ev.Decision == "denied" && contains(ev.Reason, "delegation denied") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit event for delegation denial")
	}
}
