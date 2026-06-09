package exchange

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── Execution-scoped token tests ──────────────────────────────────

func TestExchange_ExecutionScoped_HasShortTTL(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method: "POST",
		URI:    "https://api.example.com/v1/transfers",
		Nonce:  "test-nonce-001",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Execution-scoped tokens should have 30s TTL.
	if resp.ExpiresIn != 30 {
		t.Errorf("ExpiresIn = %d, want 30 (execution-scoped)", resp.ExpiresIn)
	}

	// Parse token and verify short expiry.
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	iat, _ := token.IssuedAt()
	exp, _ := token.Expiration()
	ttl := exp.Sub(iat)
	if ttl != ExecutionScopeTTL {
		t.Errorf("token TTL = %v, want %v", ttl, ExecutionScopeTTL)
	}
}

func TestExchange_ExecutionScoped_HasClaims(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	payloadBody := []byte(`{"from":"acc-123","to":"acc-456","amount":1000}`)
	hash := sha256.Sum256(payloadBody)
	payloadHash := base64.RawURLEncoding.EncodeToString(hash[:])

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method:      "POST",
		URI:         "https://api.bank.com/v1/transfers",
		PayloadHash: payloadHash,
		Nonce:       "test-nonce-002",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Verify htm claim.
	var htm string
	if err := token.Get("htm", &htm); err != nil {
		t.Fatalf("getting htm claim: %v", err)
	}
	if htm != "POST" {
		t.Errorf("htm = %q, want %q", htm, "POST")
	}

	// Verify htu claim.
	var htu string
	if err := token.Get("htu", &htu); err != nil {
		t.Fatalf("getting htu claim: %v", err)
	}
	if htu != "https://api.bank.com/v1/transfers" {
		t.Errorf("htu = %q, want %q", htu, "https://api.bank.com/v1/transfers")
	}

	// Verify inp_hash claim (ECT-aligned, replaces payload_hash).
	var ph string
	if err := token.Get("inp_hash", &ph); err != nil {
		t.Fatalf("getting inp_hash claim: %v", err)
	}
	if ph != payloadHash {
		t.Errorf("inp_hash = %q, want %q", ph, payloadHash)
	}

	// Verify nonce claim.
	var nonce string
	if err := token.Get("nonce", &nonce); err != nil {
		t.Fatalf("getting nonce claim: %v", err)
	}
	if nonce != "test-nonce-002" {
		t.Errorf("nonce = %q, want %q", nonce, "test-nonce-002")
	}
}

func TestExchange_WithoutExecutionScope_DefaultTTL(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without execution scope, standard 5-minute TTL.
	if resp.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want 300 (standard TTL)", resp.ExpiresIn)
	}
}

func TestExchange_ExecutionScoped_NoClaims_WithoutScope(t *testing.T) {
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

	// htm/htu should NOT be present on standard tokens.
	var htm string
	if err := token.Get("htm", &htm); err == nil {
		t.Error("htm claim should not be present on non-execution-scoped token")
	}
}

func TestExchange_ExecutionScoped_NonceReplay(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com/v1/accounts",
		Nonce:  "unique-nonce-123",
	}

	// First use should succeed.
	_, err = engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("first exchange should succeed: %v", err)
	}

	// Second use with same nonce should fail.
	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected nonce replay error, got nil")
	}
	if !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("expected ErrNonceReplay, got %v", err)
	}
}

func TestExchange_ExecutionScoped_MissingMethod(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		URI:   "https://api.example.com/v1/accounts",
		Nonce: "nonce-1",
	}

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing method")
	}
	if !errors.Is(err, ErrExecutionScopeInvalid) {
		t.Fatalf("expected ErrExecutionScopeInvalid, got %v", err)
	}
}

func TestExchange_ExecutionScoped_MissingURI(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method: "GET",
		Nonce:  "nonce-2",
	}

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing URI")
	}
	if !errors.Is(err, ErrExecutionScopeInvalid) {
		t.Fatalf("expected ErrExecutionScopeInvalid, got %v", err)
	}
}

func TestExchange_ExecutionScoped_MissingNonce(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com/v1/accounts",
	}

	_, err = engine.Exchange(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
	if !errors.Is(err, ErrExecutionScopeInvalid) {
		t.Fatalf("expected ErrExecutionScopeInvalid, got %v", err)
	}
}

// ── VerifyExecutionScope tests ────────────────────────────────────

func TestVerifyExecutionScope_CorrectAction(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	scope := &core.ExecutionScope{
		Method: "POST",
		URI:    "https://api.example.com/v1/transfers",
		Nonce:  "verify-nonce-1",
	}

	req := validRequest()
	req.ExecutionScope = scope

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Same action should pass verification.
	if err := VerifyExecutionScope(token, scope); err != nil {
		t.Fatalf("verification should pass for correct action: %v", err)
	}
}

func TestVerifyExecutionScope_WrongMethod(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method: "POST",
		URI:    "https://api.example.com/v1/transfers",
		Nonce:  "verify-nonce-2",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Different method should fail.
	wrongScope := &core.ExecutionScope{
		Method: "DELETE",
		URI:    "https://api.example.com/v1/transfers",
	}
	if err := VerifyExecutionScope(token, wrongScope); err == nil {
		t.Fatal("verification should fail for wrong method")
	}
}

func TestVerifyExecutionScope_WrongURI(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method: "POST",
		URI:    "https://api.example.com/v1/transfers",
		Nonce:  "verify-nonce-3",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Different URI should fail.
	wrongScope := &core.ExecutionScope{
		Method: "POST",
		URI:    "https://api.example.com/v1/admin/users",
	}
	if err := VerifyExecutionScope(token, wrongScope); err == nil {
		t.Fatal("verification should fail for wrong URI")
	}
}

func TestVerifyExecutionScope_PayloadHashMismatch(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	originalHash := sha256.Sum256([]byte(`{"amount":1000}`))
	payloadHash := base64.RawURLEncoding.EncodeToString(originalHash[:])

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method:      "POST",
		URI:         "https://api.example.com/v1/transfers",
		PayloadHash: payloadHash,
		Nonce:       "verify-nonce-4",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Tampered payload should fail.
	tamperedHash := sha256.Sum256([]byte(`{"amount":999999}`))
	tamperedScope := &core.ExecutionScope{
		Method:      "POST",
		URI:         "https://api.example.com/v1/transfers",
		PayloadHash: base64.RawURLEncoding.EncodeToString(tamperedHash[:]),
	}
	if err := VerifyExecutionScope(token, tamperedScope); err == nil {
		t.Fatal("verification should fail for tampered payload hash")
	}
}

// ── Nonce tracker tests ──────────────────────────────────────────

func TestNonceTracker_Expiry(t *testing.T) {
	tracker := &nonceTracker{
		seen:   make(map[string]time.Time),
		maxAge: 10 * time.Millisecond,
	}

	// Record a nonce.
	if err := tracker.check("nonce-a"); err != nil {
		t.Fatalf("first check should pass: %v", err)
	}

	// Immediate replay should fail.
	if err := tracker.check("nonce-a"); err == nil {
		t.Fatal("immediate replay should fail")
	}

	// After expiry, the nonce should be cleaned up on the next cleanup cycle.
	time.Sleep(20 * time.Millisecond)

	// Drive enough operations to trigger opportunistic cleanup.
	for i := 0; i < cleanupInterval; i++ {
		_ = tracker.check(fmt.Sprintf("filler-%d", i))
	}

	// Original nonce should now be cleaned up.
	if _, exists := tracker.seen["nonce-a"]; exists {
		t.Error("expired nonce should have been cleaned up")
	}
}

func TestExchange_ExecutionScope_WithExecAct(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method:  "POST",
		URI:     "https://api.example.com/v1/data",
		Nonce:   "exec-act-test-nonce",
		ExecAct: "tools/transfer",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var execAct string
	if err := token.Get("exec_act", &execAct); err != nil {
		t.Fatalf("missing exec_act claim: %v", err)
	}
	if execAct != "tools/transfer" {
		t.Errorf("exec_act = %q, want tools/transfer", execAct)
	}
}

func TestExchange_ExecutionScope_WithTargetAndWorkflowID(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method:     "POST",
		URI:        "https://api.example.com/v1/data",
		Nonce:      "target-wid-test-nonce",
		Target:     "urn:starfly:resource:db/production",
		WorkflowID: "wf-12345",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var target string
	if err := token.Get("target", &target); err != nil {
		t.Fatalf("missing target claim: %v", err)
	}
	if target != "urn:starfly:resource:db/production" {
		t.Errorf("target = %q", target)
	}

	var wid string
	if err := token.Get("wid", &wid); err != nil {
		t.Fatalf("missing wid claim: %v", err)
	}
	if wid != "wf-12345" {
		t.Errorf("wid = %q", wid)
	}
}

func TestExchange_ExecutionScope_WithInputHash(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method:    "POST",
		URI:       "https://api.example.com/v1/data",
		Nonce:     "input-hash-test-nonce",
		InputHash: "sha256:input-hash-value",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var inpHash string
	if err := token.Get("inp_hash", &inpHash); err != nil {
		t.Fatalf("missing inp_hash claim: %v", err)
	}
	if inpHash != "sha256:input-hash-value" {
		t.Errorf("inp_hash = %q", inpHash)
	}
}

// ── VerifyExecutionScope edge case tests ─────────────────────────

func TestVerifyExecutionScope_MissingHtmClaim(t *testing.T) {
	token, err := jwt.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	scope := &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com",
	}
	if err := VerifyExecutionScope(token, scope); err == nil {
		t.Fatal("expected error for missing htm claim")
	}
}

func TestVerifyExecutionScope_MissingHtuClaim(t *testing.T) {
	token, err := jwt.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}
	_ = token.Set("htm", "GET")

	scope := &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com",
	}
	if err := VerifyExecutionScope(token, scope); err == nil {
		t.Fatal("expected error for missing htu claim")
	}
}

func TestVerifyExecutionScope_MissingInpHashClaim(t *testing.T) {
	token, err := jwt.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}
	_ = token.Set("htm", "POST")
	_ = token.Set("htu", "https://api.example.com/v1/transfers")

	scope := &core.ExecutionScope{
		Method:    "POST",
		URI:       "https://api.example.com/v1/transfers",
		InputHash: "sha256:abc123",
	}
	err = VerifyExecutionScope(token, scope)
	if err == nil {
		t.Fatal("expected error for missing inp_hash claim")
	}
	if !errors.Is(err, ErrExecutionScopeInvalid) {
		t.Errorf("expected ErrExecutionScopeInvalid, got %v", err)
	}
}

func TestVerifyExecutionScope_FallbackToPayloadHash(t *testing.T) {
	token, err := jwt.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}
	_ = token.Set("htm", "POST")
	_ = token.Set("htu", "https://api.example.com/v1/transfers")
	_ = token.Set("payload_hash", "hash-abc")

	scope := &core.ExecutionScope{
		Method:      "POST",
		URI:         "https://api.example.com/v1/transfers",
		PayloadHash: "hash-abc",
	}
	if err := VerifyExecutionScope(token, scope); err != nil {
		t.Fatalf("expected pass with payload_hash fallback: %v", err)
	}
}

func TestVerifyExecutionScope_InputHashPrecedence(t *testing.T) {
	token, err := jwt.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}
	_ = token.Set("htm", "POST")
	_ = token.Set("htu", "https://api.example.com/v1/transfers")
	_ = token.Set("inp_hash", "input-hash-value")

	scope := &core.ExecutionScope{
		Method:      "POST",
		URI:         "https://api.example.com/v1/transfers",
		InputHash:   "input-hash-value",
		PayloadHash: "old-payload-hash",
	}
	if err := VerifyExecutionScope(token, scope); err != nil {
		t.Fatalf("expected pass with InputHash precedence: %v", err)
	}
}

func TestVerifyExecutionScope_NoHashRequired(t *testing.T) {
	token, err := jwt.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}
	_ = token.Set("htm", "GET")
	_ = token.Set("htu", "https://api.example.com/v1/data")

	scope := &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com/v1/data",
	}
	if err := VerifyExecutionScope(token, scope); err != nil {
		t.Fatalf("expected pass with no hash: %v", err)
	}
}

// ── Nonce tracker tests ──────────────────────────────────────────

func TestNonceTracker_HighWaterMark(t *testing.T) {
	tracker := &nonceTracker{
		seen:   make(map[string]time.Time),
		maxAge: 1 * time.Millisecond, // very short so entries expire fast
	}

	// Fill past the high-water mark with already-expired entries.
	past := time.Now().Add(-1 * time.Second)
	for i := 0; i < nonceHighWaterMark+100; i++ {
		tracker.seen[fmt.Sprintf("old-%d", i)] = past
	}

	if tracker.size() != nonceHighWaterMark+100 {
		t.Fatalf("expected %d entries, got %d", nonceHighWaterMark+100, tracker.size())
	}

	// Next check should trigger high-water cleanup.
	if err := tracker.check("new-nonce"); err != nil {
		t.Fatalf("check should pass: %v", err)
	}

	// Expired entries should have been cleaned up.
	sz := tracker.size()
	if sz > nonceHighWaterMark {
		t.Errorf("expected cleanup to reduce size below %d, got %d", nonceHighWaterMark, sz)
	}
}
