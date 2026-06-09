package exchange

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/secrets"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// ── Mock collaborators ──────────────────────────────────────────────

type mockIdentity struct {
	validateFunc func(ctx context.Context, credential, credType string) (*core.WorkloadIdentity, error)
}

func (m *mockIdentity) ValidateWorkload(ctx context.Context, credential, credType string) (*core.WorkloadIdentity, error) {
	return m.validateFunc(ctx, credential, credType)
}


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

type mockAuditor struct {
	events []*core.AuditEvent
}

func (m *mockAuditor) Log(_ context.Context, event *core.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────

func validRequest() *core.TokenExchangeRequest {
	return &core.TokenExchangeRequest{
		GrantType:        grantTypeTokenExchange,
		SubjectToken:     "test-sa-token",
		SubjectTokenType: subjectTokenTypeJWT,
		Audience:         "https://api.target.example.com",
		Scope:            "read:secrets",
	}
}

func goodIdentity() *mockIdentity {
	return &mockIdentity{
		validateFunc: func(_ context.Context, _, _ string) (*core.WorkloadIdentity, error) {
			return &core.WorkloadIdentity{
				ID:          "wimse://production.example.com/ns/default/sa/my-app",
				TrustDomain: "production.example.com",
				Attestation: &core.AttestationEvidence{Method: "k8s-sa"},
				Claims:      map[string]interface{}{"namespace": "default", "serviceaccount": "my-app"},
			}, nil
		},
	}
}

func allowPolicy(claims map[string]interface{}) *mockPolicy {
	return &mockPolicy{
		decision: &core.PolicyDecision{
			Allowed: true,
			Claims:  claims,
		},
	}
}

func denyPolicy(reason string) *mockPolicy {
	return &mockPolicy{
		decision: &core.PolicyDecision{
			Allowed: false,
			Reason:  reason,
		},
	}
}

// ── Tests ───────────────────────────────────────────────────────────

func TestExchange(t *testing.T) {
	tests := []struct {
		name         string
		req          *core.TokenExchangeRequest
		identity     *mockIdentity
		policy       *mockPolicy
		wantErr      error
		wantDecision string // expected audit decision
	}{
		{
			name:         "valid exchange",
			req:          validRequest(),
			identity:     goodIdentity(),
			policy:       allowPolicy(nil),
			wantDecision: "allowed",
		},
		{
			name:         "policy deny",
			req:          validRequest(),
			identity:     goodIdentity(),
			policy:       denyPolicy("namespace not allowed"),
			wantErr:      ErrPolicyDenied,
			wantDecision: "denied",
		},
		{
			name: "invalid grant type",
			req: func() *core.TokenExchangeRequest {
				r := validRequest()
				r.GrantType = "authorization_code"
				return r
			}(),
			identity: goodIdentity(),
			policy:   allowPolicy(nil),
			wantErr:  ErrInvalidGrantType,
		},
		{
			name: "unsupported token type",
			req: func() *core.TokenExchangeRequest {
				r := validRequest()
				r.SubjectTokenType = "urn:totally:unsupported:token-type"
				return r
			}(),
			identity: goodIdentity(),
			policy:   allowPolicy(nil),
			wantErr:  ErrUnsupportedToken,
		},
		{
			name: "identity validation fails",
			req:  validRequest(),
			identity: &mockIdentity{
				validateFunc: func(context.Context, string, string) (*core.WorkloadIdentity, error) {
					return nil, errors.New("token validation failed")
				},
			},
			policy: allowPolicy(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditor := &mockAuditor{}
			engine, err := New(tt.identity, tt.policy, auditor)
			if err != nil {
				t.Fatalf("creating engine: %v", err)
			}

			resp, err := engine.Exchange(context.Background(), tt.req)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error wrapping %v, got %v", tt.wantErr, err)
				}
				// Check audit event for policy deny.
				if tt.wantDecision != "" && len(auditor.events) > 0 {
					last := auditor.events[len(auditor.events)-1]
					if last.Decision != tt.wantDecision {
						t.Errorf("audit decision = %q, want %q", last.Decision, tt.wantDecision)
					}
				}
				return
			}

			// Identity failure — propagated error with no sentinel.
			if tt.name == "identity validation fails" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !contains(err.Error(), "token validation failed") {
					t.Fatalf("expected identity error, got %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.TokenType != "Bearer" {
				t.Errorf("TokenType = %q, want %q", resp.TokenType, "Bearer")
			}
			if resp.IssuedTokenType != subjectTokenTypeJWT {
				t.Errorf("IssuedTokenType = %q, want %q", resp.IssuedTokenType, subjectTokenTypeJWT)
			}
			if resp.ExpiresIn != 300 {
				t.Errorf("ExpiresIn = %d, want 300", resp.ExpiresIn)
			}
			if resp.Scope != tt.req.Scope {
				t.Errorf("Scope = %q, want %q", resp.Scope, tt.req.Scope)
			}
			if resp.AccessToken == "" {
				t.Fatal("AccessToken is empty")
			}

			// Check audit event.
			if tt.wantDecision != "" && len(auditor.events) > 0 {
				last := auditor.events[len(auditor.events)-1]
				if last.Decision != tt.wantDecision {
					t.Errorf("audit decision = %q, want %q", last.Decision, tt.wantDecision)
				}
			}
		})
	}
}

func TestExchange_JWTClaims(t *testing.T) {
	auditor := &mockAuditor{}
	policyClaims := map[string]interface{}{
		"caps":         []interface{}{"read", "list"},
		"blast_radius": "namespace",
	}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the signed JWT without verification to inspect claims.
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	// Verify standard claims.
	sub, _ := token.Subject()
	if sub != "wimse://production.example.com/ns/default/sa/my-app" {
		t.Errorf("sub = %q, want WIMSE URI", sub)
	}

	iss, _ := token.Issuer()
	if iss != "starfly" {
		t.Errorf("iss = %q, want %q", iss, "starfly")
	}

	aud, _ := token.Audience()
	if len(aud) == 0 || aud[0] != "https://api.target.example.com" {
		t.Errorf("aud = %v, want [https://api.target.example.com]", aud)
	}

	iat, _ := token.IssuedAt()
	if iat.IsZero() {
		t.Error("iat is zero")
	}
	exp, _ := token.Expiration()
	if exp.IsZero() {
		t.Error("exp is zero")
	}
	if !exp.After(iat) {
		t.Error("exp should be after iat")
	}

	// Verify WIMSE trust domain claim.
	var td string
	if err := token.Get("td", &td); err != nil {
		t.Fatalf("getting td claim: %v", err)
	}
	if td != "production.example.com" {
		t.Errorf("td = %q, want %q", td, "production.example.com")
	}

	// Verify policy-injected claims.
	var caps []interface{}
	if err := token.Get("caps", &caps); err != nil {
		t.Fatalf("getting caps claim: %v", err)
	}
	if len(caps) != 2 {
		t.Errorf("caps length = %d, want 2", len(caps))
	}

	var br string
	if err := token.Get("blast_radius", &br); err != nil {
		t.Fatalf("getting blast_radius claim: %v", err)
	}
	if br != "namespace" {
		t.Errorf("blast_radius = %q, want %q", br, "namespace")
	}

	// Verify the token is signed with RS256.
	msg, err := jws.Parse([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWS: %v", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		t.Fatal("no signatures found")
	}
	headers := sigs[0].ProtectedHeaders()
	alg, _ := headers.Algorithm()
	if alg != jwa.RS256() {
		t.Errorf("alg = %v, want RS256", alg)
	}
	kid, _ := headers.KeyID()
	if kid != "starfly-dev-1" {
		t.Errorf("kid = %q, want %q", kid, "starfly-dev-1")
	}
}

func TestPublicKeySet(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	set, err := engine.PublicKeySet()
	if err != nil {
		t.Fatalf("PublicKeySet: %v", err)
	}

	if set.Len() != 1 {
		t.Fatalf("key count = %d, want 1", set.Len())
	}

	key, ok := set.Key(0)
	if !ok {
		t.Fatal("failed to get key at index 0")
	}

	kid, _ := key.KeyID()
	if kid != "starfly-dev-1" {
		t.Errorf("kid = %q, want %q", kid, "starfly-dev-1")
	}

	alg, _ := key.Algorithm()
	if alg != jwa.RS256() {
		t.Errorf("alg = %v, want RS256", alg)
	}

	if kty := key.KeyType(); kty != jwa.RSA() {
		t.Errorf("kty = %v, want RSA", kty)
	}

	use, _ := key.KeyUsage()
	if use != "sig" {
		t.Errorf("use = %q, want %q", use, "sig")
	}

	// Key must be public (no private components).
	var rawKey interface{}
	if err := jwk.Export(key, &rawKey); err != nil {
		t.Fatalf("exporting key: %v", err)
	}
	switch rawKey.(type) {
	case *rsa.PublicKey:
		// OK
	default:
		t.Fatalf("expected *rsa.PublicKey, got %T", rawKey)
	}
}

func TestPublicKeySet_KidMatchesJWT(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	// Mint a token.
	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Extract kid from the JWT header.
	msg, err := jws.Parse([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWS: %v", err)
	}
	jwtKid, _ := msg.Signatures()[0].ProtectedHeaders().KeyID()

	// Get the JWKS kid.
	set, err := engine.PublicKeySet()
	if err != nil {
		t.Fatalf("PublicKeySet: %v", err)
	}
	jwksKey, ok := set.Key(0)
	if !ok {
		t.Fatal("no key in set")
	}
	jwksKid, _ := jwksKey.KeyID()

	if jwtKid != jwksKid {
		t.Errorf("JWT kid %q does not match JWKS kid %q", jwtKid, jwksKid)
	}
}

func TestPublicKeySet_VerifiesJWT(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	// Mint a token.
	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Get the public key set.
	set, err := engine.PublicKeySet()
	if err != nil {
		t.Fatalf("PublicKeySet: %v", err)
	}

	// Verify the JWT using the JWKS public key.
	_, err = jwt.Parse([]byte(resp.AccessToken), jwt.WithKeySet(set))
	if err != nil {
		t.Fatalf("JWT verification with JWKS failed: %v", err)
	}
}

// ── Mock SyncBus ─────────────────────────────────────────────────

type mockSyncBus struct {
	flashes []*core.Signal
	err     error
}

func (m *mockSyncBus) Flash(_ context.Context, signal *core.Signal) error {
	m.flashes = append(m.flashes, signal)
	return m.err
}

func (m *mockSyncBus) Subscribe(context.Context, string, core.SignalHandler) error {
	return errors.New("not implemented")
}

func (m *mockSyncBus) Replay(context.Context, time.Time) ([]*core.Signal, error) {
	return nil, errors.New("not implemented")
}

// ── SyncBus integration tests ────────────────────────────────────

func TestExchange_FlashOnSuccess(t *testing.T) {
	bus := &mockSyncBus{}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor, WithSyncBus(bus, "unit-test-01"))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(bus.flashes) != 1 {
		t.Fatalf("flash count = %d, want 1", len(bus.flashes))
	}

	sig := bus.flashes[0]
	if sig.Type != "identity_event" {
		t.Errorf("signal type = %q, want %q", sig.Type, "identity_event")
	}
	if sig.Payload["workload_id"] != "wimse://production.example.com/ns/default/sa/my-app" {
		t.Errorf("workload_id = %v", sig.Payload["workload_id"])
	}
	if sig.Payload["audience"] != "https://api.target.example.com" {
		t.Errorf("audience = %v", sig.Payload["audience"])
	}
	if sig.Payload["trust_domain"] != "production.example.com" {
		t.Errorf("trust_domain = %v", sig.Payload["trust_domain"])
	}
}

func TestExchange_NoFlashOnDeny(t *testing.T) {
	bus := &mockSyncBus{}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), denyPolicy("not allowed"), auditor, WithSyncBus(bus, "unit-test-01"))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected error for denied exchange")
	}

	if len(bus.flashes) != 0 {
		t.Errorf("flash count = %d, want 0 (denied exchanges should not flash)", len(bus.flashes))
	}
}

func TestExchange_FlashError_DoesNotFailExchange(t *testing.T) {
	bus := &mockSyncBus{err: errors.New("NATS unavailable")}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor, WithSyncBus(bus, "unit-test-01"))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("exchange should succeed even when flash fails: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	// Flash was attempted.
	if len(bus.flashes) != 1 {
		t.Fatalf("flash count = %d, want 1", len(bus.flashes))
	}

	// Audit should contain a signal_flash_failed event.
	var found bool
	for _, ev := range auditor.events {
		if ev.Action == "signal_flash_failed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected signal_flash_failed audit event")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ── Mock RevocationIndex ──────────────────────────────────────────

type mockRevocation struct {
	entries map[string]*core.RevocationEntry
	err     error
}

func (m *mockRevocation) IsRevoked(_ context.Context, subjectID string) (*core.RevocationEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.entries[subjectID], nil
}

func (m *mockRevocation) Revoke(_ context.Context, subjectID string, reason string, expiresAt time.Time) error {
	if m.entries == nil {
		m.entries = make(map[string]*core.RevocationEntry)
	}
	m.entries[subjectID] = &core.RevocationEntry{SubjectID: subjectID, Reason: reason, ExpiresAt: expiresAt}
	return nil
}

func (m *mockRevocation) Cleanup(_ context.Context) (int, error) {
	return 0, nil
}

func (m *mockRevocation) Hash() string       { return "" }
func (m *mockRevocation) Export() ([]byte, error) { return nil, nil }
func (m *mockRevocation) Import(_ []byte) error   { return nil }

// ── Revocation tests ─────────────────────────────────────────────

func TestExchange_RevokedSubject(t *testing.T) {
	revIdx := &mockRevocation{
		entries: map[string]*core.RevocationEntry{
			"wimse://production.example.com/ns/default/sa/my-app": {
				SubjectID: "wimse://production.example.com/ns/default/sa/my-app",
				Reason:    "session-revoked",
			},
		},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor, WithRevocationChecker(revIdx))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected error for revoked subject")
	}
	if !errors.Is(err, ErrSubjectRevoked) {
		t.Fatalf("expected ErrSubjectRevoked, got %v", err)
	}

	// Should have a denied audit event with revocation reason including the entry's reason.
	var found bool
	for _, ev := range auditor.events {
		if ev.Decision == "denied" && strings.Contains(ev.Reason, "subject identity revoked") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected denied audit event with revocation reason")
	}
}

func TestExchange_NotRevoked(t *testing.T) {
	revIdx := &mockRevocation{
		entries: map[string]*core.RevocationEntry{},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor, WithRevocationChecker(revIdx))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}

func TestExchange_RevocationCheckError_FailsOpen(t *testing.T) {
	revIdx := &mockRevocation{
		err: errors.New("revocation index unavailable"),
	}
	auditor := &mockAuditor{}
	var callbackCalled int
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor,
		WithRevocationChecker(revIdx),
		WithOnRevocationError(func() { callbackCalled++ }),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	// Fail open: exchange should succeed even when revocation check errors.
	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("expected fail-open, got error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	// Verify callback was invoked (used for metrics counter).
	if callbackCalled != 1 {
		t.Errorf("expected onRevocationError callback to be called once, got %d", callbackCalled)
	}

	// Verify audit event was logged for the fail-open.
	var found bool
	for _, ev := range auditor.events {
		if ev.Action == "revocation_check_failed" && ev.Decision == "allowed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit event with action=revocation_check_failed and decision=allowed")
	}
}

func TestExchange_NoRevocationChecker(t *testing.T) {
	// Without a revocation checker, exchange works normally.
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}

// ── OTel span tests ─────────────────────────────────────────────────

// setupTestTracer installs an in-memory span exporter and returns it.
// The caller should defer restoring the original provider.
func setupTestTracer() *tracetest.InMemoryExporter {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(tp)
	return exporter
}

func TestExchange_CreatesSpans(t *testing.T) {
	exporter := setupTestTracer()

	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exporter.GetSpans()

	// Expect at least: exchange.Exchange, exchange.ValidateWorkload,
	// exchange.EvaluatePolicy, exchange.SignJWT, exchange.AuditLog
	expectedSpans := map[string]bool{
		"exchange.Exchange":         false,
		"exchange.ValidateWorkload": false,
		"exchange.EvaluatePolicy":   false,
		"exchange.SignJWT":          false,
		"exchange.AuditLog":         false,
	}

	for _, s := range spans {
		if _, ok := expectedSpans[s.Name]; ok {
			expectedSpans[s.Name] = true
		}
	}

	for name, found := range expectedSpans {
		if !found {
			t.Errorf("expected span %q not found in recorded spans", name)
		}
	}
}

func TestExchange_SpansShareTraceID(t *testing.T) {
	exporter := setupTestTracer()

	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}

	traceID := spans[0].SpanContext.TraceID()
	for _, s := range spans[1:] {
		if s.SpanContext.TraceID() != traceID {
			t.Errorf("span %q has different trace ID: got %s, want %s",
				s.Name, s.SpanContext.TraceID(), traceID)
		}
	}
}

func TestExchange_DeniedSpanRecordsError(t *testing.T) {
	exporter := setupTestTracer()

	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), denyPolicy("not allowed"), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected error for denied exchange")
	}

	spans := exporter.GetSpans()

	// Find the root exchange span and check it recorded an error.
	var found bool
	for _, s := range spans {
		if s.Name == "exchange.Exchange" {
			found = true
			if len(s.Events) == 0 {
				t.Error("exchange.Exchange span should have error events")
			}
			break
		}
	}
	if !found {
		t.Error("exchange.Exchange span not found")
	}
}

// ── Mock types for secret delivery tests ─────────────────────────

type mockEncryptionKeyStore struct {
	key jwk.Key
	err error
}

func (m *mockEncryptionKeyStore) Register(_ context.Context, _ string, _ jwk.Key) error {
	return nil
}

func (m *mockEncryptionKeyStore) Get(_ context.Context, _ string) (jwk.Key, error) {
	return m.key, m.err
}

type mockSecretSource struct {
	name   string
	bundle *secrets.SecretBundle
	err    error
}

func (m *mockSecretSource) Name() string                  { return m.name }
func (m *mockSecretSource) Available(_ context.Context) bool { return true }
func (m *mockSecretSource) Fetch(_ context.Context, _ []secrets.SecretRef) (*secrets.SecretBundle, error) {
	return m.bundle, m.err
}

// ── Option function tests ────────────────────────────────────────

func TestWithIssuer_SetsIssuerInJWT(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithIssuer("custom-issuer"))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	if engine.issuer != "custom-issuer" {
		t.Errorf("issuer = %q, want custom-issuer", engine.issuer)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}
	iss, _ := token.Issuer()
	if iss != "custom-issuer" {
		t.Errorf("JWT issuer = %q, want custom-issuer", iss)
	}
}

func TestWithTTL_SetsTokenTTL(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithTTL(10*time.Minute))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	if engine.ttl != 10*time.Minute {
		t.Errorf("ttl = %v, want 10m", engine.ttl)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.ExpiresIn != 600 {
		t.Errorf("ExpiresIn = %d, want 600", resp.ExpiresIn)
	}
}

func TestWithExecutionScopeTTL_SetsExecutionTTL(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithExecutionScopeTTL(15*time.Second))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	if engine.executionTTL != 15*time.Second {
		t.Errorf("executionTTL = %v, want 15s", engine.executionTTL)
	}

	req := validRequest()
	req.ExecutionScope = &core.ExecutionScope{
		Method: "GET",
		URI:    "https://api.example.com/v1/data",
		Nonce:  "exec-ttl-test-nonce",
	}
	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.ExpiresIn != 15 {
		t.Errorf("ExpiresIn = %d, want 15", resp.ExpiresIn)
	}
}

func TestWithOnExchange_CallbackOnSuccess(t *testing.T) {
	var cbSubject, cbTarget, cbResult string
	var cbDuration time.Duration
	cb := func(subject, target, result string, dur time.Duration) {
		cbSubject = subject
		cbTarget = target
		cbResult = result
		cbDuration = dur
	}

	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithOnExchange(cb))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if cbSubject == "" {
		t.Error("callback subject should be set")
	}
	if cbTarget != "https://api.target.example.com" {
		t.Errorf("callback target = %q", cbTarget)
	}
	if cbResult != "ok" {
		t.Errorf("callback result = %q, want ok", cbResult)
	}
	if cbDuration == 0 {
		t.Error("callback duration should be non-zero")
	}
}

func TestWithSecretSource_SetsSecretSource(t *testing.T) {
	reg := secrets.NewRegistry()
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithSecretSource(reg))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	if engine.secretSource != reg {
		t.Error("secretSource not set")
	}
}

func TestWithEncryptionKeyStore_SetsKeyStore(t *testing.T) {
	ks := &mockEncryptionKeyStore{}
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithEncryptionKeyStore(ks))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	if engine.encryptionKeyStore != ks {
		t.Error("encryptionKeyStore not set")
	}
}

func TestWithOnSecretDelivery_SetsCallback(t *testing.T) {
	cb := func(source, result string, dur time.Duration) {}
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{}, WithOnSecretDelivery(cb))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	if engine.onSecretDelivery == nil {
		t.Error("onSecretDelivery not set")
	}
}

// ── Engine.Keyring accessor test ─────────────────────────────────

func TestEngine_Keyring_ReturnsKeyring(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	kr := engine.Keyring()
	if kr == nil {
		t.Fatal("Keyring() returned nil")
	}
	if kr.ActiveKid() != "starfly-dev-1" {
		t.Errorf("active kid = %q, want starfly-dev-1", kr.ActiveKid())
	}
}

// ── PublicKeySet fallback test ───────────────────────────────────

func TestPublicKeySet_FallbackNoKeyring(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, "fallback-key")
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256())
	_ = key.Set(jwk.KeyUsageKey, "sig")

	e := &Engine{signKey: key}

	set, err := e.PublicKeySet()
	if err != nil {
		t.Fatalf("PublicKeySet: %v", err)
	}
	if set.Len() != 1 {
		t.Errorf("set len = %d, want 1", set.Len())
	}
}

// ── Exchange error paths ─────────────────────────────────────────

func TestExchange_SigningKeyFailure(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatal(err)
	}
	engine.signKey = nil
	engine.keyring = nil

	_, err = engine.Exchange(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected error for nil signing key")
	}
	if !strings.Contains(err.Error(), "signing JWT") {
		t.Errorf("error = %q, expected to contain 'signing JWT'", err.Error())
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestNew_RandReaderFailure(t *testing.T) {
	orig := rand.Reader
	rand.Reader = failReader{}
	defer func() { rand.Reader = orig }()

	_, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err == nil {
		t.Fatal("expected error when rand.Reader fails")
	}
	if !strings.Contains(err.Error(), "generating dev signing key") {
		t.Errorf("error = %q, want containing 'generating dev signing key'", err.Error())
	}
}

func TestExchange_PolicyEngineError(t *testing.T) {
	policy := &mockPolicy{err: errors.New("OPA unavailable")}
	engine, err := New(goodIdentity(), policy, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if err == nil {
		t.Fatal("expected error for policy engine failure")
	}
	if !strings.Contains(err.Error(), "evaluating policy") {
		t.Errorf("error = %q, want containing 'evaluating policy'", err.Error())
	}
}

func TestExchange_DelegationDepthFromPolicy(t *testing.T) {
	policyClaims := map[string]interface{}{
		"delegation_depth": 3,
	}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var depth float64
	if err := token.Get("delegation_depth", &depth); err != nil {
		t.Fatalf("missing delegation_depth claim: %v", err)
	}
	if int(depth) != 3 {
		t.Errorf("delegation_depth = %v, want 3", depth)
	}
}

func TestExchange_RevokedSubject_NoReason(t *testing.T) {
	revIdx := &mockRevocation{
		entries: map[string]*core.RevocationEntry{
			"wimse://production.example.com/ns/default/sa/my-app": {
				SubjectID: "wimse://production.example.com/ns/default/sa/my-app",
			},
		},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor, WithRevocationChecker(revIdx))
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), validRequest())
	if !errors.Is(err, ErrSubjectRevoked) {
		t.Fatalf("expected ErrSubjectRevoked, got %v", err)
	}

	var found bool
	for _, ev := range auditor.events {
		if ev.Decision == "denied" && ev.Reason == "subject identity revoked" {
			found = true
		}
	}
	if !found {
		t.Error("expected denial audit with bare revocation reason")
	}
}

func TestExchange_Attestation_AllWorkloadFields(t *testing.T) {
	var capturedInput *core.PolicyInput
	capPolicy := &capturingPolicy{
		inner:    &mockPolicy{decision: &core.PolicyDecision{Allowed: true}},
		captured: &capturedInput,
	}

	engine, err := New(goodIdentity(), capPolicy, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	req.Attestation = &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
			Metadata: map[string]string{"region": "us-east-1"},
		},
		Workload: &core.ServerAttestWorkload{
			BinaryHash:  "sha256:abc123",
			Namespace:   "prod",
			PodName:     "my-pod-xyz",
			ImageDigest: "sha256:image123",
			NodeName:    "node-1",
		},
		Hardware: []*core.ServerAttestHardware{
			{Type: "tpm2"},
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
	attestCtx, ok := capturedInput.Context["attestation"].(map[string]interface{})
	if !ok {
		t.Fatal("attestation not in policy context")
	}
	wl, ok := attestCtx["workload"].(map[string]interface{})
	if !ok {
		t.Fatal("workload not in attestation context")
	}
	if wl["image_digest"] != "sha256:image123" {
		t.Errorf("image_digest = %v", wl["image_digest"])
	}
	if wl["node_name"] != "node-1" {
		t.Errorf("node_name = %v", wl["node_name"])
	}
	if wl["pod_name"] != "my-pod-xyz" {
		t.Errorf("pod_name = %v", wl["pod_name"])
	}
	platform, ok := attestCtx["platform"].(map[string]interface{})
	if !ok {
		t.Fatal("platform not in attestation context")
	}
	if platform["metadata"] == nil {
		t.Error("platform.metadata should be present")
	}
}

// ── deliverSecrets tests ─────────────────────────────────────────

func secretRefsDecision(refs []interface{}) *core.PolicyDecision {
	return &core.PolicyDecision{
		Allowed: true,
		Claims:  map[string]interface{}{"secret_refs": refs},
	}
}

func TestDeliverSecrets_NoSecretRefs(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	engine.secretSource = secrets.NewRegistry()

	decision := &core.PolicyDecision{Allowed: true, Claims: map[string]interface{}{}}
	result := engine.deliverSecrets(context.Background(), "workload-1", decision)
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDeliverSecrets_InvalidRefsType(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	engine.secretSource = secrets.NewRegistry()

	decision := &core.PolicyDecision{
		Allowed: true,
		Claims:  map[string]interface{}{"secret_refs": "not-a-slice"},
	}
	result := engine.deliverSecrets(context.Background(), "workload-1", decision)
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDeliverSecrets_EmptyRefsSlice(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	engine.secretSource = secrets.NewRegistry()

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{}))
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDeliverSecrets_NonMapRefsIgnored(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	engine.secretSource = secrets.NewRegistry()

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{"not-a-map", 42}))
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDeliverSecrets_IncompleteRefs(t *testing.T) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}
	engine.secretSource = secrets.NewRegistry()

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{
			map[string]interface{}{"source": "vault"},
			map[string]interface{}{"source": "vault", "path": "/secret"},
		}))
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDeliverSecrets_NoEncryptionKeyStore(t *testing.T) {
	reg := secrets.NewRegistry()
	var metricResult string
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{},
		WithSecretSource(reg),
		WithOnSecretDelivery(func(_, result string, _ time.Duration) {
			metricResult = result
		}),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{
			map[string]interface{}{"source": "vault", "path": "/secret/data", "key": "password"},
		}))
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
	if metricResult != "no_key" {
		t.Errorf("metric = %q, want no_key", metricResult)
	}
}

func TestDeliverSecrets_EncryptionKeyNotFound(t *testing.T) {
	reg := secrets.NewRegistry()
	ks := &mockEncryptionKeyStore{err: errors.New("not found")}
	var metricResult string
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{},
		WithSecretSource(reg),
		WithEncryptionKeyStore(ks),
		WithOnSecretDelivery(func(_, result string, _ time.Duration) {
			metricResult = result
		}),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{
			map[string]interface{}{"source": "vault", "path": "/secret/data", "key": "password"},
		}))
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
	if metricResult != "no_key" {
		t.Errorf("metric = %q, want no_key", metricResult)
	}
}

func TestDeliverSecrets_SourceFetchError(t *testing.T) {
	reg := secrets.NewRegistry()

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encKey, _ := jwk.Import(ecPriv.Public())
	ks := &mockEncryptionKeyStore{key: encKey}

	var metricResult string
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{},
		WithSecretSource(reg),
		WithEncryptionKeyStore(ks),
		WithOnSecretDelivery(func(_, result string, _ time.Duration) {
			metricResult = result
		}),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{
			map[string]interface{}{"source": "vault", "path": "/secret/data", "key": "password"},
		}))
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
	if metricResult != "source_unavailable" {
		t.Errorf("metric = %q, want source_unavailable", metricResult)
	}
}

func TestDeliverSecrets_EncryptError(t *testing.T) {
	source := &mockSecretSource{
		name:   "mock",
		bundle: &secrets.SecretBundle{Claims: map[string]string{"db_password": "s3cret"}},
	}
	reg := secrets.NewRegistry()
	reg.Register(source)

	// RSA key will fail with ECDH-ES+A256KW algorithm used by EncryptSecretBundle.
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey, _ := jwk.Import(rsaPriv.Public())
	ks := &mockEncryptionKeyStore{key: rsaKey}

	var metricResult string
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{},
		WithSecretSource(reg),
		WithEncryptionKeyStore(ks),
		WithOnSecretDelivery(func(_, result string, _ time.Duration) {
			metricResult = result
		}),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{
			map[string]interface{}{"source": "mock", "path": "/secret/data", "key": "password"},
		}))
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
	if metricResult != "encrypt_error" {
		t.Errorf("metric = %q, want encrypt_error", metricResult)
	}
}

func TestDeliverSecrets_HappyPath(t *testing.T) {
	source := &mockSecretSource{
		name:   "mock",
		bundle: &secrets.SecretBundle{Claims: map[string]string{"db_password": "s3cret"}},
	}
	reg := secrets.NewRegistry()
	reg.Register(source)

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encKey, _ := jwk.Import(ecPriv.Public())
	ks := &mockEncryptionKeyStore{key: encKey}

	var metricResult string
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{},
		WithSecretSource(reg),
		WithEncryptionKeyStore(ks),
		WithOnSecretDelivery(func(_, result string, _ time.Duration) {
			metricResult = result
		}),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{
			map[string]interface{}{"source": "mock", "path": "/secret/data", "key": "password", "alias": "db_password"},
		}))
	if result == "" {
		t.Error("expected non-empty encrypted secret")
	}
	if metricResult != "ok" {
		t.Errorf("metric = %q, want ok", metricResult)
	}
}

func TestDeliverSecrets_LargeBundleWarning(t *testing.T) {
	largeClaims := make(map[string]string)
	for i := 0; i < 100; i++ {
		largeClaims[fmt.Sprintf("key_%d", i)] = strings.Repeat("x", 50)
	}
	source := &mockSecretSource{
		name:   "mock",
		bundle: &secrets.SecretBundle{Claims: largeClaims},
	}
	reg := secrets.NewRegistry()
	reg.Register(source)

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encKey, _ := jwk.Import(ecPriv.Public())
	ks := &mockEncryptionKeyStore{key: encKey}

	var metricResult string
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{},
		WithSecretSource(reg),
		WithEncryptionKeyStore(ks),
		WithOnSecretDelivery(func(_, result string, _ time.Duration) {
			metricResult = result
		}),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	result := engine.deliverSecrets(context.Background(), "workload-1",
		secretRefsDecision([]interface{}{
			map[string]interface{}{"source": "mock", "path": "/secret/data", "key": "password"},
		}))
	if result == "" {
		t.Error("expected non-empty encrypted secret")
	}
	if metricResult != "ok" {
		t.Errorf("metric = %q, want ok", metricResult)
	}
}

func TestExchange_WithSecretDelivery(t *testing.T) {
	source := &mockSecretSource{
		name:   "mock",
		bundle: &secrets.SecretBundle{Claims: map[string]string{"db_password": "s3cret"}},
	}
	reg := secrets.NewRegistry()
	reg.Register(source)

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encKey, _ := jwk.Import(ecPriv.Public())
	ks := &mockEncryptionKeyStore{key: encKey}

	policyClaims := map[string]interface{}{
		"secret_refs": []interface{}{
			map[string]interface{}{"source": "mock", "path": "/secret/data", "key": "password"},
		},
	}
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), auditor,
		WithSecretSource(reg),
		WithEncryptionKeyStore(ks),
	)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	token, err := jwt.ParseInsecure([]byte(resp.AccessToken))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var secretsClaim string
	if err := token.Get("secrets", &secretsClaim); err != nil {
		t.Fatalf("missing secrets claim: %v", err)
	}
	if secretsClaim == "" {
		t.Error("secrets claim should not be empty")
	}

	var found bool
	for _, ev := range auditor.events {
		if ev.Action == "token_exchange" && ev.Decision == "allowed" {
			if ev.Metadata != nil && ev.Metadata["secret_delivery"] == "ok" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected audit event with secret_delivery=ok metadata")
	}
}
