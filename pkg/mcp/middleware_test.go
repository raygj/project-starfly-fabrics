package mcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/starfly-fabrics/starfly/pkg/audit"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── Test helpers ────────────────────────────────────────────────────

// mockJWKSResolver implements core.JWKSResolver for tests.
type mockJWKSResolver struct {
	key crypto.PublicKey
	err error
}

func (m *mockJWKSResolver) ResolveKey(_ context.Context, _ string, _ string) (crypto.PublicKey, error) {
	return m.key, m.err
}

func (m *mockJWKSResolver) Prefetch(_ context.Context, _ []string) error { return nil }
func (m *mockJWKSResolver) Stats() core.JWKSCacheStats                   { return core.JWKSCacheStats{} }

// mockRevocationIndex implements core.RevocationIndex for tests.
type mockRevocationIndex struct {
	entry *core.RevocationEntry
	err   error
}

func (m *mockRevocationIndex) IsRevoked(_ context.Context, _ string) (*core.RevocationEntry, error) {
	return m.entry, m.err
}
func (m *mockRevocationIndex) Revoke(_ context.Context, _ string, _ string, _ time.Time) error {
	return nil
}
func (m *mockRevocationIndex) Cleanup(_ context.Context) (int, error) { return 0, nil }
func (m *mockRevocationIndex) Hash() string                          { return "" }
func (m *mockRevocationIndex) Export() ([]byte, error)               { return nil, nil }
func (m *mockRevocationIndex) Import(_ []byte) error                 { return nil }

// mockPolicyEngine implements core.PolicyEngine for tests.
type mockPolicyEngine struct {
	decision *core.PolicyDecision
	err      error
}

func (m *mockPolicyEngine) Evaluate(_ context.Context, _ *core.PolicyInput) (*core.PolicyDecision, error) {
	return m.decision, m.err
}
func (m *mockPolicyEngine) LoadBundle(_ context.Context, _ string) error { return nil }

// testKeys generates an RSA key pair and returns the private key and JWK public key.
func testKeys(t *testing.T) (*rsa.PrivateKey, jwk.Key) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubJWK, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatalf("import public key to JWK: %v", err)
	}
	_ = pubJWK.Set(jwk.KeyIDKey, "test-kid-1")
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.RS256())
	return privKey, pubJWK
}

// signToken creates a signed JWT with the given claims.
func signToken(t *testing.T, privKey *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	builder := jwt.New()
	for k, v := range claims {
		if err := builder.Set(k, v); err != nil {
			t.Fatalf("set claim %q: %v", k, err)
		}
	}
	signed, err := jwt.Sign(builder, jwt.WithKey(jwa.RS256(), privKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// ── Tests ───────────────────────────────────────────────────────────

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{name: "valid bearer", header: "Bearer eyJhbGciOi...", want: "eyJhbGciOi..."},
		{name: "case insensitive", header: "bearer some.token", want: "some.token"},
		{name: "missing header", header: "", wantErr: true},
		{name: "wrong scheme", header: "Basic abc123", wantErr: true},
		{name: "no space", header: "Bearertoken", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			got, err := extractBearerToken(r)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("token = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractToolID(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		header string
		want   string
	}{
		{name: "from header", path: "/v1/mcp/call", header: "code-search", want: "code-search"},
		{name: "from path", path: "/v1/mcp/tools/code-search/call", want: "code-search"},
		{name: "header takes precedence", path: "/v1/mcp/tools/other/call", header: "preferred", want: "preferred"},
		{name: "no tool ID", path: "/v1/mcp/call", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tt.path, nil)
			if tt.header != "" {
				r.Header.Set("X-MCP-Tool-ID", tt.header)
			}
			got := extractToolID(r)
			if got != tt.want {
				t.Fatalf("toolID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		have     []string
		required []string
		wantErr  bool
	}{
		{name: "no requirements", have: nil, required: nil, wantErr: false},
		{name: "all present", have: []string{"read", "write"}, required: []string{"read"}, wantErr: false},
		{name: "exact match", have: []string{"read"}, required: []string{"read"}, wantErr: false},
		{name: "missing one", have: []string{"read"}, required: []string{"read", "write"}, wantErr: true},
		{name: "empty have", have: nil, required: []string{"read"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCapabilities(tt.have, tt.required)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBlastRadiusFits(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		max     string
		fits    bool
	}{
		{name: "wildcard max", token: "namespace:prod", max: "*", fits: true},
		{name: "scope wildcard", token: "namespace:dev", max: "namespace:*", fits: true},
		{name: "exact match", token: "db:readonly", max: "db:readonly", fits: true},
		{name: "scope mismatch", token: "namespace:prod", max: "namespace:dev", fits: false},
		{name: "type mismatch", token: "namespace:dev", max: "db:dev", fits: false},
		{name: "no colon exact", token: "global", max: "global", fits: true},
		{name: "no colon mismatch", token: "global", max: "local", fits: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := blastRadiusFits(tt.token, tt.max)
			if got != tt.fits {
				t.Fatalf("blastRadiusFits(%q, %q) = %v, want %v", tt.token, tt.max, got, tt.fits)
			}
		})
	}
}

func TestExtractTrustDomain(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"wimse://dev.local/ns/default/sa/agent", "dev.local"},
		{"spiffe://cluster.prod/workload/api", "cluster.prod"},
		{"https://example.com", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractTrustDomain(tt.uri)
		if got != tt.want {
			t.Errorf("extractTrustDomain(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

func TestVerifyToolCall_ValidToken(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:               "code-search",
		ResourceURI:          "https://mcp.example.com/tools/code-search",
		RequiredCapabilities: []string{"query-read"},
		MaxBlastRadius:       "workspace:*",
	})

	token := signToken(t, privKey, map[string]interface{}{
		"sub":          "wimse://dev.local/agent/test-agent",
		"iss":          "starfly-unit-1",
		"aud":          []string{"https://mcp.example.com/tools/code-search"},
		"exp":          time.Now().Add(5 * time.Minute),
		"iat":          time.Now(),
		"caps":         []interface{}{"query-read", "tool-execute"},
		"blast_radius": "workspace:dev",
	})

	cfg := Config{
		JWKSResolver: &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:     registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy: &mockPolicyEngine{
			decision: &core.PolicyDecision{Allowed: true},
		},
	}

	claims, err := VerifyToolCall(context.Background(), cfg, token, "code-search")
	if err != nil {
		t.Fatalf("VerifyToolCall: %v", err)
	}
	if claims.Subject != "wimse://dev.local/agent/test-agent" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Audience != "https://mcp.example.com/tools/code-search" {
		t.Errorf("Audience = %q", claims.Audience)
	}
	if len(claims.Capabilities) != 2 {
		t.Errorf("Capabilities = %v", claims.Capabilities)
	}
	if claims.BlastRadius != "workspace:dev" {
		t.Errorf("BlastRadius = %q", claims.BlastRadius)
	}
	if claims.ToolID != "code-search" {
		t.Errorf("ToolID = %q", claims.ToolID)
	}
}

func TestVerifyToolCall_AudienceMismatch(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "code-search",
		ResourceURI: "https://mcp.example.com/tools/code-search",
	})

	// Token has wrong audience — confused deputy attack.
	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/attacker",
		"iss": "starfly-unit-1",
		"aud": []string{"https://mcp.example.com/tools/OTHER-TOOL"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	cfg := Config{
		JWKSResolver: &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:     registry,
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "code-search")
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
	if !containsError(err, ErrAudienceMismatch) {
		t.Fatalf("error = %v, want ErrAudienceMismatch", err)
	}
}

func TestVerifyToolCall_TokenRevoked(t *testing.T) {
	privKey, _ := testKeys(t)

	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/revoked-agent",
		"iss": "starfly-unit-1",
		"aud": []string{"test"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	cfg := Config{
		JWKSResolver: &mockJWKSResolver{key: &privKey.PublicKey},
		RevocationChecker: &mockRevocationIndex{
			entry: &core.RevocationEntry{
				SubjectID: "wimse://dev.local/agent/revoked-agent",
				Reason:    "compromised",
			},
		},
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "")
	if err == nil {
		t.Fatal("expected revocation error")
	}
	if !containsError(err, ErrTokenRevoked) {
		t.Fatalf("error = %v, want ErrTokenRevoked", err)
	}
}

func TestVerifyToolCall_PolicyDenied(t *testing.T) {
	privKey, _ := testKeys(t)

	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/denied",
		"iss": "starfly-unit-1",
		"aud": []string{"test"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		RevocationChecker: &mockRevocationIndex{},
		Policy: &mockPolicyEngine{
			decision: &core.PolicyDecision{Allowed: false, Reason: "policy says no"},
		},
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "")
	if err == nil {
		t.Fatal("expected policy denied error")
	}
	if !containsError(err, ErrPolicyDenied) {
		t.Fatalf("error = %v, want ErrPolicyDenied", err)
	}
}

func TestVerifyToolCall_CapabilityDenied(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:               "admin-tool",
		ResourceURI:          "https://mcp.example.com/tools/admin",
		RequiredCapabilities: []string{"admin-write", "admin-delete"},
		MaxBlastRadius:       "*",
	})

	// Token only has query-read, not admin-write/delete.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":  "wimse://dev.local/agent/limited",
		"iss":  "starfly-unit-1",
		"aud":  []string{"https://mcp.example.com/tools/admin"},
		"exp":  time.Now().Add(5 * time.Minute),
		"iat":  time.Now(),
		"caps": []interface{}{"query-read"},
	})

	cfg := Config{
		JWKSResolver: &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:     registry,
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "admin-tool")
	if err == nil {
		t.Fatal("expected capability denied error")
	}
	if !containsError(err, ErrCapabilityDenied) {
		t.Fatalf("error = %v, want ErrCapabilityDenied", err)
	}
}

func TestVerifyToolCall_BlastRadiusExceeded(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:         "scoped-tool",
		ResourceURI:    "https://mcp.example.com/tools/scoped",
		MaxBlastRadius: "namespace:dev",
	})

	// Token has broader blast radius than tool allows.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":          "wimse://dev.local/agent/broad",
		"iss":          "starfly-unit-1",
		"aud":          []string{"https://mcp.example.com/tools/scoped"},
		"exp":          time.Now().Add(5 * time.Minute),
		"iat":          time.Now(),
		"blast_radius": "namespace:prod",
	})

	cfg := Config{
		JWKSResolver: &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:     registry,
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "scoped-tool")
	if err == nil {
		t.Fatal("expected blast radius exceeded error")
	}
	if !containsError(err, ErrBlastRadiusExceeded) {
		t.Fatalf("error = %v, want ErrBlastRadiusExceeded", err)
	}
}

func TestVerifyToolCall_ToolNotRegistered(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry() // empty

	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/test",
		"iss": "starfly-unit-1",
		"aud": []string{"test"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	cfg := Config{
		JWKSResolver: &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:     registry,
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "unknown-tool")
	if err == nil {
		t.Fatal("expected tool not registered error")
	}
	if !containsError(err, ErrToolNotRegistered) {
		t.Fatalf("error = %v, want ErrToolNotRegistered", err)
	}
}

func TestMiddleware_Integration(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:               "test-tool",
		ResourceURI:          "https://mcp.example.com/tools/test",
		RequiredCapabilities: []string{"read"},
		MaxBlastRadius:       "workspace:*",
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	// Handler that checks claims are in context.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			t.Error("expected claims in context")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(cfg)(inner)

	token := signToken(t, privKey, map[string]interface{}{
		"sub":          "wimse://dev.local/agent/test",
		"iss":          "starfly-unit-1",
		"aud":          []string{"https://mcp.example.com/tools/test"},
		"exp":          time.Now().Add(5 * time.Minute),
		"iat":          time.Now(),
		"caps":         []interface{}{"read", "write"},
		"blast_radius": "workspace:dev",
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/test-tool/call", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestMiddleware_MissingToken(t *testing.T) {
	cfg := Config{}
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestClaimsFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	if got := ClaimsFromContext(ctx); got != nil {
		t.Fatal("expected nil claims from empty context")
	}
}

func TestInferAlgorithm(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	alg := inferAlgorithm(&privKey.PublicKey)
	if alg != jwa.RS256() {
		t.Fatalf("alg = %v, want RS256", alg)
	}
}

// ── Execution Binding Tests ─────────────────────────────────────────

func TestVerifyToolCall_ExecBindingRequired(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:            "strict-tool",
		ResourceURI:       "https://mcp.example.com/tools/strict",
		RequiresExecution: true,
	})

	// Token WITHOUT execution scope claims — should be rejected.
	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/test",
		"iss": "starfly-unit-1",
		"aud": []string{"https://mcp.example.com/tools/strict"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "strict-tool")
	if err == nil {
		t.Fatal("expected execution binding required error")
	}
	if !containsError(err, ErrExecBindingRequired) {
		t.Fatalf("error = %v, want ErrExecBindingRequired", err)
	}
}

func TestVerifyToolCall_ExecOpMismatch(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:            "sql-query",
		ResourceURI:       "https://mcp.example.com/tools/sql-query",
		AllowedOperations: []string{"query", "read"},
	})

	// Token with exec_act="delete" — not in allowed set.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/sql-query"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"exec_act": "delete",
		"inp_hash": "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "sql-query")
	if err == nil {
		t.Fatal("expected exec_act mismatch error")
	}
	if !containsError(err, ErrExecOpMismatch) {
		t.Fatalf("error = %v, want ErrExecOpMismatch", err)
	}
}

func TestVerifyToolCall_ExecOpAllowed(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:            "sql-query",
		ResourceURI:       "https://mcp.example.com/tools/sql-query",
		AllowedOperations: []string{"query", "read"},
	})

	// Token with exec_act="query" — in allowed set.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/sql-query"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"exec_act": "query",
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "sql-query")
	if err != nil {
		t.Fatalf("VerifyToolCall: %v", err)
	}
}

func TestVerifyToolCall_ExecPayloadMismatch(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "data-tool",
		ResourceURI: "https://mcp.example.com/tools/data",
	})

	// Compute hash of the "authorized" body, but send a different body.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/data"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"inp_hash": computeInputHash([]byte(`{"query":"SELECT 1"}`)),
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	// Tampered body — different from what was hashed.
	opts := &VerifyOptions{RequestBody: []byte(`{"query":"DROP TABLE users"}`)}
	_, err := VerifyToolCall(context.Background(), cfg, token, "data-tool", opts)
	if err == nil {
		t.Fatal("expected payload mismatch error")
	}
	if !containsError(err, ErrExecPayloadMismatch) {
		t.Fatalf("error = %v, want ErrExecPayloadMismatch", err)
	}
}

func TestVerifyToolCall_ExecPayloadMatch(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "data-tool",
		ResourceURI: "https://mcp.example.com/tools/data",
	})

	body := []byte(`{"query":"SELECT 1"}`)
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/data"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"inp_hash": computeInputHash(body),
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	// Same body — hash should match.
	opts := &VerifyOptions{RequestBody: body}
	_, err := VerifyToolCall(context.Background(), cfg, token, "data-tool", opts)
	if err != nil {
		t.Fatalf("VerifyToolCall: %v", err)
	}
}

func TestVerifyToolCall_ExecTargetMismatch(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:         "sql-query",
		ResourceURI:    "https://mcp.example.com/tools/sql-query",
		AllowedTargets: []string{"postgresql://analytics.prod:5432/metrics"},
	})

	// Token targets a different database.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":    "wimse://dev.local/agent/test",
		"iss":    "starfly-unit-1",
		"aud":    []string{"https://mcp.example.com/tools/sql-query"},
		"exp":    time.Now().Add(5 * time.Minute),
		"iat":    time.Now(),
		"target": "postgresql://production.internal:5432/users",
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "sql-query")
	if err == nil {
		t.Fatal("expected target mismatch error")
	}
	if !containsError(err, ErrExecTargetMismatch) {
		t.Fatalf("error = %v, want ErrExecTargetMismatch", err)
	}
}

func TestVerifyToolCall_ExecPayloadMissing(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:            "strict-tool",
		ResourceURI:       "https://mcp.example.com/tools/strict",
		RequiresExecution: true,
	})

	// Token has execution scope (exec_act) but no inp_hash — tool requires it.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/strict"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"exec_act": "query",
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	_, err := VerifyToolCall(context.Background(), cfg, token, "strict-tool")
	if err == nil {
		t.Fatal("expected payload missing error")
	}
	if !containsError(err, ErrExecPayloadMissing) {
		t.Fatalf("error = %v, want ErrExecPayloadMissing", err)
	}
}

func TestExtractClaims_ExecutionScope(t *testing.T) {
	privKey, _ := testKeys(t)

	// Token with ECT-aligned flat claims (draft-nennemann-wimse-ect-00).
	token := signToken(t, privKey, map[string]interface{}{
		"sub":       "wimse://dev.local/agent/test",
		"iss":       "starfly-unit-1",
		"aud":       []string{"https://mcp.example.com/tools/sql-query"},
		"exp":       time.Now().Add(5 * time.Minute),
		"iat":       time.Now(),
		"htm":       "POST",
		"htu":       "https://mcp.example.com/tools/sql-query/call",
		"exec_act":  "query",
		"inp_hash":  "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
		"out_hash":  "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564",
		"target":    "postgresql://analytics.prod:5432/metrics",
		"wid":       "a0b1c2d3-e4f5-6789-abcd-ef0123456789",
		"nonce":     "test-nonce-001",
	})

	parsed, err := jwt.Parse([]byte(token),
		jwt.WithKey(jwa.RS256(), &privKey.PublicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	claims := extractClaims(parsed)

	if claims.Execution == nil {
		t.Fatal("expected Execution to be set")
	}
	ex := claims.Execution

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"Method", ex.Method, "POST"},
		{"URI", ex.URI, "https://mcp.example.com/tools/sql-query/call"},
		{"ExecAct", ex.ExecAct, "query"},
		{"InputHash", ex.InputHash, "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"},
		{"OutputHash", ex.OutputHash, "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564"},
		{"Target", ex.Target, "postgresql://analytics.prod:5432/metrics"},
		{"WorkflowID", ex.WorkflowID, "a0b1c2d3-e4f5-6789-abcd-ef0123456789"},
		{"Nonce", ex.Nonce, "test-nonce-001"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestExtractClaims_LegacyPayloadHash(t *testing.T) {
	privKey, _ := testKeys(t)

	// Token with deprecated payload_hash (no inp_hash) — backward compat.
	token := signToken(t, privKey, map[string]interface{}{
		"sub":          "wimse://dev.local/agent/legacy",
		"iss":          "starfly-unit-1",
		"aud":          []string{"test"},
		"exp":          time.Now().Add(5 * time.Minute),
		"iat":          time.Now(),
		"htm":          "POST",
		"payload_hash": "sha256-legacy-hash",
	})

	parsed, err := jwt.Parse([]byte(token),
		jwt.WithKey(jwa.RS256(), &privKey.PublicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	claims := extractClaims(parsed)

	if claims.Execution == nil {
		t.Fatal("expected Execution to be set for legacy token")
	}
	if claims.Execution.InputHash != "sha256-legacy-hash" {
		t.Errorf("InputHash = %q, want %q", claims.Execution.InputHash, "sha256-legacy-hash")
	}
	if claims.Execution.PayloadHash != "sha256-legacy-hash" {
		t.Errorf("PayloadHash = %q, want %q", claims.Execution.PayloadHash, "sha256-legacy-hash")
	}
}

func TestExtractClaims_NoExecutionScope(t *testing.T) {
	privKey, _ := testKeys(t)

	// Token with no execution claims — should have nil Execution.
	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/plain",
		"iss": "starfly-unit-1",
		"aud": []string{"test"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	parsed, err := jwt.Parse([]byte(token),
		jwt.WithKey(jwa.RS256(), &privKey.PublicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	claims := extractClaims(parsed)

	if claims.Execution != nil {
		t.Errorf("expected nil Execution for non-execution-scoped token, got %+v", claims.Execution)
	}
}

// ── Coverage gap tests ──────────────────────────────────────────────

func TestInferAlgorithm_AllKeyTypes(t *testing.T) {
	// RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if got := inferAlgorithm(&rsaKey.PublicKey); got != jwa.RS256() {
		t.Errorf("RSA: got %v, want RS256", got)
	}

	// ECDSA
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	if got := inferAlgorithm(&ecKey.PublicKey); got != jwa.ES256() {
		t.Errorf("ECDSA: got %v, want ES256", got)
	}

	// EdDSA
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate EdDSA key: %v", err)
	}
	if got := inferAlgorithm(edPub); got != jwa.EdDSA() {
		t.Errorf("EdDSA: got %v, want EdDSA", got)
	}
}

func TestInferSignerAlgorithm_AllKeyTypes(t *testing.T) {
	// RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if got := inferSignerAlgorithm(rsaKey); got != jwa.RS256() {
		t.Errorf("RSA: got %v, want RS256", got)
	}

	// ECDSA
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	if got := inferSignerAlgorithm(ecKey); got != jwa.ES256() {
		t.Errorf("ECDSA: got %v, want ES256", got)
	}

	// EdDSA
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate EdDSA key: %v", err)
	}
	if got := inferSignerAlgorithm(edPriv); got != jwa.EdDSA() {
		t.Errorf("EdDSA: got %v, want EdDSA", got)
	}
}

func TestSubjectOrEmpty(t *testing.T) {
	var nilClaims *VerifiedClaims
	if got := nilClaims.subjectOrEmpty(); got != "" {
		t.Errorf("nil claims: got %q, want empty", got)
	}

	claims := &VerifiedClaims{Subject: "wimse://test/agent"}
	if got := claims.subjectOrEmpty(); got != "wimse://test/agent" {
		t.Errorf("got %q, want %q", got, "wimse://test/agent")
	}
}

func TestMiddleware_RevokedErrorMapping(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "test-tool",
		ResourceURI: "https://mcp.example.com/tools/test",
	})

	cfg := Config{
		JWKSResolver: &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:     registry,
		RevocationChecker: &mockRevocationIndex{
			entry: &core.RevocationEntry{
				SubjectID: "wimse://dev.local/agent/revoked",
				Reason:    "compromised",
			},
		},
		Policy: &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/revoked",
		"iss": "starfly-unit-1",
		"aud": []string{"https://mcp.example.com/tools/test"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(cfg)(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/test-tool/call", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "token_revoked") {
		t.Errorf("body should contain token_revoked, got: %s", w.Body.String())
	}
}

func TestMiddleware_ExecutionBindingErrorMapping(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:            "strict-tool",
		ResourceURI:       "https://mcp.example.com/tools/strict",
		RequiresExecution: true,
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
	}

	// Token without execution scope → should get execution_binding_failed.
	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/test",
		"iss": "starfly-unit-1",
		"aud": []string{"https://mcp.example.com/tools/strict"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(cfg)(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/strict-tool/call", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "execution_binding_failed") {
		t.Errorf("body should contain execution_binding_failed, got: %s", w.Body.String())
	}
}

func TestMiddleware_FullECTPipeline(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "data-tool",
		ResourceURI: "https://mcp.example.com/tools/data",
	})

	wt := NewWorkflowTracker()
	ledger := audit.NewECTLedger()

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
		SigningKey:         privKey,
		SigningKeyID:       "test-kid-1",
		Issuer:             "wimse://test.local",
		WorkflowTracker:    wt,
		ECTLedger:          ledger,
		Auditor:            &mockAuditor{},
		UnitID:             "unit-test",
	}

	body := []byte(`{"query":"SELECT 1"}`)
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/test",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/data"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"exec_act": "query",
		"inp_hash": computeInputHash(body),
		"wid":      "wf-test-001",
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	})

	handler := Middleware(cfg)(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/data-tool/call",
		strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify ECT header present.
	if w.Header().Get("Execution-Context") == "" {
		t.Error("expected Execution-Context header")
	}

	// Verify ledger got the entry.
	if ledger.Len() != 1 {
		t.Errorf("ledger length = %d, want 1", ledger.Len())
	}

	// Verify workflow tracker recorded the task.
	if wt.WorkflowSize("wf-test-001") != 1 {
		t.Errorf("workflow size = %d, want 1", wt.WorkflowSize("wf-test-001"))
	}
}

func TestMiddleware_AudienceMismatchErrorMapping(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "tool-a",
		ResourceURI: "https://mcp.example.com/tools/a",
	})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
	}

	// Wrong audience.
	token := signToken(t, privKey, map[string]interface{}{
		"sub": "wimse://dev.local/agent/test",
		"iss": "starfly-unit-1",
		"aud": []string{"https://mcp.example.com/tools/WRONG"},
		"exp": time.Now().Add(5 * time.Minute),
		"iat": time.Now(),
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(cfg)(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/tool-a/call", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "audience_mismatch") {
		t.Errorf("body should contain audience_mismatch, got: %s", w.Body.String())
	}
}

func TestExtractParentECTJTIs(t *testing.T) {
	privKey, _ := testKeys(t)

	// Create two parent ECTs.
	parent1Claims := map[string]interface{}{
		"iss": "wimse://test/tool-a",
		"aud": []string{"wimse://test/agent"},
		"jti": "parent-jti-001",
		"iat": time.Now(),
		"exp": time.Now().Add(5 * time.Minute),
	}
	parent2Claims := map[string]interface{}{
		"iss": "wimse://test/tool-b",
		"aud": []string{"wimse://test/agent"},
		"jti": "parent-jti-002",
		"iat": time.Now(),
		"exp": time.Now().Add(5 * time.Minute),
	}

	ect1 := signToken(t, privKey, parent1Claims)
	ect2 := signToken(t, privKey, parent2Claims)

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/test/call", nil)
	req.Header.Add("Execution-Context", ect1)
	req.Header.Add("Execution-Context", ect2)

	jtis := extractParentECTJTIs(req)
	if len(jtis) != 2 {
		t.Fatalf("got %d JTIs, want 2", len(jtis))
	}
	if jtis[0] != "parent-jti-001" || jtis[1] != "parent-jti-002" {
		t.Errorf("jtis = %v", jtis)
	}
}

func TestExtractParentECTJTIs_NoHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	jtis := extractParentECTJTIs(req)
	if jtis != nil {
		t.Errorf("expected nil for no headers, got %v", jtis)
	}
}

func TestExtractParentECTJTIs_InvalidJWT(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Add("Execution-Context", "not-a-valid-jwt")

	jtis := extractParentECTJTIs(req)
	if len(jtis) != 0 {
		t.Errorf("expected empty for invalid JWT, got %v", jtis)
	}
}

func TestMiddleware_InboundECTParentLinkage(t *testing.T) {
	privKey, _ := testKeys(t)

	registry := NewRegistry()
	_ = registry.Register(&ToolEntry{
		ToolID:      "child-tool",
		ResourceURI: "https://mcp.example.com/tools/child",
	})

	wt := NewWorkflowTracker()
	ledger := audit.NewECTLedger()

	// Pre-record the parent task in the workflow tracker so DAG validation passes.
	_ = wt.RecordTask("wf-chain", "parent-jti-abc", time.Now(), []string{})

	cfg := Config{
		JWKSResolver:      &mockJWKSResolver{key: &privKey.PublicKey},
		Registry:          registry,
		RevocationChecker: &mockRevocationIndex{},
		Policy:            &mockPolicyEngine{decision: &core.PolicyDecision{Allowed: true}},
		SigningKey:         privKey,
		SigningKeyID:       "test-kid",
		Issuer:             "wimse://test.local",
		WorkflowTracker:    wt,
		ECTLedger:          ledger,
	}

	body := []byte(`{"data":"test"}`)
	token := signToken(t, privKey, map[string]interface{}{
		"sub":      "wimse://dev.local/agent/child",
		"iss":      "starfly-unit-1",
		"aud":      []string{"https://mcp.example.com/tools/child"},
		"exp":      time.Now().Add(5 * time.Minute),
		"iat":      time.Now(),
		"exec_act": "process",
		"inp_hash": computeInputHash(body),
		"wid":      "wf-chain",
	})

	// Create a parent ECT to include as Execution-Context header.
	parentECT := signToken(t, privKey, map[string]interface{}{
		"iss": "wimse://test/tool-parent",
		"aud": []string{"wimse://dev.local/agent/child"},
		"jti": "parent-jti-abc",
		"iat": time.Now(),
		"exp": time.Now().Add(5 * time.Minute),
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	handler := Middleware(cfg)(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/child-tool/call",
		strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Add("Execution-Context", parentECT)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify ECT response header contains par reference.
	ectHeader := w.Header().Get("Execution-Context")
	if ectHeader == "" {
		t.Fatal("expected Execution-Context response header")
	}

	parsed, err := jwt.Parse([]byte(ectHeader),
		jwt.WithKey(jwa.RS256(), &privKey.PublicKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		t.Fatalf("parse response ECT: %v", err)
	}

	var par []interface{}
	if err := parsed.Get("par", &par); err != nil {
		t.Fatalf("get par: %v", err)
	}
	if len(par) != 1 || par[0] != "parent-jti-abc" {
		t.Errorf("par = %v, want [parent-jti-abc]", par)
	}
}

// mockAuditor implements core.Auditor for tests.
type mockAuditor struct {
	events []*core.AuditEvent
}

func (m *mockAuditor) Log(_ context.Context, event *core.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

// containsError checks if err's message contains target's message.
func containsError(err, target error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	targetMsg := target.Error()
	if len(targetMsg) == 0 {
		return false
	}
	for i := 0; i <= len(errMsg)-len(targetMsg); i++ {
		if errMsg[i:i+len(targetMsg)] == targetMsg {
			return true
		}
	}
	return false
}
