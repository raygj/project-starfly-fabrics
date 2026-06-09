package oauth2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"go.opentelemetry.io/otel"
)

// mintAccessToken mints a JWT access token with the given claims.
func mintAccessToken(t *testing.T, sub, clientID, issuer, scope string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkKey, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	builder := jwt.NewBuilder().
		Issuer(issuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())

	if sub != "" {
		builder = builder.Subject(sub)
	}

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	if clientID != "" {
		if err := tok.Set("client_id", clientID); err != nil {
			t.Fatal(err)
		}
	}
	if scope != "" {
		if err := tok.Set("scope", scope); err != nil {
			t.Fatal(err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// mintSignedAccessToken mints a JWT access token signed with the given key, including a key ID.
func mintSignedAccessToken(t *testing.T, sub, clientID, issuer, scope string, signingKey jwk.Key) string {
	t.Helper()
	builder := jwt.NewBuilder().
		Issuer(issuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())

	if sub != "" {
		builder = builder.Subject(sub)
	}

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	if clientID != "" {
		if err := tok.Set("client_id", clientID); err != nil {
			t.Fatal(err)
		}
	}
	if scope != "" {
		if err := tok.Set("scope", scope); err != nil {
			t.Fatal(err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// introspectionServer creates an httptest server that validates Basic auth
// and returns the given IntrospectionResponse as JSON.
func introspectionServer(t *testing.T, response IntrospectionResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Basic auth
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-client" || pass != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify token parameter is present
		if r.FormValue("token") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encoding introspection response: %v", err)
		}
	}))
}

func TestDevMode_JWT(t *testing.T) {
	token := mintAccessToken(t, "svc-account-1", "my-client", "https://auth.example.com", "read write")

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), token, "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// client_id is preferred over sub for the principal
	if identity.ID != "wimse://dev.local/oauth2/my-client" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://dev.local/oauth2/my-client")
	}
	if identity.TrustDomain != "dev.local" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "dev.local")
	}
	if identity.Attestation.Method != "oauth2" {
		t.Errorf("attestation method = %q, want oauth2", identity.Attestation.Method)
	}
	if identity.Claims["issuer"] != "https://auth.example.com" {
		t.Errorf("issuer claim = %v, want https://auth.example.com", identity.Claims["issuer"])
	}
	if identity.Claims["client_id"] != "my-client" {
		t.Errorf("client_id claim = %v, want my-client", identity.Claims["client_id"])
	}
	if identity.Claims["scope"] != "read write" {
		t.Errorf("scope claim = %v, want 'read write'", identity.Claims["scope"])
	}
	if identity.Claims["token_type"] != "jwt" {
		t.Errorf("token_type claim = %v, want jwt", identity.Claims["token_type"])
	}
	if identity.Claims["dev_mode"] != true {
		t.Error("missing dev_mode claim")
	}
}

func TestDevMode_Opaque(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), "opaque-token-abc12345xyz", "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.ID != "wimse://dev.local/oauth2/opaque-token" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://dev.local/oauth2/opaque-token")
	}
	if identity.TrustDomain != "dev.local" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "dev.local")
	}
	if identity.Attestation.Method != "oauth2" {
		t.Errorf("attestation method = %q, want oauth2", identity.Attestation.Method)
	}
	if identity.Claims["token_type"] != "opaque" {
		t.Errorf("token_type claim = %v, want opaque", identity.Claims["token_type"])
	}
	if identity.Claims["key_prefix"] != "opaque-t" {
		t.Errorf("key_prefix claim = %v, want opaque-t", identity.Claims["key_prefix"])
	}
	if identity.Claims["dev_mode"] != true {
		t.Error("missing dev_mode claim")
	}
}

func TestProdMode_JWT_HappyPath(t *testing.T) {
	// 1. Generate ECDSA P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Create JWK from private key
	signingKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	// 3. Mint OAuth2 JWT access token
	token := mintSignedAccessToken(t, "svc-account-1", "my-client", "https://auth.example.com", "read", signingKey)

	// 4. Create httptest server serving public key as JWKS
	pubKey, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	jwks := jwk.NewSet()
	if err := jwks.AddKey(pubKey); err != nil {
		t.Fatal(err)
	}
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	// 5. Create Provider with trust domain
	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: srv.URL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// 6. Validate
	identity, err := p.ValidateWorkload(context.Background(), token, "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oauth2/my-client" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oauth2/my-client")
	}
	if identity.Attestation.Method != "oauth2" {
		t.Errorf("attestation method = %q, want %q", identity.Attestation.Method, "oauth2")
	}
	if identity.Claims["token_type"] != "jwt" {
		t.Errorf("token_type claim = %v, want jwt", identity.Claims["token_type"])
	}
}

func TestProdMode_Opaque_HappyPath(t *testing.T) {
	issuer := "https://auth.example.com"
	srv := introspectionServer(t, IntrospectionResponse{
		Active:   true,
		Sub:      "user-123",
		ClientID: "service-abc",
		Scope:    "read write",
		Issuer:   issuer,
	})
	defer srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), "opaque-token-value", "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oauth2/service-abc" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oauth2/service-abc")
	}
	if identity.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "example.com")
	}
	if identity.Claims["token_type"] != "opaque" {
		t.Errorf("token_type claim = %v, want opaque", identity.Claims["token_type"])
	}
	if identity.Claims["client_id"] != "service-abc" {
		t.Errorf("client_id claim = %v, want service-abc", identity.Claims["client_id"])
	}
	if identity.Claims["scope"] != "read write" {
		t.Errorf("scope claim = %v, want 'read write'", identity.Claims["scope"])
	}
}

func TestProdMode_Opaque_Inactive(t *testing.T) {
	issuer := "https://auth.example.com"
	srv := introspectionServer(t, IntrospectionResponse{
		Active: false,
	})
	defer srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "expired-token", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "token is not active") {
		t.Fatalf("error = %q, want containing 'token is not active'", err.Error())
	}
}

func TestProdMode_Opaque_AuthFailure(t *testing.T) {
	issuer := "https://auth.example.com"
	// Server that always returns 401 (bad credentials)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "wrong-client",
			ClientSecret: "wrong-secret",
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "some-token", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error = %q, want containing '401'", err.Error())
	}
}

func TestWrongCredType(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "anything", "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported credential type") {
		t.Fatalf("error = %q, want containing 'unsupported credential type'", err.Error())
	}
}

func TestEmptyCredential(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "empty credential") {
		t.Fatalf("error = %q, want containing 'empty credential'", err.Error())
	}
}

func TestJWT_UnknownIssuer(t *testing.T) {
	token := mintAccessToken(t, "user-1", "client-1", "https://unknown-issuer.com", "")

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: "https://example.com/jwks"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), token, "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown OAuth2 issuer") {
		t.Fatalf("error = %q, want containing 'unknown OAuth2 issuer'", err.Error())
	}
}

func TestInterfaceAssertion(t *testing.T) {
	var _ core.IdentityProvider = (*Provider)(nil)
}

// mockJWKSResolver returns a fixed public key for any ResolveKey call.
type mockJWKSResolver struct {
	pubKey crypto.PublicKey
}

func (m *mockJWKSResolver) ResolveKey(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return m.pubKey, nil
}

func (m *mockJWKSResolver) Prefetch(_ context.Context, _ []string) error { return nil }

func (m *mockJWKSResolver) Stats() core.JWKSCacheStats {
	return core.JWKSCacheStats{}
}

func TestProdMode_JWT_WithJWKSResolver(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "resolver-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	token := mintSignedAccessToken(t, "svc-account-1", "my-client", "https://auth.example.com", "read", signingKey)

	resolver := &mockJWKSResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: "https://example.com/jwks"},
		}),
		WithJWKSResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), token, "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oauth2/my-client" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oauth2/my-client")
	}
}

func TestJWT_MissingIssClaim(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkKey, err := jwk.Import(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	// Build JWT without iss claim
	builder := jwt.NewBuilder().
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Subject("user-1")
	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: "https://example.com/jwks"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), string(signed), "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing iss claim") {
		t.Fatalf("error = %q, want containing 'missing iss claim'", err.Error())
	}
}

func TestJWT_MissingBothSubAndClientID(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	token := mintSignedAccessToken(t, "", "", "https://auth.example.com", "", signingKey)

	pubKey, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.KeyIDKey, "key-1"); err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	jwks := jwk.NewSet()
	if err := jwks.AddKey(pubKey); err != nil {
		t.Fatal(err)
	}
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: srv.URL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), token, "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing both sub and client_id") {
		t.Fatalf("error = %q, want containing 'missing both sub and client_id'", err.Error())
	}
}

func TestJWT_SubUsedAsPrincipalWhenNoClientID(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	token := mintSignedAccessToken(t, "svc-account-1", "", "https://auth.example.com", "", signingKey)

	pubKey, err := jwk.Import(privKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.KeyIDKey, "key-1"); err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	jwks := jwk.NewSet()
	if err := jwks.AddKey(pubKey); err != nil {
		t.Fatal(err)
	}
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: srv.URL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), token, "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oauth2/svc-account-1" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oauth2/svc-account-1")
	}
}

func TestOpaque_NoIntrospectionEndpoints(t *testing.T) {
	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "opaque-token-xyz", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no introspection endpoints configured") {
		t.Fatalf("error = %q, want containing 'no introspection endpoints configured'", err.Error())
	}
}

func TestOpaque_MultipleIntrospectionEndpoints(t *testing.T) {
	issuer1 := "https://auth1.example.com"
	issuer2 := "https://auth2.example.com"
	srv1 := introspectionServer(t, IntrospectionResponse{Active: true, Sub: "user-1", Issuer: issuer1})
	srv2 := introspectionServer(t, IntrospectionResponse{Active: true, Sub: "user-2", Issuer: issuer2})
	defer srv1.Close()
	defer srv2.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer1},
			{Name: "example.com", Enabled: true, Issuer: issuer2},
		}),
		WithIntrospection(issuer1, srv1.URL, ClientCredentials{ClientID: "test-client", ClientSecret: "test-secret"}),
		WithIntrospection(issuer2, srv2.URL, ClientCredentials{ClientID: "test-client", ClientSecret: "test-secret"}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "opaque-token", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "cannot determine issuer") {
		t.Fatalf("error = %q, want containing 'cannot determine issuer'", err.Error())
	}
}

func TestOpaque_IntrospectionNoSubNoClientID_FallsBackToUnknown(t *testing.T) {
	issuer := "https://auth.example.com"
	srv := introspectionServer(t, IntrospectionResponse{
		Active:  true,
		Sub:     "",
		Issuer:  issuer,
		Scope:   "read",
	})
	defer srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), "opaque-token", "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oauth2/unknown" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oauth2/unknown")
	}
}

func TestOpaque_UnknownIssuerFromIntrospection(t *testing.T) {
	issuer := "https://auth.example.com"
	unknownIssuer := "https://unknown-issuer.com"
	srv := introspectionServer(t, IntrospectionResponse{
		Active:  true,
		Sub:     "user-1",
		Issuer:  unknownIssuer,
	})
	defer srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "opaque-token", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown OAuth2 issuer from introspection") {
		t.Fatalf("error = %q, want containing 'unknown OAuth2 issuer from introspection'", err.Error())
	}
}

func TestJWT_NoJWKSURLAndNoResolver(t *testing.T) {
	token := mintAccessToken(t, "user-1", "client-1", "https://auth.example.com", "")

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), token, "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no JWKS URL or resolver") {
		t.Fatalf("error = %q, want containing 'no JWKS URL or resolver'", err.Error())
	}
}

func TestWithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	p, err := NewProvider(WithHTTPClient(customClient))
	if err != nil {
		t.Fatal(err)
	}
	if p.httpClient != customClient {
		t.Error("expected custom HTTP client to be set")
	}
}

func TestDevMode_Opaque_ShortToken(t *testing.T) {
	p, _ := NewProvider(WithDevMode(true))
	identity, err := p.ValidateWorkload(context.Background(), "short", "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["key_prefix"] != "short" {
		t.Errorf("key_prefix = %v, want 'short'", identity.Claims["key_prefix"])
	}
}

func TestDevMode_JWT_SubAsPrincipal(t *testing.T) {
	token := mintAccessToken(t, "svc-only-sub", "", "https://auth.example.com", "")
	p, _ := NewProvider(WithDevMode(true))
	identity, err := p.ValidateWorkload(context.Background(), token, "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://dev.local/oauth2/svc-only-sub" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://dev.local/oauth2/svc-only-sub")
	}
}

func TestProdMode_JWT_JWKSFetchError(t *testing.T) {
	token := mintAccessToken(t, "user-1", "client-1", "https://auth.example.com", "")
	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: "http://127.0.0.1:1/bad-jwks"},
		}),
	)
	_, err := p.ValidateWorkload(context.Background(), token, "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "fetching JWKS") {
		t.Fatalf("error = %q, want containing 'fetching JWKS'", err.Error())
	}
}

func TestProdMode_JWT_JWKSFetchOK_ValidationFails(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkSigning, _ := jwk.Import(signingKey)
	_ = jwkSigning.Set(jwk.KeyIDKey, "kid-1")
	_ = jwkSigning.Set(jwk.AlgorithmKey, jwa.ES256())
	token := mintSignedAccessToken(t, "user-1", "client-1", "https://auth.example.com", "read", jwkSigning)

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubJWK, _ := jwk.Import(wrongKey.Public())
	_ = pubJWK.Set(jwk.KeyIDKey, "kid-1")
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.ES256())
	jwks := jwk.NewSet()
	_ = jwks.AddKey(pubJWK)
	jwksBytes, _ := json.Marshal(jwks)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: srv.URL},
		}),
	)

	_, err := p.ValidateWorkload(context.Background(), token, "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestVerifyWithResolver_BadJWS(t *testing.T) {
	resolver := &mockJWKSResolver{}
	p, _ := NewProvider(WithJWKSResolver(resolver))
	_, span := otel.Tracer(tracerName).Start(context.Background(), "test")
	err := p.verifyWithResolver(context.Background(), "not-a-jws", "https://example.com/jwks", span)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parsing JWS") {
		t.Fatalf("error = %q, want containing 'parsing JWS'", err.Error())
	}
}

type errJWKSResolver struct{}

func (m *errJWKSResolver) ResolveKey(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("key not found")
}
func (m *errJWKSResolver) Prefetch(_ context.Context, _ []string) error { return nil }
func (m *errJWKSResolver) Stats() core.JWKSCacheStats                  { return core.JWKSCacheStats{} }

func TestVerifyWithResolver_ResolveKeyError(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.Import(privKey)
	_ = jwkKey.Set(jwk.KeyIDKey, "kid-1")
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())
	tok, _ := jwt.NewBuilder().
		Issuer("https://auth.example.com").
		Subject("user-1").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5*time.Minute).UTC()).
		Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))

	resolver := &errJWKSResolver{}
	p, _ := NewProvider(WithJWKSResolver(resolver))
	_, span := otel.Tracer(tracerName).Start(context.Background(), "test")
	err := p.verifyWithResolver(context.Background(), string(signed), "https://example.com/jwks", span)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "resolving key") {
		t.Fatalf("error = %q, want containing 'resolving key'", err.Error())
	}
}

func TestVerifyWithResolver_WrongKey(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.Import(privKey)
	_ = jwkKey.Set(jwk.KeyIDKey, "kid-1")
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())
	tok, _ := jwt.NewBuilder().
		Issuer("https://auth.example.com").
		Subject("user-1").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5*time.Minute).UTC()).
		Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resolver := &mockJWKSResolver{pubKey: wrongKey.Public()}
	p, _ := NewProvider(WithJWKSResolver(resolver))
	_, span := otel.Tracer(tracerName).Start(context.Background(), "test")
	err := p.verifyWithResolver(context.Background(), string(signed), "https://example.com/jwks", span)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestOpaque_IntrospectionInvalidJSON(t *testing.T) {
	issuer := "https://auth.example.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-client" || pass != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)

	_, err := p.ValidateWorkload(context.Background(), "opaque-token", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "decoding introspection response") {
		t.Fatalf("error = %q, want containing 'decoding introspection response'", err.Error())
	}
}

func TestOpaque_IntrospectionFallbackIssuer(t *testing.T) {
	issuer := "https://auth.example.com"
	srv := introspectionServer(t, IntrospectionResponse{
		Active:   true,
		Sub:      "user-fb",
		ClientID: "client-fb",
		Issuer:   "",
	})
	defer srv.Close()

	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)

	identity, err := p.ValidateWorkload(context.Background(), "opaque-token", "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["issuer"] != issuer {
		t.Errorf("issuer = %v, want %v", identity.Claims["issuer"], issuer)
	}
}

func TestOpaque_SubAsPrincipalWhenNoClientID(t *testing.T) {
	issuer := "https://auth.example.com"
	srv := introspectionServer(t, IntrospectionResponse{
		Active: true,
		Sub:    "user-sub-only",
		Issuer: issuer,
	})
	defer srv.Close()

	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)

	identity, err := p.ValidateWorkload(context.Background(), "opaque-token", "oauth2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oauth2/user-sub-only" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oauth2/user-sub-only")
	}
}

func TestOpaque_IntrospectionNetworkError(t *testing.T) {
	issuer := "https://auth.example.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
	}))
	srv.Close()

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: issuer},
		}),
		WithIntrospection(issuer, srv.URL, ClientCredentials{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "opaque-token", "oauth2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "introspection request failed") {
		t.Fatalf("error = %q, want containing 'introspection request failed'", err.Error())
	}
}
