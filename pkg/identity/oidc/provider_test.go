package oidc

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

func mintTestOIDCToken(t *testing.T, sub, issuer string, extraClaims map[string]interface{}) string {
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
		Subject(sub).
		Issuer(issuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range extraClaims {
		if err := tok.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestProvider_ValidateWorkload(t *testing.T) {
	tests := []struct {
		name    string
		cred    string
		ct      string
		devMode bool
		wantErr string
		wantURI string
	}{
		{
			name:    "dev mode happy path",
			cred:    mintTestOIDCToken(t, "user-123", "https://accounts.google.com", nil),
			ct:      "oidc",
			devMode: true,
			wantURI: "wimse://dev.local/oidc/user-123",
		},
		{
			name: "dev mode with optional claims",
			cred: mintTestOIDCToken(t, "user-456", "https://login.microsoftonline.com/tenant", map[string]interface{}{
				"email":  "user@example.com",
				"groups": []string{"admins", "devs"},
				"azp":    "client-id-123",
			}),
			ct:      "oidc",
			devMode: true,
			wantURI: "wimse://dev.local/oidc/user-456",
		},
		{
			name:    "wrong cred type",
			cred:    "anything",
			ct:      "k8s-sa",
			devMode: true,
			wantErr: "unsupported credential type",
		},
		{
			name:    "malformed JWT",
			cred:    "not-a-jwt",
			ct:      "oidc",
			devMode: true,
			wantErr: "malformed OIDC token",
		},
		{
			name: "missing iss claim",
			cred: func() string {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				jwkKey, _ := jwk.Import(key)
				_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())
				tok, _ := jwt.NewBuilder().Subject("test").Build()
				signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
				return string(signed)
			}(),
			ct:      "oidc",
			devMode: true,
			wantErr: "missing iss claim",
		},
		{
			name: "missing sub claim",
			cred: func() string {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				jwkKey, _ := jwk.Import(key)
				_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())
				tok, _ := jwt.NewBuilder().Issuer("https://auth.example.com").Build()
				signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
				return string(signed)
			}(),
			ct:      "oidc",
			devMode: true,
			wantErr: "missing sub claim",
		},
		{
			name:    "unknown issuer (prod mode)",
			cred:    mintTestOIDCToken(t, "user-789", "https://unknown-issuer.com", nil),
			ct:      "oidc",
			devMode: false,
			wantErr: "unknown OIDC issuer",
		},
		{
			name:    "no JWKS URL (prod mode)",
			cred:    mintTestOIDCToken(t, "user-000", "https://nojwks.example.com", nil),
			ct:      "oidc",
			devMode: false,
			wantErr: "no JWKS URL",
		},
		{
			name:    "JWKS fetch error (prod mode)",
			cred:    mintTestOIDCToken(t, "user-111", "https://accounts.google.com", nil),
			ct:      "oidc",
			devMode: false,
			wantErr: "fetching JWKS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProvider(
				WithDevMode(tt.devMode),
				WithTrustDomains([]core.TrustDomain{
					{Name: "google.com", Enabled: true, Issuer: "https://accounts.google.com", JWKSURL: "https://invalid.test/jwks"},
					{Name: "nojwks.com", Enabled: true, Issuer: "https://nojwks.example.com", JWKSURL: ""},
				}),
			)
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}

			identity, err := p.ValidateWorkload(context.Background(), tt.cred, tt.ct)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if identity.ID != tt.wantURI {
				t.Errorf("ID = %q, want %q", identity.ID, tt.wantURI)
			}
			if identity.Attestation.Method != "oidc" {
				t.Errorf("attestation method = %q, want oidc", identity.Attestation.Method)
			}
			if identity.Claims["issuer"] == nil {
				t.Error("missing issuer in claims")
			}
			if identity.Claims["subject"] == nil {
				t.Error("missing subject in claims")
			}
		})
	}
}

func TestProvider_ValidateWorkload_OptionalClaims(t *testing.T) {
	cred := mintTestOIDCToken(t, "user-claims", "https://auth.example.com", map[string]interface{}{
		"email":  "test@example.com",
		"groups": []interface{}{"eng", "platform"},
		"roles":  []interface{}{"admin"},
		"azp":    "my-client",
	})

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "oidc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.Claims["email"] != "test@example.com" {
		t.Errorf("email = %v, want test@example.com", identity.Claims["email"])
	}
	if identity.Claims["azp"] != "my-client" {
		t.Errorf("azp = %v, want my-client", identity.Claims["azp"])
	}
	if identity.Claims["groups"] == nil {
		t.Error("missing groups claim")
	}
	if identity.Claims["roles"] == nil {
		t.Error("missing roles claim")
	}
}

func TestProdValidate_HappyPath(t *testing.T) {
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

	// 3. Mint OIDC token
	tok, err := jwt.NewBuilder().
		Subject("user-prod-1").
		Issuer("https://auth.example.com").
		Audience([]string{"starfly"}).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}

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
	identity, err := p.ValidateWorkload(context.Background(), string(signed), "oidc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oidc/user-prod-1" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oidc/user-prod-1")
	}
	if identity.Attestation.Method != "oidc" {
		t.Errorf("attestation method = %q, want %q", identity.Attestation.Method, "oidc")
	}
}

func TestProdValidate_AudienceRejection(t *testing.T) {
	// Generate key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

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

	// Mint token with aud: ["starfly"]
	tok, err := jwt.NewBuilder().
		Subject("user-prod-1").
		Issuer("https://auth.example.com").
		Audience([]string{"starfly"}).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}

	// JWKS server
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

	// Provider expects "other-service" but token has "starfly"
	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: srv.URL},
		}),
		WithExpectedAudiences([]string{"other-service"}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), string(signed), "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Fatalf("error = %q, want containing 'audience'", err.Error())
	}
}

type oidcMockResolver struct {
	pubKey crypto.PublicKey
	err    error
}

func (m *oidcMockResolver) ResolveKey(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.pubKey, nil
}

func (m *oidcMockResolver) Prefetch(_ context.Context, _ []string) error { return nil }

func (m *oidcMockResolver) Stats() core.JWKSCacheStats { return core.JWKSCacheStats{} }

func mintSignedOIDCToken(t *testing.T, sub, issuer string, audiences []string, signingKey jwk.Key) string {
	t.Helper()
	builder := jwt.NewBuilder().
		Subject(sub).
		Issuer(issuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())
	if len(audiences) > 0 {
		builder = builder.Audience(audiences)
	}
	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), signingKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestWithJWKSResolver(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resolver := &oidcMockResolver{pubKey: privKey.Public()}
	p, err := NewProvider(WithJWKSResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	if p.jwksResolver == nil {
		t.Error("expected jwksResolver to be set")
	}
}

func TestProdValidate_WithJWKSResolver_HappyPath(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "oidc-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	token := mintSignedOIDCToken(t, "user-resolver-1", "https://auth.example.com", nil, signingKey)

	resolver := &oidcMockResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: "https://example.com/jwks"},
		}),
		WithJWKSResolver(resolver),
	)
	if err != nil {
		t.Fatal(err)
	}

	identity, err := p.ValidateWorkload(context.Background(), token, "oidc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oidc/user-resolver-1" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oidc/user-resolver-1")
	}
}

func TestProdValidate_WithJWKSResolver_ResolveKeyError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "oidc-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	token := mintSignedOIDCToken(t, "user-1", "https://auth.example.com", nil, signingKey)

	resolver := &oidcMockResolver{err: fmt.Errorf("key not found")}
	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: "https://example.com/jwks"},
		}),
		WithJWKSResolver(resolver),
	)

	_, err = p.ValidateWorkload(context.Background(), token, "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "resolving key") {
		t.Fatalf("error = %q, want containing 'resolving key'", err.Error())
	}
}

func TestProdValidate_WithJWKSResolver_WrongKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.KeyIDKey, "oidc-key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signingKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	token := mintSignedOIDCToken(t, "user-1", "https://auth.example.com", nil, signingKey)

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resolver := &oidcMockResolver{pubKey: wrongKey.Public()}
	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, Issuer: "https://auth.example.com", JWKSURL: "https://example.com/jwks"},
		}),
		WithJWKSResolver(resolver),
	)

	_, err = p.ValidateWorkload(context.Background(), token, "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestVerifyWithResolver_BadJWS(t *testing.T) {
	resolver := &oidcMockResolver{}
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

func TestVerifyWithResolver_MissingKid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.Import(privKey)
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())
	tok, _ := jwt.NewBuilder().
		Subject("user-1").
		Issuer("https://auth.example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))

	resolver := &oidcMockResolver{pubKey: privKey.Public()}
	p, _ := NewProvider(WithJWKSResolver(resolver))
	_, span := otel.Tracer(tracerName).Start(context.Background(), "test")
	err := p.verifyWithResolver(context.Background(), string(signed), "https://example.com/jwks", span)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing kid") {
		t.Fatalf("error = %q, want containing 'missing kid'", err.Error())
	}
}

func TestProdValidate_JWKSFetchOK_ValidationFails(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkSigning, _ := jwk.Import(signingKey)
	_ = jwkSigning.Set(jwk.KeyIDKey, "kid-1")
	_ = jwkSigning.Set(jwk.AlgorithmKey, jwa.ES256())

	tok, _ := jwt.NewBuilder().
		Subject("user-jf-1").
		Issuer("https://auth.example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkSigning))

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubJWK, _ := jwk.Import(wrongKey.Public())
	_ = pubJWK.Set(jwk.KeyIDKey, "kid-1")
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.ES256())
	jwks := map[string]interface{}{"keys": []interface{}{pubJWK}}
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

	_, err := p.ValidateWorkload(context.Background(), string(signed), "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestProdValidate_AudienceMatchHappyPath(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingKey, _ := jwk.Import(privKey)
	_ = signingKey.Set(jwk.KeyIDKey, "key-aud-1")
	_ = signingKey.Set(jwk.AlgorithmKey, jwa.ES256())

	token := mintSignedOIDCToken(t, "user-aud-1", "https://auth.example.com", []string{"starfly"}, signingKey)

	pubKey, _ := jwk.Import(privKey.Public())
	_ = pubKey.Set(jwk.KeyIDKey, "key-aud-1")
	_ = pubKey.Set(jwk.AlgorithmKey, jwa.ES256())
	jwks := jwk.NewSet()
	_ = jwks.AddKey(pubKey)
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
		WithExpectedAudiences([]string{"starfly"}),
	)

	identity, err := p.ValidateWorkload(context.Background(), token, "oidc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/oidc/user-aud-1" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/oidc/user-aud-1")
	}
}

func TestProdValidate_MissingAudClaim(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signingKey, _ := jwk.Import(privKey)
	_ = signingKey.Set(jwk.KeyIDKey, "key-noaud-1")
	_ = signingKey.Set(jwk.AlgorithmKey, jwa.ES256())

	token := mintSignedOIDCToken(t, "user-noaud-1", "https://auth.example.com", nil, signingKey)

	pubKey, _ := jwk.Import(privKey.Public())
	_ = pubKey.Set(jwk.KeyIDKey, "key-noaud-1")
	_ = pubKey.Set(jwk.AlgorithmKey, jwa.ES256())
	jwks := jwk.NewSet()
	_ = jwks.AddKey(pubKey)
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
		WithExpectedAudiences([]string{"starfly"}),
	)

	_, err := p.ValidateWorkload(context.Background(), token, "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing aud claim") {
		t.Fatalf("error = %q, want containing 'missing aud claim'", err.Error())
	}
}

func TestDiscoverJWKS_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	_, err := DiscoverJWKS(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "decoding response") {
		t.Fatalf("error = %q, want containing 'decoding response'", err.Error())
	}
}

func TestDiscoverJWKS(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": "https://auth.example.com/jwks",
			})
		}))
		defer srv.Close()

		uri, err := DiscoverJWKS(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if uri != "https://auth.example.com/jwks" {
			t.Errorf("jwks_uri = %q, want https://auth.example.com/jwks", uri)
		}
	})

	t.Run("missing jwks_uri", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "test"})
		}))
		defer srv.Close()

		_, err := DiscoverJWKS(context.Background(), srv.URL)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "jwks_uri not found") {
			t.Errorf("error = %q, want containing jwks_uri not found", err.Error())
		}
	})

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		_, err := DiscoverJWKS(context.Background(), srv.URL)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "returned 500") {
			t.Errorf("error = %q, want containing returned 500", err.Error())
		}
	})

	t.Run("unreachable server", func(t *testing.T) {
		_, err := DiscoverJWKS(context.Background(), "http://127.0.0.1:1")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
