package spiffe

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

func mintTestSVID(t *testing.T, sub string) string {
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

	tok, err := jwt.NewBuilder().
		Subject(sub).
		Issuer("spiffe://example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
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
			cred:    mintTestSVID(t, "spiffe://example.com/ns/default/sa/web"),
			ct:      "spiffe-svid",
			devMode: true,
			wantURI: "wimse://dev.local/spiffe/ns/default/sa/web",
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
			ct:      "spiffe-svid",
			devMode: true,
			wantErr: "malformed JWT-SVID",
		},
		{
			name: "missing sub claim",
			cred: func() string {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				jwkKey, _ := jwk.Import(key)
				_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())
				tok, _ := jwt.NewBuilder().Issuer("test").Build()
				signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
				return string(signed)
			}(),
			ct:      "spiffe-svid",
			devMode: true,
			wantErr: "missing sub claim",
		},
		{
			name:    "non-spiffe URI",
			cred:    mintTestSVID(t, "https://example.com/workload"),
			ct:      "spiffe-svid",
			devMode: true,
			wantErr: "invalid SPIFFE ID",
		},
		{
			name:    "spiffe ID missing path",
			cred:    mintTestSVID(t, "spiffe://example.com"),
			ct:      "spiffe-svid",
			devMode: true,
			wantErr: "missing workload path",
		},
		{
			name:    "unknown trust domain (prod mode)",
			cred:    mintTestSVID(t, "spiffe://unknown.domain/workload/svc"),
			ct:      "spiffe-svid",
			devMode: false,
			wantErr: "unknown SPIFFE trust domain",
		},
		{
			name:    "trust domain no JWKS URL (prod mode)",
			cred:    mintTestSVID(t, "spiffe://nojwks.local/workload/svc"),
			ct:      "spiffe-svid",
			devMode: false,
			wantErr: "no JWKS URL",
		},
		{
			name:    "JWKS fetch error (prod mode, bad URL)",
			cred:    mintTestSVID(t, "spiffe://example.com/ns/default/sa/web"),
			ct:      "spiffe-svid",
			devMode: false,
			wantErr: "fetching JWKS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProvider(
				WithDevMode(tt.devMode),
				WithTrustDomains([]core.TrustDomain{
					{Name: "example.com", Enabled: true, JWKSURL: "https://example.com/.well-known/jwks.json"},
					{Name: "nojwks.local", Enabled: true, JWKSURL: ""},
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
			if identity.Attestation.Method != "spiffe-svid" {
				t.Errorf("attestation method = %q, want spiffe-svid", identity.Attestation.Method)
			}
			if identity.Claims["spiffe_id"] == nil {
				t.Error("missing spiffe_id in claims")
			}
		})
	}
}

func TestParseSpiffeID(t *testing.T) {
	tests := []struct {
		input   string
		wantTD  string
		wantWP  string
		wantErr bool
	}{
		{"spiffe://example.com/ns/default/sa/web", "example.com", "ns/default/sa/web", false},
		{"spiffe://prod.acme/workload/api", "prod.acme", "workload/api", false},
		{"spiffe://example.com", "", "", true},
		{"https://example.com/path", "", "", true},
		{"garbage", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			td, wp, err := parseSpiffeID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if td != tt.wantTD {
				t.Errorf("trust domain = %q, want %q", td, tt.wantTD)
			}
			if wp != tt.wantWP {
				t.Errorf("workload path = %q, want %q", wp, tt.wantWP)
			}
		})
	}
}

func TestWithJWKSResolver(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &spiffeMockResolver{pubKey: privKey.Public()}

	p, err := NewProvider(WithJWKSResolver(resolver))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.jwksResolver == nil {
		t.Error("expected jwksResolver to be set")
	}
}

func TestWithTrustDomains_DisabledFiltered(t *testing.T) {
	p, err := NewProvider(WithTrustDomains([]core.TrustDomain{
		{Name: "enabled.com", Enabled: true},
		{Name: "disabled.com", Enabled: false},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.trustDomains["enabled.com"]; !ok {
		t.Error("expected enabled.com to be present")
	}
	if _, ok := p.trustDomains["disabled.com"]; ok {
		t.Error("expected disabled.com to be absent")
	}
}

type spiffeMockResolver struct {
	pubKey crypto.PublicKey
	err    error
}

func (m *spiffeMockResolver) ResolveKey(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.pubKey, nil
}

func (m *spiffeMockResolver) Prefetch(_ context.Context, _ []string) error { return nil }

func (m *spiffeMockResolver) Stats() core.JWKSCacheStats { return core.JWKSCacheStats{} }

func TestProdValidate_WithJWKSResolver_HappyPath(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwkKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, "test-kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	tok, err := jwt.NewBuilder().
		Subject("spiffe://example.com/ns/default/sa/web").
		Issuer("spiffe://example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}

	resolver := &spiffeMockResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithDevMode(false),
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, JWKSURL: "https://example.com/jwks"},
		}),
		WithJWKSResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), string(signed), "spiffe-svid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://example.com/spiffe/ns/default/sa/web" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/spiffe/ns/default/sa/web")
	}
	if identity.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want example.com", identity.TrustDomain)
	}
}

func TestProdValidate_WithJWKSResolver_ResolveKeyError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, "kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	tok, err := jwt.NewBuilder().
		Subject("spiffe://example.com/workload/svc").
		Issuer("spiffe://example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}

	resolver := &spiffeMockResolver{err: fmt.Errorf("key not found")}
	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, JWKSURL: "https://example.com/jwks"},
		}),
		WithJWKSResolver(resolver),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.ValidateWorkload(context.Background(), string(signed), "spiffe-svid")
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
	jwkKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, "kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	tok, err := jwt.NewBuilder().
		Subject("spiffe://example.com/workload/svc").
		Issuer("spiffe://example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &spiffeMockResolver{pubKey: wrongKey.Public()}
	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, JWKSURL: "https://example.com/jwks"},
		}),
		WithJWKSResolver(resolver),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.ValidateWorkload(context.Background(), string(signed), "spiffe-svid")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestVerifyWithResolver_BadJWS(t *testing.T) {
	resolver := &spiffeMockResolver{}
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
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	tok, err := jwt.NewBuilder().
		Subject("spiffe://example.com/workload/svc").
		Issuer("spiffe://example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}

	resolver := &spiffeMockResolver{pubKey: privKey.Public()}
	p, _ := NewProvider(WithJWKSResolver(resolver))
	_, span := otel.Tracer(tracerName).Start(context.Background(), "test")
	err = p.verifyWithResolver(context.Background(), string(signed), "https://example.com/jwks", span)
	if err == nil {
		t.Fatal("expected error for missing kid")
	}
	if !strings.Contains(err.Error(), "missing kid") {
		t.Fatalf("error = %q, want containing 'missing kid'", err.Error())
	}
}

func TestProdValidate_JWKSFetchOK_ValidationFails(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkSigning, err := jwk.Import(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkSigning.Set(jwk.KeyIDKey, "kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := jwkSigning.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	tok, err := jwt.NewBuilder().
		Subject("spiffe://example.com/workload/svc").
		Issuer("spiffe://example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkSigning))
	if err != nil {
		t.Fatal(err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubJWK, err := jwk.Import(wrongKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, "kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	jwks := map[string]interface{}{"keys": []interface{}{pubJWK}}
	jwksBytes, _ := json.Marshal(jwks)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, JWKSURL: srv.URL},
		}),
	)

	_, err = p.ValidateWorkload(context.Background(), string(signed), "spiffe-svid")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestParseSpiffeID_EmptyHost(t *testing.T) {
	_, _, err := parseSpiffeID("spiffe:///workload")
	if err == nil {
		t.Fatal("expected error for empty host")
	}
	if !strings.Contains(err.Error(), "missing trust domain") {
		t.Fatalf("error = %q, want containing 'missing trust domain'", err.Error())
	}
}

func TestProdValidate_HappyPath(t *testing.T) {
	// 1. Generate ECDSA P-256 key pair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Build a JWK from the private key, set kid and alg.
	jwkKey, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, "test-kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	// Mint a JWT-SVID signed with the private key.
	tok, err := jwt.NewBuilder().
		Subject("spiffe://example.com/ns/default/sa/web").
		Issuer("spiffe://example.com").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}

	// 3. Build JWKS with the public key and serve via httptest.
	pubKey, err := jwk.Import(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.KeyIDKey, "test-kid-1"); err != nil {
		t.Fatal(err)
	}
	if err := pubKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{pubKey},
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

	// 4. Create Provider in prod mode with trust domain pointing to httptest JWKS URL.
	p, err := NewProvider(
		WithDevMode(false),
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true, JWKSURL: srv.URL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// 5. Validate and assert.
	identity, err := p.ValidateWorkload(context.Background(), string(signed), "spiffe-svid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.ID != "wimse://example.com/spiffe/ns/default/sa/web" {
		t.Errorf("ID = %q, want %q", identity.ID, "wimse://example.com/spiffe/ns/default/sa/web")
	}
	if identity.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "example.com")
	}
	if identity.Attestation.Method != "spiffe-svid" {
		t.Errorf("Attestation.Method = %q, want %q", identity.Attestation.Method, "spiffe-svid")
	}
	if identity.Claims["spiffe_id"] == nil {
		t.Error("missing spiffe_id in claims")
	}
	if identity.Claims["trust_domain"] == nil {
		t.Error("missing trust_domain in claims")
	}
}
