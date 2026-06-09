package gcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"go.opentelemetry.io/otel"
)

func mintGCPToken(t *testing.T, sub, email, projectID string) string {
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
		Issuer(googleIssuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	if email != "" {
		if err := tok.Set("email", email); err != nil {
			t.Fatal(err)
		}
	}

	if projectID != "" {
		googleClaim := map[string]interface{}{
			"compute_engine": map[string]interface{}{
				"project_id": projectID,
			},
		}
		if err := tok.Set("google", googleClaim); err != nil {
			t.Fatal(err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestDevMode_HappyPath(t *testing.T) {
	cred := mintGCPToken(t, "112233445566", "svc@my-project.iam.gserviceaccount.com", "my-project")

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://dev.local/gcp/svc@my-project.iam.gserviceaccount.com"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
	if identity.Attestation.Method != credType {
		t.Errorf("attestation method = %q, want %q", identity.Attestation.Method, credType)
	}
	if identity.Claims["email"] != "svc@my-project.iam.gserviceaccount.com" {
		t.Errorf("email claim = %v, want svc@my-project.iam.gserviceaccount.com", identity.Claims["email"])
	}
	if identity.Claims["project_id"] != "my-project" {
		t.Errorf("project_id claim = %v, want my-project", identity.Claims["project_id"])
	}
}

func TestDevMode_FallbackToSub(t *testing.T) {
	cred := mintGCPToken(t, "112233445566", "", "my-project")

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://dev.local/gcp/112233445566"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
}

func TestWrongIssuer(t *testing.T) {
	// Mint a token with a non-Google issuer.
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
		Subject("sub-1").
		Issuer("https://wrong-issuer.example.com").
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

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), string(signed), credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("error = %q, want containing 'issuer'", err.Error())
	}
}

func TestWrongCredType(t *testing.T) {
	cred := mintGCPToken(t, "sub-1", "test@example.com", "proj")

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported credential type") {
		t.Fatalf("error = %q, want containing 'unsupported credential type'", err.Error())
	}
}

func TestMalformedJWT(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "not-a-jwt", credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "malformed GCP token") {
		t.Fatalf("error = %q, want containing 'malformed GCP token'", err.Error())
	}
}

func TestMissingSub(t *testing.T) {
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
		Issuer(googleIssuer).
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

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), string(signed), credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing sub claim") {
		t.Fatalf("error = %q, want containing 'missing sub claim'", err.Error())
	}
}

func TestInterfaceAssertion(t *testing.T) {
	p, err := NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	var _ core.IdentityProvider = p
}

// mockJWKSResolver implements core.JWKSResolver for production-mode tests.
// It returns a fixed public key for ResolveKey and no-op Prefetch/Stats.
type mockJWKSResolver struct {
	key       crypto.PublicKey
	resolveErr error
}

func (m *mockJWKSResolver) ResolveKey(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	return m.key, nil
}

func (m *mockJWKSResolver) Prefetch(_ context.Context, _ []string) error { return nil }

func (m *mockJWKSResolver) Stats() core.JWKSCacheStats { return core.JWKSCacheStats{} }

// mintGCPTokenWithKey mints a JWT signed with the given private key and kid,
// for production-mode verification via JWKSResolver.
func mintGCPTokenWithKey(t *testing.T, privKey *ecdsa.PrivateKey, kid, sub, email, projectID, zone, instanceID string, useFlatProjectID bool) string {
	t.Helper()
	jwkKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	builder := jwt.NewBuilder().
		Subject(sub).
		Issuer(googleIssuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	if email != "" {
		if err := tok.Set("email", email); err != nil {
			t.Fatal(err)
		}
	}

	if useFlatProjectID {
		if projectID != "" {
			if err := tok.Set("project_id", projectID); err != nil {
				t.Fatal(err)
			}
		}
	} else if projectID != "" || zone != "" || instanceID != "" {
		ce := make(map[string]interface{})
		if projectID != "" {
			ce["project_id"] = projectID
		}
		if zone != "" {
			ce["zone"] = zone
		}
		if instanceID != "" {
			ce["instance_id"] = instanceID
		}
		googleClaim := map[string]interface{}{"compute_engine": ce}
		if err := tok.Set("google", googleClaim); err != nil {
			t.Fatal(err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestProdMode_JWKSResolver_HappyPath(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := mintGCPTokenWithKey(t, privKey, "test-kid-1", "112233445566", "svc@my-project.iam.gserviceaccount.com", "my-project", "", "", false)

	resolver := &mockJWKSResolver{key: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(resolver),
		WithTrustDomains([]core.TrustDomain{
			{Name: "my-project", Enabled: true, JWKSURL: googleJWKSURL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://my-project/gcp/svc@my-project.iam.gserviceaccount.com"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
	if identity.TrustDomain != "my-project" {
		t.Errorf("TrustDomain = %q, want my-project", identity.TrustDomain)
	}
	if identity.Claims["email"] != "svc@my-project.iam.gserviceaccount.com" {
		t.Errorf("email claim = %v", identity.Claims["email"])
	}
	if identity.Claims["project_id"] != "my-project" {
		t.Errorf("project_id claim = %v", identity.Claims["project_id"])
	}
}

func TestProdMode_UnknownProject(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := mintGCPTokenWithKey(t, privKey, "kid-1", "sub-1", "svc@unknown.iam.gserviceaccount.com", "unknown-project", "", "", false)

	resolver := &mockJWKSResolver{key: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(resolver),
		WithTrustDomains([]core.TrustDomain{
			{Name: "known-project", Enabled: true, JWKSURL: googleJWKSURL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown GCP project") {
		t.Fatalf("error = %q, want containing 'unknown GCP project'", err.Error())
	}
}

func TestProdMode_AllowedProjects_Rejected(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := mintGCPTokenWithKey(t, privKey, "kid-1", "sub-1", "", "disallowed-project", "", "", false)

	resolver := &mockJWKSResolver{key: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(resolver),
		WithTrustDomains([]core.TrustDomain{
			{Name: "disallowed-project", Enabled: true, JWKSURL: googleJWKSURL},
		}),
		WithAllowedProjects([]string{"allowed-project"}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not in allowed projects") {
		t.Fatalf("error = %q, want containing 'not in allowed projects'", err.Error())
	}
}

func TestProdMode_AllowedProjects_Accepted(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := mintGCPTokenWithKey(t, privKey, "kid-1", "sub-1", "", "allowed-project", "", "", false)

	resolver := &mockJWKSResolver{key: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(resolver),
		WithTrustDomains([]core.TrustDomain{
			{Name: "allowed-project", Enabled: true, JWKSURL: googleJWKSURL},
		}),
		WithAllowedProjects([]string{"allowed-project"}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.TrustDomain != "allowed-project" {
		t.Errorf("TrustDomain = %q, want allowed-project", identity.TrustDomain)
	}
	if identity.Claims["project_id"] != "allowed-project" {
		t.Errorf("project_id = %v", identity.Claims["project_id"])
	}
}

func TestDevMode_GCE_Metadata_ZoneAndInstanceID(t *testing.T) {
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
		Subject("112233445566").
		Issuer(googleIssuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := tok.Set("email", "svc@gce.iam.gserviceaccount.com"); err != nil {
		t.Fatal(err)
	}
	googleClaim := map[string]interface{}{
		"compute_engine": map[string]interface{}{
			"project_id":  "gce-project",
			"zone":        "us-central1-a",
			"instance_id": "1234567890123456789",
		},
	}
	if err := tok.Set("google", googleClaim); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}
	cred := string(signed)

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["zone"] != "us-central1-a" {
		t.Errorf("zone = %v, want us-central1-a", identity.Claims["zone"])
	}
	if identity.Claims["instance_id"] != "1234567890123456789" {
		t.Errorf("instance_id = %v, want 1234567890123456789", identity.Claims["instance_id"])
	}
	if identity.Claims["project_id"] != "gce-project" {
		t.Errorf("project_id = %v, want gce-project", identity.Claims["project_id"])
	}
}

func TestDevMode_FlatProjectID_Fallback(t *testing.T) {
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
		Subject("sub-flat").
		Issuer(googleIssuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	// No google.compute_engine; only flat project_id
	if err := tok.Set("project_id", "flat-project"); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), string(signed), credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["project_id"] != "flat-project" {
		t.Errorf("project_id = %v, want flat-project", identity.Claims["project_id"])
	}
}

func TestProdMode_JWKSResolver_ResolveKeyError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := mintGCPTokenWithKey(t, privKey, "kid-1", "sub-1", "", "my-project", "", "", false)

	resolver := &mockJWKSResolver{key: privKey.Public(), resolveErr: errors.New("key not found")}
	p, err := NewProvider(
		WithJWKSResolver(resolver),
		WithTrustDomains([]core.TrustDomain{
			{Name: "my-project", Enabled: true, JWKSURL: googleJWKSURL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "resolving key") {
		t.Fatalf("error = %q, want containing 'resolving key'", err.Error())
	}
}

func TestProdMode_JWKSResolver_WrongKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Resolver returns a different key (wrong key for verification)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := mintGCPTokenWithKey(t, signingKey, "kid-1", "sub-1", "", "my-project", "", "", false)

	resolver := &mockJWKSResolver{key: wrongKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(resolver),
		WithTrustDomains([]core.TrustDomain{
			{Name: "my-project", Enabled: true, JWKSURL: googleJWKSURL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestProdMode_FlatProjectID_WithJWKSResolver(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := mintGCPTokenWithKey(t, privKey, "kid-1", "sub-flat", "svc@flat.iam.gserviceaccount.com", "flat-project", "", "", true)

	resolver := &mockJWKSResolver{key: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(resolver),
		WithTrustDomains([]core.TrustDomain{
			{Name: "flat-project", Enabled: true, JWKSURL: googleJWKSURL},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["project_id"] != "flat-project" {
		t.Errorf("project_id = %v, want flat-project", identity.Claims["project_id"])
	}
	if identity.ID != "wimse://flat-project/gcp/svc@flat.iam.gserviceaccount.com" {
		t.Errorf("ID = %q", identity.ID)
	}
}

func TestVerifyWithResolver_InvalidJWS(t *testing.T) {
	mock := &mockJWKSResolver{}
	p, _ := NewProvider(WithJWKSResolver(mock))

	ctx := context.Background()
	_, span := otel.Tracer("test").Start(ctx, "test-span")
	err := p.verifyWithResolver(ctx, "not-a-jws-token", googleJWKSURL, span)
	if err == nil {
		t.Fatal("expected error for invalid JWS")
	}
	if !strings.Contains(err.Error(), "parsing JWS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyWithResolver_ResolveKeyError(t *testing.T) {
	mock := &mockJWKSResolver{resolveErr: errors.New("key not found")}
	p, _ := NewProvider(WithJWKSResolver(mock))

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.Import(privKey)
	_ = jwkKey.Set(jwk.KeyIDKey, "test-kid")
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())

	tok, _ := jwt.NewBuilder().Subject("test").Issuer(googleIssuer).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))

	ctx := context.Background()
	_, span := otel.Tracer("test").Start(ctx, "test-span")
	err := p.verifyWithResolver(ctx, string(signed), googleJWKSURL, span)
	if err == nil {
		t.Fatal("expected error when resolver fails")
	}
	if !strings.Contains(err.Error(), "resolving key") {
		t.Errorf("unexpected error: %v", err)
	}
}
