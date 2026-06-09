package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const testSigningKID = "azure-test-kid-1"

func mintAzureToken(t *testing.T, sub, oid, tid string) string {
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

	issuer := azureIssuerPrefix + tid + "/v2.0"

	builder := jwt.NewBuilder().
		Subject(sub).
		Issuer(issuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	if oid != "" {
		if err := tok.Set("oid", oid); err != nil {
			t.Fatal(err)
		}
	}
	if tid != "" {
		if err := tok.Set("tid", tid); err != nil {
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
	cred := mintAzureToken(t, "sub-abc-123", "oid-def-456", "tenant-ghi-789")

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://dev.local/azure/oid-def-456"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
	if identity.Attestation.Method != credType {
		t.Errorf("attestation method = %q, want %q", identity.Attestation.Method, credType)
	}
	if identity.Claims["tenant_id"] != "tenant-ghi-789" {
		t.Errorf("tenant_id claim = %v, want tenant-ghi-789", identity.Claims["tenant_id"])
	}
	if identity.Claims["object_id"] != "oid-def-456" {
		t.Errorf("object_id claim = %v, want oid-def-456", identity.Claims["object_id"])
	}
}

func TestDevMode_FallbackToSub(t *testing.T) {
	cred := mintAzureToken(t, "sub-abc-123", "", "tenant-ghi-789")

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://dev.local/azure/sub-abc-123"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
}

func TestExtractTenantID(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		want    string
		wantErr bool
	}{
		{
			name:   "v2 issuer",
			issuer: "https://login.microsoftonline.com/72f988bf-1234-5678-abcd-ef0123456789/v2.0",
			want:   "72f988bf-1234-5678-abcd-ef0123456789",
		},
		{
			name:   "v1 issuer (STS)",
			issuer: "https://sts.windows.net/72f988bf-1234-5678-abcd-ef0123456789/",
			want:   "72f988bf-1234-5678-abcd-ef0123456789",
		},
		{
			name:   "v2 issuer without trailing slash",
			issuer: "https://login.microsoftonline.com/my-tenant/v2.0",
			want:   "my-tenant",
		},
		{
			name:    "invalid issuer",
			issuer:  "https://example.com/something",
			wantErr: true,
		},
		{
			name:    "empty path after prefix",
			issuer:  "https://login.microsoftonline.com/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractTenantID(tt.issuer)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("extractTenantID(%q) = %q, want %q", tt.issuer, got, tt.want)
			}
		})
	}
}

func TestWrongIssuer(t *testing.T) {
	// Mint a token with a non-Azure issuer.
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
		Issuer("https://accounts.google.com").
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
	cred := mintAzureToken(t, "sub-1", "oid-1", "tenant-1")

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
	if !strings.Contains(err.Error(), "malformed Azure token") {
		t.Fatalf("error = %q, want containing 'malformed Azure token'", err.Error())
	}
}

func TestInterfaceAssertion(t *testing.T) {
	p, err := NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	var _ core.IdentityProvider = p
}

// mintSignedAzureToken creates an Azure JWT signed with a known key (kid set).
// Returns the signed token string. The caller must provide the same public key
// to the mock JWKSResolver for verification to succeed.
func mintSignedAzureToken(t *testing.T, privKey *ecdsa.PrivateKey, sub, oid, tid string, extraClaims map[string]interface{}) string {
	t.Helper()
	jwkKey, err := jwk.Import(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.KeyIDKey, testSigningKID); err != nil {
		t.Fatal(err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}

	issuer := azureIssuerPrefix + tid + "/v2.0"
	if iss, ok := extraClaims["issuer"]; ok {
		issuer = iss.(string)
		delete(extraClaims, "issuer")
	}

	builder := jwt.NewBuilder().
		Subject(sub).
		Issuer(issuer).
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC())

	if oid != "" {
		builder = builder.Claim("oid", oid)
	}
	if tid != "" {
		builder = builder.Claim("tid", tid)
	}
	for k, v := range extraClaims {
		builder = builder.Claim(k, v)
	}

	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// mockJWKSResolver returns a fixed public key for any issuer/kid.
type mockJWKSResolver struct {
	pubKey crypto.PublicKey
	err    error
}

func (m *mockJWKSResolver) ResolveKey(_ context.Context, _ string, _ string) (crypto.PublicKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.pubKey, nil
}

func nopSpan(ctx context.Context) (context.Context, trace.Span) {
	return otel.Tracer("test").Start(ctx, "test-span")
}

func (m *mockJWKSResolver) Prefetch(_ context.Context, _ []string) error {
	return nil
}

func (m *mockJWKSResolver) Stats() core.JWKSCacheStats {
	return core.JWKSCacheStats{}
}

// failingJWKSResolver returns an error from ResolveKey.
type failingJWKSResolver struct{}

func (f *failingJWKSResolver) ResolveKey(_ context.Context, _ string, _ string) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("mock resolve error")
}

func (f *failingJWKSResolver) Prefetch(_ context.Context, _ []string) error {
	return nil
}

func (f *failingJWKSResolver) Stats() core.JWKSCacheStats {
	return core.JWKSCacheStats{}
}

func TestProductionMode_ResolverResolveKeyError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "tenant-123"
	cred := mintSignedAzureToken(t, privKey, "sub-1", "oid-1", tenantID, nil)

	p, err := NewProvider(
		WithJWKSResolver(&failingJWKSResolver{}),
		WithTrustDomains([]core.TrustDomain{
			{Name: tenantID, Enabled: true, Issuer: azureIssuerPrefix + tenantID + "/v2.0"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error from resolver, got nil")
	}
	if !strings.Contains(err.Error(), "resolving key") {
		t.Errorf("error = %q, want containing 'resolving key'", err.Error())
	}
}

func TestProductionMode_WrongKeySignatureFails(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "tenant-123"
	cred := mintSignedAzureToken(t, privKey, "sub-1", "oid-1", tenantID, nil)

	// Mock returns a different key - verification should fail
	mock := &mockJWKSResolver{pubKey: otherKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(mock),
		WithTrustDomains([]core.TrustDomain{
			{Name: tenantID, Enabled: true, Issuer: azureIssuerPrefix + tenantID + "/v2.0"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected validation error for wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error = %q, want containing 'validation failed'", err.Error())
	}
}

func TestProductionMode_VerifyWithResolver(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "72f988bf-1234-5678-abcd-ef0123456789"
	cred := mintSignedAzureToken(t, privKey, "sub-1", "oid-1", tenantID, nil)

	mock := &mockJWKSResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(mock),
		WithTrustDomains([]core.TrustDomain{
			{Name: tenantID, Enabled: true, Issuer: azureIssuerPrefix + tenantID + "/v2.0"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantURI := "wimse://" + tenantID + "/azure/oid-1"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
	if identity.TrustDomain != tenantID {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, tenantID)
	}
}

func TestProductionMode_UnknownTenant(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "unknown-tenant-123"
	cred := mintSignedAzureToken(t, privKey, "sub-1", "oid-1", tenantID, nil)

	mock := &mockJWKSResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(mock),
		WithTrustDomains([]core.TrustDomain{
			{Name: "known-tenant-456", Enabled: true, Issuer: azureIssuerPrefix + "known-tenant-456/v2.0"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error for unknown tenant, got nil")
	}
	if !strings.Contains(err.Error(), "unknown Azure tenant") {
		t.Errorf("error = %q, want containing 'unknown Azure tenant'", err.Error())
	}
}

func TestProductionMode_AllowedTenantsRejected(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "disallowed-tenant"
	cred := mintSignedAzureToken(t, privKey, "sub-1", "oid-1", tenantID, nil)

	mock := &mockJWKSResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(mock),
		WithTrustDomains([]core.TrustDomain{
			{Name: tenantID, Enabled: true, Issuer: azureIssuerPrefix + tenantID + "/v2.0"},
		}),
		WithAllowedTenants([]string{"allowed-tenant-only"}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, credType)
	if err == nil {
		t.Fatal("expected error for disallowed tenant, got nil")
	}
	if !strings.Contains(err.Error(), "not in allowed tenants") {
		t.Errorf("error = %q, want containing 'not in allowed tenants'", err.Error())
	}
}

func TestProductionMode_AllowedTenantsAccepted(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "allowed-tenant"
	cred := mintSignedAzureToken(t, privKey, "sub-1", "oid-1", tenantID, nil)

	mock := &mockJWKSResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(mock),
		WithTrustDomains([]core.TrustDomain{
			{Name: tenantID, Enabled: true, Issuer: azureIssuerPrefix + tenantID + "/v2.0"},
		}),
		WithAllowedTenants([]string{tenantID, "other-tenant"}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://"+tenantID+"/azure/oid-1" {
		t.Errorf("ID = %q", identity.ID)
	}
}

func TestAppIDClaim(t *testing.T) {
	// mintAzureToken doesn't set appid; use dev mode with a custom token
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
		Subject("sub-sp").
		Issuer(azureIssuerPrefix + "tenant-1/v2.0").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Claim("oid", "oid-sp").
		Claim("tid", "tenant-1").
		Claim("appid", "app-id-12345").
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

	identity, err := p.ValidateWorkload(context.Background(), string(signed), credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["app_id"] != "app-id-12345" {
		t.Errorf("app_id claim = %v, want app-id-12345", identity.Claims["app_id"])
	}
}

func TestAZPFallback(t *testing.T) {
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
		Subject("sub-sp").
		Issuer(azureIssuerPrefix + "tenant-1/v2.0").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Claim("oid", "oid-sp").
		Claim("tid", "tenant-1").
		Claim("azp", "azp-app-id").
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

	identity, err := p.ValidateWorkload(context.Background(), string(signed), credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["app_id"] != "azp-app-id" {
		t.Errorf("app_id claim (azp fallback) = %v, want azp-app-id", identity.Claims["app_id"])
	}
}

func TestNameClaim(t *testing.T) {
	cred := mintSignedAzureToken(t, mustGenKey(t), "sub-1", "oid-1", "tenant-1", map[string]interface{}{"name": "My Service Principal"})

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["name"] != "My Service Principal" {
		t.Errorf("name claim = %v, want My Service Principal", identity.Claims["name"])
	}
}

func mustGenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRolesClaim(t *testing.T) {
	key := mustGenKey(t)
	cred := mintSignedAzureToken(t, key, "sub-1", "oid-1", "tenant-1", map[string]interface{}{"roles": []string{"Reader", "Contributor"}})

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rolesVal := identity.Claims["roles"]
	if rolesVal == nil {
		t.Fatal("roles claim is nil")
	}
	roles, ok := rolesVal.([]interface{})
	if !ok {
		t.Fatalf("roles claim type = %T, want []interface{}", rolesVal)
	}
	if len(roles) != 2 || roles[0].(string) != "Reader" || roles[1].(string) != "Contributor" {
		t.Errorf("roles = %v, want [Reader Contributor]", roles)
	}
}

func TestTIDClaimFallback(t *testing.T) {
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
	// Issuer with path that extractTenantID might not parse (edge case), but tid claim provides fallback
	tok, err := jwt.NewBuilder().
		Subject("sub-1").
		Issuer(azureIssuerPrefix + "tenant-from-tid/v2.0").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Claim("oid", "oid-1").
		Claim("tid", "tenant-from-tid").
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

	identity, err := p.ValidateWorkload(context.Background(), string(signed), credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["tenant_id"] != "tenant-from-tid" {
		t.Errorf("tenant_id = %v, want tenant-from-tid (from tid claim)", identity.Claims["tenant_id"])
	}
}

func TestSTSIssuerPrefix(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "72f988bf-1234-5678-abcd-ef0123456789"
	cred := mintSignedAzureToken(t, privKey, "sub-1", "oid-1", tenantID, map[string]interface{}{
		"issuer": azureSTSPrefix + tenantID + "/",
	})

	mock := &mockJWKSResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(mock),
		WithTrustDomains([]core.TrustDomain{
			{Name: tenantID, Enabled: true, Issuer: azureSTSPrefix + tenantID + "/"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Claims["tenant_id"] != tenantID {
		t.Errorf("tenant_id = %v, want %s (STS issuer)", identity.Claims["tenant_id"], tenantID)
	}
}

func TestMissingSubClaim(t *testing.T) {
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
		Issuer(azureIssuerPrefix + "tenant-1/v2.0").
		IssuedAt(time.Now().UTC()).
		Expiration(time.Now().Add(5 * time.Minute).UTC()).
		Claim("oid", "oid-1").
		Claim("tid", "tenant-1").
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
		t.Fatal("expected error for missing sub, got nil")
	}
	if !strings.Contains(err.Error(), "missing sub claim") {
		t.Errorf("error = %q, want containing 'missing sub claim'", err.Error())
	}
}

func TestProductionMode_FullHappyPath(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "prod-tenant-abc"
	cred := mintSignedAzureToken(t, privKey, "sub-workload", "oid-workload", tenantID, map[string]interface{}{
		"appid": "app-123",
		"name":  "Production Workload",
		"roles": []string{"Reader"},
	})

	mock := &mockJWKSResolver{pubKey: privKey.Public()}
	p, err := NewProvider(
		WithJWKSResolver(mock),
		WithTrustDomains([]core.TrustDomain{
			{Name: tenantID, Enabled: true, Issuer: azureIssuerPrefix + tenantID + "/v2.0"},
		}),
		WithAllowedTenants([]string{tenantID}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, credType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "wimse://"+tenantID+"/azure/oid-workload" {
		t.Errorf("ID = %q", identity.ID)
	}
	if identity.Claims["app_id"] != "app-123" {
		t.Errorf("app_id = %v", identity.Claims["app_id"])
	}
	if identity.Claims["name"] != "Production Workload" {
		t.Errorf("name = %v", identity.Claims["name"])
	}
	// roles claim extraction covered by TestRolesClaim
}

func TestVerifyWithResolver_InvalidJWS(t *testing.T) {
	mock := &mockJWKSResolver{}
	p, _ := NewProvider(WithJWKSResolver(mock))

	ctx := context.Background()
	_, span := nopSpan(ctx)
	err := p.verifyWithResolver(ctx, "not-a-jws-token", "https://login.microsoftonline.com/test/v2.0", span)
	if err == nil {
		t.Fatal("expected error for invalid JWS")
	}
	if !strings.Contains(err.Error(), "parsing JWS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyWithResolver_ResolveKeyError(t *testing.T) {
	mock := &mockJWKSResolver{err: errors.New("key not found")}
	p, _ := NewProvider(WithJWKSResolver(mock))

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.Import(privKey)
	_ = jwkKey.Set(jwk.KeyIDKey, "test-kid")
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256())

	tok, _ := jwt.NewBuilder().Subject("test").Issuer("test").
		Expiration(time.Now().Add(5 * time.Minute).UTC()).Build()
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkKey))

	ctx := context.Background()
	_, span := nopSpan(ctx)
	err := p.verifyWithResolver(ctx, string(signed), "https://login.microsoftonline.com/test/v2.0", span)
	if err == nil {
		t.Fatal("expected error when resolver fails")
	}
	if !strings.Contains(err.Error(), "resolving key") {
		t.Errorf("unexpected error: %v", err)
	}
}
