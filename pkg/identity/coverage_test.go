package identity

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestNew_DevMode(t *testing.T) {
	ctx := context.Background()
	p, err := New(ctx, nil, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
	if !p.devMode {
		t.Error("devMode should be true")
	}
}

func TestNew_DisabledDomain(t *testing.T) {
	ctx := context.Background()
	domains := []core.TrustDomain{
		{Name: "disabled.example.com", Enabled: false, JWKSURL: "http://x", Issuer: "http://x"},
	}
	p, err := New(ctx, domains, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(p.trustDomains) != 0 {
		t.Errorf("trust domains = %d, want 0 (disabled domain should be skipped)", len(p.trustDomains))
	}
}

func TestNew_DomainMissingFields(t *testing.T) {
	ctx := context.Background()
	domains := []core.TrustDomain{
		{Name: "missing.example.com", Enabled: true, JWKSURL: "", Issuer: "http://x"},
		{Name: "missing2.example.com", Enabled: true, JWKSURL: "http://x", Issuer: ""},
	}
	p, err := New(ctx, domains, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(p.trustDomains) != 0 {
		t.Errorf("trust domains = %d, want 0 (incomplete domains should be skipped)", len(p.trustDomains))
	}
}

func TestValidateWorkload_DevMode(t *testing.T) {
	te := newTestEnv(t)
	ctx := context.Background()

	p, err := New(ctx, []core.TrustDomain{te.td}, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := te.mintToken(t)
	id, err := p.ValidateWorkload(ctx, string(token), "k8s-sa")
	if err != nil {
		t.Fatalf("ValidateWorkload: %v", err)
	}

	if id.TrustDomain != "dev.local" {
		t.Errorf("TrustDomain = %q, want dev.local", id.TrustDomain)
	}
	if id.Attestation.Method != "dev-bypass" {
		t.Errorf("Attestation.Method = %q, want dev-bypass", id.Attestation.Method)
	}
	if devMode, ok := id.Claims["dev_mode"].(bool); !ok || !devMode {
		t.Error("Claims should include dev_mode=true")
	}
}

func TestValidateWorkload_DevMode_MinimalToken(t *testing.T) {
	ctx := context.Background()

	p, err := New(ctx, nil, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Create a minimal JWT without k8s claims.
	tok, _ := jwt.NewBuilder().
		Issuer("test").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()

	privKey := newTestEnv(t).privateKey
	privJWK, _ := jwk.Import(privKey)
	_ = privJWK.Set(jwk.KeyIDKey, "test-key-1")
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privJWK))

	id, err := p.ValidateWorkload(ctx, string(signed), "k8s-sa")
	if err != nil {
		t.Fatalf("ValidateWorkload: %v", err)
	}

	if id.TrustDomain != "dev.local" {
		t.Errorf("TrustDomain = %q, want dev.local", id.TrustDomain)
	}
	// Without sub claim, default workload name should be used.
	if id.Claims["namespace"] != "default" {
		t.Errorf("Claims[namespace] = %v, want default", id.Claims["namespace"])
	}
}

func TestValidateWorkload_DevMode_WithSubject(t *testing.T) {
	ctx := context.Background()

	p, err := New(ctx, nil, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tok, _ := jwt.NewBuilder().
		Subject("system:serviceaccount:kube-system:admin").
		Issuer("test").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()

	privKey := newTestEnv(t).privateKey
	privJWK, _ := jwk.Import(privKey)
	_ = privJWK.Set(jwk.KeyIDKey, "test-key-1")
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privJWK))

	id, err := p.ValidateWorkload(ctx, string(signed), "k8s-sa")
	if err != nil {
		t.Fatalf("ValidateWorkload: %v", err)
	}

	// With sub but no k8s SA claim, the SA should fall back to the sub.
	sa, _ := id.Claims["serviceaccount"].(string)
	if sa != "system:serviceaccount:kube-system:admin" {
		t.Errorf("Claims[serviceaccount] = %q", sa)
	}
}

func TestClaimString_FlatKey(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_ = tok.Set("namespace", "my-ns")

	got := claimString(tok, "namespace")
	if got != "my-ns" {
		t.Errorf("claimString(flatKey) = %q, want my-ns", got)
	}
}

func TestClaimString_NestedPath(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_ = tok.Set("kubernetes.io", map[string]interface{}{
		"namespace": "nested-ns",
	})

	got := claimString(tok, "namespace", "kubernetes.io", "namespace")
	if got != "nested-ns" {
		t.Errorf("claimString(nested) = %q, want nested-ns", got)
	}
}

func TestClaimString_NonStringNested(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_ = tok.Set("kubernetes.io", map[string]interface{}{
		"namespace": 42, // not a string
	})

	got := claimString(tok, "", "kubernetes.io", "namespace")
	if got != "" {
		t.Errorf("claimString(non-string) = %q, want empty", got)
	}
}

func TestClaimString_MissingPath(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_ = tok.Set("kubernetes.io", map[string]interface{}{
		"namespace": "ns",
	})

	got := claimString(tok, "", "kubernetes.io", "nonexistent")
	if got != "" {
		t.Errorf("claimString(missing) = %q, want empty", got)
	}
}

func TestClaimString_EmptyFlatKey(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	got := claimString(tok, "")
	if got != "" {
		t.Errorf("claimString(empty) = %q, want empty", got)
	}
}

func TestClaimString_NonMapNested(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_ = tok.Set("kubernetes.io", "a-string-value")

	// When the top-level claim is a string (not a map), the nested path
	// traversal fails at the first key, and val remains the original string.
	// The function then finds val is a string and returns it.
	got := claimString(tok, "", "kubernetes.io", "namespace")
	if got != "a-string-value" {
		t.Errorf("claimString(non-map) = %q, want a-string-value", got)
	}
}

func TestClaimString_FlatKeyNonString(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_ = tok.Set("mykey", 123)

	got := claimString(tok, "mykey")
	if got != "" {
		t.Errorf("claimString(flat non-string) = %q, want empty", got)
	}
}

func TestClaimString_DeepNestedPath(t *testing.T) {
	tok, _ := jwt.NewBuilder().Build()
	_ = tok.Set("kubernetes.io", map[string]interface{}{
		"serviceaccount": map[string]interface{}{
			"name": "deep-sa",
		},
	})

	got := claimString(tok, "", "kubernetes.io", "serviceaccount", "name")
	if got != "deep-sa" {
		t.Errorf("claimString(deep-nested) = %q, want deep-sa", got)
	}
}
