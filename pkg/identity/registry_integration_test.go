package identity_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
	"github.com/starfly-fabrics/starfly/pkg/identity"
)

// ── Mock providers for integration test ─────────────────────────────

// routingProvider records which credType it was called with and returns
// a WorkloadIdentity tagged with its name.
type routingProvider struct {
	name     string
	credType string
}

func (p *routingProvider) ValidateWorkload(_ context.Context, _ string, credType string) (*core.WorkloadIdentity, error) {
	if credType != p.credType {
		return nil, errors.New("unsupported credential type: " + credType)
	}
	return &core.WorkloadIdentity{
		ID:          "wimse://example.com/" + p.name,
		TrustDomain: "example.com",
		Attestation: &core.AttestationEvidence{Method: credType},
		Claims:      map[string]interface{}{"provider": p.name},
	}, nil
}

type mockPolicy struct{}

func (m *mockPolicy) Evaluate(_ context.Context, _ *core.PolicyInput) (*core.PolicyDecision, error) {
	return &core.PolicyDecision{Allowed: true, Claims: map[string]interface{}{}}, nil
}

func (m *mockPolicy) LoadBundle(_ context.Context, _ string) error { return nil }

type mockAuditor struct{}

func (m *mockAuditor) Log(_ context.Context, _ *core.AuditEvent) error { return nil }

// ── Integration tests ───────────────────────────────────────────────

// TestRegistryExchange_SPIFFERouting verifies that an exchange with
// subject_token_type=urn:starfly:token-type:spiffe-svid routes to the
// SPIFFE provider through the registry.
func TestRegistryExchange_SPIFFERouting(t *testing.T) {
	reg := identity.NewRegistry()
	reg.Register("k8s-sa", &routingProvider{name: "k8s", credType: "k8s-sa"})
	reg.Register("spiffe-svid", &routingProvider{name: "spiffe", credType: "spiffe-svid"})
	reg.Register("oidc", &routingProvider{name: "oidc", credType: "oidc"})

	engine, err := exchange.New(reg, &mockPolicy{}, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "spiffe-jwt-svid-token",
		SubjectTokenType: "urn:starfly:token-type:spiffe-svid",
		Audience:         "https://api.target.example.com",
	})
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}

// TestRegistryExchange_OIDCRouting verifies OIDC token type routing.
func TestRegistryExchange_OIDCRouting(t *testing.T) {
	reg := identity.NewRegistry()
	reg.Register("k8s-sa", &routingProvider{name: "k8s", credType: "k8s-sa"})
	reg.Register("spiffe-svid", &routingProvider{name: "spiffe", credType: "spiffe-svid"})
	reg.Register("oidc", &routingProvider{name: "oidc", credType: "oidc"})

	engine, err := exchange.New(reg, &mockPolicy{}, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "oidc-id-token",
		SubjectTokenType: "urn:starfly:token-type:oidc",
		Audience:         "https://api.target.example.com",
	})
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}

// TestRegistryExchange_JWTBackwardCompat verifies that the bare JWT token type
// still routes to the K8s SA provider (ADR-0006 backward compatibility).
func TestRegistryExchange_JWTBackwardCompat(t *testing.T) {
	reg := identity.NewRegistry()
	reg.Register("k8s-sa", &routingProvider{name: "k8s", credType: "k8s-sa"})
	reg.Register("spiffe-svid", &routingProvider{name: "spiffe", credType: "spiffe-svid"})
	reg.Register("oidc", &routingProvider{name: "oidc", credType: "oidc"})

	engine, err := exchange.New(reg, &mockPolicy{}, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "k8s-sa-jwt",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
		Audience:         "https://api.target.example.com",
	})
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
}

// TestRegistryExchange_UnknownTokenType verifies that an unknown token type
// is rejected before reaching the registry.
func TestRegistryExchange_UnknownTokenType(t *testing.T) {
	reg := identity.NewRegistry()
	reg.Register("k8s-sa", &routingProvider{name: "k8s", credType: "k8s-sa"})

	engine, err := exchange.New(reg, &mockPolicy{}, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "some-token",
		SubjectTokenType: "urn:starfly:token-type:unknown",
		Audience:         "https://api.target.example.com",
	})
	if err == nil {
		t.Fatal("expected error for unknown token type")
	}
	if !errors.Is(err, exchange.ErrUnsupportedToken) {
		t.Fatalf("expected ErrUnsupportedToken, got: %v", err)
	}
}

// TestRegistryExchange_MissingProvider verifies that the registry returns
// a clear error when no provider is registered for a valid token type.
func TestRegistryExchange_MissingProvider(t *testing.T) {
	reg := identity.NewRegistry()
	reg.Register("k8s-sa", &routingProvider{name: "k8s", credType: "k8s-sa"})
	// No SPIFFE provider registered.

	engine, err := exchange.New(reg, &mockPolicy{}, &mockAuditor{})
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	_, err = engine.Exchange(context.Background(), &core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     "spiffe-token",
		SubjectTokenType: "urn:starfly:token-type:spiffe-svid",
		Audience:         "https://api.target.example.com",
	})
	if err == nil {
		t.Fatal("expected error for unregistered provider")
	}
	if !strings.Contains(err.Error(), "no provider registered") {
		t.Fatalf("expected 'no provider registered' error, got: %v", err)
	}
}
