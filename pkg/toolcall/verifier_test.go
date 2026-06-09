package toolcall

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// buildDevToken mints a minimal JWT for devMode tests (no signature required).
func buildDevToken(t testing.TB, fn func(*jwt.Builder) *jwt.Builder) string {
	t.Helper()
	b := jwt.NewBuilder().
		Subject("spiffe://example.com/agent").
		Issuer("https://starfly.test").
		Audience([]string{"mcp://tool-001"}).
		Expiration(time.Now().Add(time.Hour))
	b = fn(b)
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build dev token: %v", err)
	}
	// Sign with a throwaway key — devMode skips verification.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		t.Fatalf("sign dev token: %v", err)
	}
	return string(signed)
}

func newDevVerifier(reg *Registry) *DefaultVerifier {
	return NewVerifier(VerifierConfig{DevMode: true, Registry: reg})
}

func TestVerifierMissingToken(t *testing.T) {
	v := newDevVerifier(nil)
	_, err := v.Verify(context.Background(), &ToolCallRequest{Protocol: ProtocolMCP})
	if err != ErrMissingToken {
		t.Errorf("expected ErrMissingToken, got %v", err)
	}
}

func TestVerifierInvalidJWT(t *testing.T) {
	v := newDevVerifier(nil)
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		Token:    "not.a.jwt",
	})
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestVerifierToolNotRegistered(t *testing.T) {
	reg := NewRegistry()
	v := newDevVerifier(reg)
	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder { return b })
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "nonexistent",
		Token:    tok,
	})
	if err == nil {
		t.Error("expected error for unregistered tool")
	}
}

func TestVerifierAudienceMismatch(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:      "tool-001",
		ResourceURI: "mcp://tool-001",
		Protocols:   []Protocol{ProtocolMCP},
	})
	v := newDevVerifier(reg)

	// Token has audience "mcp://wrong-tool".
	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Audience([]string{"mcp://wrong-tool"})
	})
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "tool-001",
		Token:    tok,
	})
	if err == nil {
		t.Error("expected audience mismatch error")
	}
}

func TestVerifierCapabilityDenied(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:               "tool-001",
		ResourceURI:          "mcp://tool-001",
		Protocols:            []Protocol{ProtocolMCP},
		RequiredCapabilities: []string{"read", "write"},
	})
	v := newDevVerifier(reg)

	// Token only has "read".
	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Claim("caps", []string{"read"})
	})
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "tool-001",
		Token:    tok,
	})
	if err == nil {
		t.Error("expected capability denied error")
	}
}

func TestVerifierBlastRadiusExceeded(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:         "tool-001",
		ResourceURI:    "mcp://tool-001",
		Protocols:      []Protocol{ProtocolMCP},
		MaxBlastRadius: "namespace:dev",
	})
	v := newDevVerifier(reg)

	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Claim("blast_radius", "namespace:prod")
	})
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "tool-001",
		Token:    tok,
	})
	if err == nil {
		t.Error("expected blast radius exceeded error")
	}
}

func TestVerifierProtocolDenied(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:      "tool-001",
		ResourceURI: "mcp://tool-001",
		Protocols:   []Protocol{ProtocolMCP},
	})
	v := newDevVerifier(reg)

	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder { return b })
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolHTTP, // tool only allows MCP
		ToolID:   "tool-001",
		Token:    tok,
	})
	if err == nil {
		t.Error("expected protocol denied error")
	}
}

func TestVerifierRevoked(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:      "tool-001",
		ResourceURI: "mcp://tool-001",
		Protocols:   []Protocol{ProtocolMCP},
	})
	revIdx := &stubRevocationIndex{revoked: "spiffe://example.com/agent", reason: "terminated"}
	v := NewVerifier(VerifierConfig{
		DevMode:           true,
		Registry:          reg,
		RevocationChecker: revIdx,
	})

	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder { return b })
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "tool-001",
		Token:    tok,
	})
	if err == nil {
		t.Error("expected revocation error")
	}
}

func TestVerifierSuccess(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:               "tool-001",
		ResourceURI:          "mcp://tool-001",
		Protocols:            []Protocol{ProtocolMCP},
		RequiredCapabilities: []string{"read"},
	})
	v := newDevVerifier(reg)

	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Claim("caps", []string{"read"})
	})
	identity, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "tool-001",
		Token:    tok,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Subject != "spiffe://example.com/agent" {
		t.Errorf("Subject: %q", identity.Subject)
	}
	if identity.Protocol != ProtocolMCP {
		t.Errorf("Protocol: %q", identity.Protocol)
	}
	if identity.ToolID != "tool-001" {
		t.Errorf("ToolID: %q", identity.ToolID)
	}
}

func TestVerifierExecBindingRequired(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:            "tool-exec",
		ResourceURI:       "mcp://tool-exec",
		Protocols:         []Protocol{ProtocolMCP},
		RequiresExecution: true,
	})
	v := newDevVerifier(reg)

	// Token has no execution claims.
	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Audience([]string{"mcp://tool-exec"})
	})
	_, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "tool-exec",
		Token:    tok,
	})
	if err == nil {
		t.Error("expected exec binding required error")
	}
}

func TestVerifierNoRegistrySkipsToolChecks(t *testing.T) {
	// Without a registry, tool-level checks are skipped — useful for raw verification.
	v := NewVerifier(VerifierConfig{DevMode: true})
	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder { return b })
	identity, err := v.Verify(context.Background(), &ToolCallRequest{
		Protocol: ProtocolMCP,
		ToolID:   "any-tool",
		Token:    tok,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.Subject == "" {
		t.Error("Subject should be set")
	}
}

// ── Benchmarks ─────────────────────────────────────────────────────────────

func BenchmarkVerifierSuccess(b *testing.B) {
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:      "bench-tool",
		ResourceURI: "mcp://bench-tool",
		Protocols:   []Protocol{ProtocolMCP},
	})
	v := newDevVerifier(reg)

	tok := buildDevToken(b, func(bld *jwt.Builder) *jwt.Builder {
		return bld.Audience([]string{"mcp://bench-tool"})
	})
	req := &ToolCallRequest{Protocol: ProtocolMCP, ToolID: "bench-tool", Token: tok}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// ── Stubs ────────────────────────────────────────────────────────────────────

type stubRevocationIndex struct {
	revoked string
	reason  string
}

func (s *stubRevocationIndex) IsRevoked(_ context.Context, subject string) (*core.RevocationEntry, error) {
	if subject == s.revoked {
		return &core.RevocationEntry{SubjectID: subject, Reason: s.reason}, nil
	}
	return nil, nil
}

func (s *stubRevocationIndex) Revoke(_ context.Context, _ string, _ string, _ time.Time) error {
	return nil
}
func (s *stubRevocationIndex) Cleanup(_ context.Context) (int, error) { return 0, nil }
func (s *stubRevocationIndex) Hash() string                           { return "" }
func (s *stubRevocationIndex) Export() ([]byte, error)                { return nil, nil }
func (s *stubRevocationIndex) Import(_ []byte) error                  { return nil }
