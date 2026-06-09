package exchange

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// BenchmarkExchangeE2E measures the full exchange hot path with mock
// collaborators: identity validation → policy evaluation → JWT build →
// RS256 sign → audit log.
func BenchmarkExchangeE2E(b *testing.B) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		b.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_, err := engine.Exchange(ctx, req)
		if err != nil {
			b.Fatalf("exchange: %v", err)
		}
	}
}

// BenchmarkJWTMint measures isolated JWT build + RS256 sign with a fresh
// RSA-2048 key, matching the engine's signing spec.
func BenchmarkJWTMint(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generating RSA key: %v", err)
	}

	key, err := jwk.Import(privKey)
	if err != nil {
		b.Fatalf("importing key: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, "bench-key-1"); err != nil {
		b.Fatalf("setting kid: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		b.Fatalf("setting alg: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		token, err := jwt.NewBuilder().
			Subject("wimse://production.example.com/ns/default/sa/my-app").
			Issuer("starfly").
			Audience([]string{"https://api.target.example.com"}).
			Build()
		if err != nil {
			b.Fatalf("building JWT: %v", err)
		}
		if err := token.Set("td", "production.example.com"); err != nil {
			b.Fatalf("setting td: %v", err)
		}
		_, err = jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
		if err != nil {
			b.Fatalf("signing JWT: %v", err)
		}
	}
}

// BenchmarkExchange_ExecutionScoped measures overhead of execution-scoped tokens.
func BenchmarkExchange_ExecutionScoped(b *testing.B) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		b.Fatalf("creating engine: %v", err)
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := validRequest()
		req.ExecutionScope = &core.ExecutionScope{
			Method:      "POST",
			URI:         "https://api.example.com/transfer",
			PayloadHash: "sha256-abc123",
			Nonce:       fmt.Sprintf("bench-nonce-%d", i),
		}
		_, err := engine.Exchange(ctx, req)
		if err != nil {
			b.Fatalf("exchange: %v", err)
		}
	}
}

// BenchmarkExchange_Delegation measures delegation chain validation overhead.
func BenchmarkExchange_Delegation(b *testing.B) {
	policyClaims := map[string]interface{}{
		"caps":         []interface{}{"read"},
		"blast_radius": "namespace",
	}
	engine, err := New(goodIdentity(), allowPolicy(policyClaims), &mockAuditor{})
	if err != nil {
		b.Fatalf("creating engine: %v", err)
	}
	ctx := context.Background()

	// Pre-mint an actor token.
	now := time.Now().UTC()
	tok, err := jwt.NewBuilder().
		Subject("wimse://parent.example.com/agent/agent-a").
		Issuer("starfly").
		Audience([]string{"starfly"}).
		IssuedAt(now).
		Expiration(now.Add(10 * time.Minute)).
		Build()
	if err != nil {
		b.Fatalf("building actor token: %v", err)
	}
	for k, v := range map[string]interface{}{
		"delegation_depth": 99,
		"caps":             []interface{}{"read", "write", "list"},
		"blast_radius":     "cluster",
	} {
		if err := tok.Set(k, v); err != nil {
			b.Fatalf("setting %s: %v", k, err)
		}
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), engine.signKey))
	if err != nil {
		b.Fatalf("signing actor token: %v", err)
	}
	actorToken := string(signed)

	b.ResetTimer()
	for b.Loop() {
		req := validRequest()
		req.ActorToken = actorToken
		_, err := engine.Exchange(ctx, req)
		if err != nil {
			b.Fatalf("exchange: %v", err)
		}
	}
}

// BenchmarkBlastRadiusCheck measures the blast radius hierarchy comparison.
func BenchmarkBlastRadiusCheck(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		isBlastRadiusNarrowerOrEqual("namespace:trading", "cluster")
		isBlastRadiusNarrowerOrEqual("function", "fabric")
		isBlastRadiusNarrowerOrEqual("cluster", "namespace")
	}
}
