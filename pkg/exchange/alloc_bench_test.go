package exchange

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// BenchmarkExchangeE2E_Allocs tracks allocation regression for the full
// exchange path: identity validation → policy evaluation → JWT build →
// RS256 sign → audit log.
func BenchmarkExchangeE2E_Allocs(b *testing.B) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		b.Fatalf("creating engine: %v", err)
	}

	req := validRequest()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := engine.Exchange(ctx, req)
		if err != nil {
			b.Fatalf("exchange: %v", err)
		}
	}
}

// BenchmarkJWTMint_Allocs tracks allocation regression for JWT build +
// RS256 sign with a fresh RSA-2048 key.
func BenchmarkJWTMint_Allocs(b *testing.B) {
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

	b.ReportAllocs()
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

// BenchmarkExchange_ExecutionScoped_Allocs tracks allocation regression for
// execution-scoped token exchange.
func BenchmarkExchange_ExecutionScoped_Allocs(b *testing.B) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		b.Fatalf("creating engine: %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
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
