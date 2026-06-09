package identity

import (
	"context"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// BenchmarkJWKSCacheHit measures ValidateWorkload with a pre-warmed JWKS
// cache (httptest server), simulating the hot-path identity check.
func BenchmarkJWKSCacheHit(b *testing.B) {
	te := newTestEnv(b)
	ctx := context.Background()

	provider, err := New(ctx, []core.TrustDomain{te.td}, false)
	if err != nil {
		b.Fatalf("creating provider: %v", err)
	}

	// Mint a valid token once; reuse across iterations.
	token := string(te.mintToken(b))

	// Warm the cache with an initial call.
	if _, err := provider.ValidateWorkload(ctx, token, "k8s-sa"); err != nil {
		b.Fatalf("warming cache: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := provider.ValidateWorkload(ctx, token, "k8s-sa")
		if err != nil {
			b.Fatalf("ValidateWorkload: %v", err)
		}
	}
}
