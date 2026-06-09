package exchange

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// BenchmarkExchangeE2E_Concurrent measures exchange throughput under GOMAXPROCS parallel workers.
func BenchmarkExchangeE2E_Concurrent(b *testing.B) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		b.Fatalf("creating engine: %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := validRequest()
			_, err := engine.Exchange(ctx, req)
			if err != nil {
				b.Fatalf("exchange: %v", err)
			}
		}
	})
}

// BenchmarkExchange_ExecutionScoped_Concurrent measures execution-scoped exchange under contention.
func BenchmarkExchange_ExecutionScoped_Concurrent(b *testing.B) {
	engine, err := New(goodIdentity(), allowPolicy(nil), &mockAuditor{})
	if err != nil {
		b.Fatalf("creating engine: %v", err)
	}
	ctx := context.Background()

	var counter atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := counter.Add(1)
			req := validRequest()
			req.ExecutionScope = &core.ExecutionScope{
				Method:      "POST",
				URI:         "https://api.example.com/transfer",
				PayloadHash: "sha256-abc123",
				Nonce:       fmt.Sprintf("concurrent-nonce-%d", n),
			}
			_, err := engine.Exchange(ctx, req)
			if err != nil {
				b.Fatalf("exchange: %v", err)
			}
		}
	})
}
