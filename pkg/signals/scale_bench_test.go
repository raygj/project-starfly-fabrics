//go:build stress

package signals

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkRevocationIndex_IsRevoked_5M validates O(1) lookup at 5M entries.
func BenchmarkRevocationIndex_IsRevoked_5M(b *testing.B) {
	benchRevocationLookup(b, 5_000_000)
}

// BenchmarkRevocationIndex_IsRevoked_10M validates O(1) lookup at 10M entries.
func BenchmarkRevocationIndex_IsRevoked_10M(b *testing.B) {
	benchRevocationLookup(b, 10_000_000)
}

// BenchmarkRevocationIndex_Revoke_Contention measures revocation under
// concurrent write pressure.
func BenchmarkRevocationIndex_Revoke_Contention(b *testing.B) {
	idx := NewRevocationIndex()
	ctx := context.Background()
	exp := time.Now().Add(1 * time.Hour)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			id := fmt.Sprintf("wimse://example.com/workload/concurrent-%d-%d", b.N, i)
			_ = idx.Revoke(ctx, id, "contention-bench", exp)
			i++
		}
	})
}

// BenchmarkRevocationIndex_IsRevoked_Concurrent measures concurrent read
// throughput at 1M entries.
func BenchmarkRevocationIndex_IsRevoked_Concurrent(b *testing.B) {
	idx := NewRevocationIndex()
	ctx := context.Background()
	exp := time.Now().Add(1 * time.Hour)

	for i := 0; i < 1_000_000; i++ {
		_ = idx.Revoke(ctx, fmt.Sprintf("wimse://example.com/workload/%d", i), "preload", exp)
	}

	target := "wimse://example.com/workload/500000"

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			entry, err := idx.IsRevoked(ctx, target)
			if err != nil {
				b.Fatalf("lookup: %v", err)
			}
			if entry == nil {
				b.Fatal("expected entry")
			}
		}
	})
}
