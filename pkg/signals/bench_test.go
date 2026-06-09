package signals

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// BenchmarkRevocationIndex_Revoke measures the cost of adding a revocation entry.
func BenchmarkRevocationIndex_Revoke(b *testing.B) {
	idx := NewRevocationIndex()
	ctx := context.Background()
	exp := time.Now().Add(1 * time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := idx.Revoke(ctx, fmt.Sprintf("wimse://example.com/workload/%d", i), "bench", exp)
		if err != nil {
			b.Fatalf("revoke: %v", err)
		}
	}
}

// BenchmarkRevocationIndex_IsRevoked_10K measures O(1) lookup with 10K entries.
func BenchmarkRevocationIndex_IsRevoked_10K(b *testing.B) {
	benchRevocationLookup(b, 10_000)
}

// BenchmarkRevocationIndex_IsRevoked_100K measures O(1) lookup with 100K entries.
func BenchmarkRevocationIndex_IsRevoked_100K(b *testing.B) {
	benchRevocationLookup(b, 100_000)
}

// BenchmarkRevocationIndex_IsRevoked_1M measures O(1) lookup with 1M entries.
func BenchmarkRevocationIndex_IsRevoked_1M(b *testing.B) {
	benchRevocationLookup(b, 1_000_000)
}

func benchRevocationLookup(b *testing.B, entries int) {
	b.Helper()
	idx := NewRevocationIndex()
	ctx := context.Background()
	exp := time.Now().Add(1 * time.Hour)

	for i := 0; i < entries; i++ {
		id := fmt.Sprintf("wimse://example.com/workload/%d", i)
		if err := idx.Revoke(ctx, id, "preload", exp); err != nil {
			b.Fatalf("preloading: %v", err)
		}
	}

	target := fmt.Sprintf("wimse://example.com/workload/%d", entries/2)

	b.ResetTimer()
	for b.Loop() {
		entry, err := idx.IsRevoked(ctx, target)
		if err != nil {
			b.Fatalf("lookup: %v", err)
		}
		if entry == nil {
			b.Fatal("expected entry to be revoked")
		}
	}
}

// BenchmarkRevocationIndex_IsRevoked_Miss measures lookup for non-existent entry.
func BenchmarkRevocationIndex_IsRevoked_Miss(b *testing.B) {
	idx := NewRevocationIndex()
	ctx := context.Background()
	exp := time.Now().Add(1 * time.Hour)

	for i := 0; i < 100_000; i++ {
		if err := idx.Revoke(ctx, fmt.Sprintf("wimse://example.com/workload/%d", i), "preload", exp); err != nil {
			b.Fatalf("preloading: %v", err)
		}
	}

	b.ResetTimer()
	for b.Loop() {
		entry, err := idx.IsRevoked(ctx, "wimse://nonexistent.com/missing")
		if err != nil {
			b.Fatalf("lookup: %v", err)
		}
		if entry != nil {
			b.Fatal("expected nil for non-existent entry")
		}
	}
}

// BenchmarkTransmitter_SignSET measures SET signing cost.
func BenchmarkTransmitter_SignSET(b *testing.B) {
	tx, err := NewTransmitter(
		WithTransmitterIssuer("bench-unit"),
	)
	if err != nil {
		b.Fatalf("creating transmitter: %v", err)
	}

	event := &core.SecurityEvent{
		Issuer:   "bench-unit",
		JTI:      "bench-jti",
		IssuedAt: time.Now().Unix(),
		Audience: "target",
		Events: map[string]map[string]interface{}{
			EventSessionRevoked: {"reason": "bench"},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := tx.signSET(event)
		if err != nil {
			b.Fatalf("sign SET: %v", err)
		}
	}
}
