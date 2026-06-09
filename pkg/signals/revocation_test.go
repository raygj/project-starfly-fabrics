package signals

import (
	"context"
	"testing"
	"time"
)

func TestRevocationIndex_RevokeAndCheck(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	subjectID := "wimse://example.com/ns/default/sa/app"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Not revoked initially.
	entry, err := idx.IsRevoked(ctx, subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry != nil {
		t.Error("expected not revoked before Revoke call")
	}

	// Revoke.
	err = idx.Revoke(ctx, subjectID, "session-revoked", expiresAt)
	if err != nil {
		t.Fatalf("Revoke error: %v", err)
	}

	// Now revoked.
	entry, err = idx.IsRevoked(ctx, subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry == nil {
		t.Error("expected revoked after Revoke call")
	}
	if entry != nil && entry.Reason != "session-revoked" {
		t.Errorf("Reason = %q, want %q", entry.Reason, "session-revoked")
	}

	// Different subject not revoked.
	entry, err = idx.IsRevoked(ctx, "wimse://example.com/ns/other/sa/other")
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry != nil {
		t.Error("expected different subject to not be revoked")
	}
}

func TestRevocationIndex_EmptySubjectID(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	err := idx.Revoke(ctx, "", "test", time.Now().Add(1*time.Hour))
	if err == nil {
		t.Error("expected error for empty subjectID")
	}
}

func TestRevocationIndex_ExpiredEntry(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	subjectID := "wimse://example.com/ns/default/sa/expired"

	// Revoke with an already-expired time.
	err := idx.Revoke(ctx, subjectID, "test", time.Now().Add(-1*time.Second))
	if err != nil {
		t.Fatalf("Revoke error: %v", err)
	}

	// Should not be considered revoked because expiry has passed.
	entry, err := idx.IsRevoked(ctx, subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry != nil {
		t.Error("expected expired revocation entry to not be considered revoked")
	}
}

func TestRevocationIndex_ZeroExpiry(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	subjectID := "wimse://example.com/ns/default/sa/permanent"

	// Revoke with zero expiry (permanent revocation).
	err := idx.Revoke(ctx, subjectID, "permanent", time.Time{})
	if err != nil {
		t.Fatalf("Revoke error: %v", err)
	}

	// Should be revoked (zero expiry = never expires).
	entry, err := idx.IsRevoked(ctx, subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry == nil {
		t.Error("expected permanent revocation to be considered revoked")
	}
}

func TestRevocationIndex_UpdateEntry(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	subjectID := "wimse://example.com/ns/default/sa/updated"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Revoke with one reason.
	err := idx.Revoke(ctx, subjectID, "reason-1", expiresAt)
	if err != nil {
		t.Fatalf("Revoke error: %v", err)
	}

	// Update with new reason.
	err = idx.Revoke(ctx, subjectID, "reason-2", expiresAt)
	if err != nil {
		t.Fatalf("Revoke update error: %v", err)
	}

	// Should still be revoked (and count is still 1).
	entry, err := idx.IsRevoked(ctx, subjectID)
	if err != nil {
		t.Fatalf("IsRevoked error: %v", err)
	}
	if entry == nil {
		t.Error("expected revoked after update")
	}
	if entry != nil && entry.Reason != "reason-2" {
		t.Errorf("Reason = %q, want %q (should reflect latest revocation)", entry.Reason, "reason-2")
	}
	if idx.Len() != 1 {
		t.Errorf("Len = %d, want 1", idx.Len())
	}
}

func TestRevocationIndex_Cleanup(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	// Add mix of expired and valid entries.
	_ = idx.Revoke(ctx, "expired-1", "test", time.Now().Add(-1*time.Hour))
	_ = idx.Revoke(ctx, "expired-2", "test", time.Now().Add(-30*time.Minute))
	_ = idx.Revoke(ctx, "valid-1", "test", time.Now().Add(1*time.Hour))
	_ = idx.Revoke(ctx, "permanent", "test", time.Time{}) // zero = never expires

	if idx.Len() != 4 {
		t.Fatalf("Len before cleanup = %d, want 4", idx.Len())
	}

	removed, err := idx.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}
	if removed != 2 {
		t.Errorf("Cleanup removed = %d, want 2", removed)
	}
	if idx.Len() != 2 {
		t.Errorf("Len after cleanup = %d, want 2", idx.Len())
	}

	// valid-1 should still be revoked.
	entry, _ := idx.IsRevoked(ctx, "valid-1")
	if entry == nil {
		t.Error("valid-1 should still be revoked")
	}

	// permanent should still be revoked.
	entry, _ = idx.IsRevoked(ctx, "permanent")
	if entry == nil {
		t.Error("permanent should still be revoked")
	}
}

func TestRevocationIndex_ConcurrentAccess(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	done := make(chan struct{})

	// Concurrent writers.
	go func() {
		for i := 0; i < 100; i++ {
			_ = idx.Revoke(ctx, "concurrent-subject", "test", time.Now().Add(1*time.Hour))
		}
		done <- struct{}{}
	}()

	// Concurrent readers.
	go func() {
		for i := 0; i < 100; i++ {
			_, _ = idx.IsRevoked(ctx, "concurrent-subject")
		}
		done <- struct{}{}
	}()

	// Concurrent cleanup.
	go func() {
		for i := 0; i < 10; i++ {
			_, _ = idx.Cleanup(ctx)
		}
		done <- struct{}{}
	}()

	<-done
	<-done
	<-done
}

func TestRevocationIndex_ExportImport_RoundTrip(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	// Populate with entries.
	_ = idx.Revoke(ctx, "wimse://example.com/sa/app-1", "session-revoked", time.Now().Add(1*time.Hour))
	_ = idx.Revoke(ctx, "wimse://example.com/sa/app-2", "credential-compromised", time.Now().Add(2*time.Hour))
	_ = idx.Revoke(ctx, "wimse://example.com/sa/app-3", "admin-action", time.Time{}) // permanent

	data, err := idx.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Import into a fresh index.
	idx2 := NewRevocationIndex()
	if err := idx2.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Verify all entries are present.
	if idx2.Len() != 3 {
		t.Fatalf("Len after import = %d, want 3", idx2.Len())
	}

	entry, _ := idx2.IsRevoked(ctx, "wimse://example.com/sa/app-1")
	if entry == nil {
		t.Error("app-1 should be revoked after import")
	}
	if entry != nil && entry.Reason != "session-revoked" {
		t.Errorf("app-1 reason = %q, want session-revoked", entry.Reason)
	}

	entry, _ = idx2.IsRevoked(ctx, "wimse://example.com/sa/app-3")
	if entry == nil {
		t.Error("app-3 (permanent) should be revoked after import")
	}
}

func TestRevocationIndex_Import_IntegrityCheck(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	_ = idx.Revoke(ctx, "wimse://example.com/sa/app-1", "test", time.Now().Add(1*time.Hour))

	data, err := idx.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Tamper with the data.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	// Flip a byte in the middle of the payload.
	tampered[len(tampered)/2] ^= 0xFF

	idx2 := NewRevocationIndex()
	err = idx2.Import(tampered)
	if err == nil {
		t.Fatal("expected error for tampered data")
	}
}

func TestRevocationIndex_Import_Merge(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	// Pre-populate with one entry.
	_ = idx.Revoke(ctx, "wimse://example.com/sa/existing", "existing-reason", time.Now().Add(1*time.Hour))

	// Create export from different index with different entries.
	other := NewRevocationIndex()
	_ = other.Revoke(ctx, "wimse://example.com/sa/imported", "imported-reason", time.Now().Add(1*time.Hour))
	_ = other.Revoke(ctx, "wimse://example.com/sa/existing", "should-not-overwrite", time.Now().Add(2*time.Hour))
	data, err := other.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Import — should merge additively.
	if err := idx.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Should have 2 entries.
	if idx.Len() != 2 {
		t.Fatalf("Len after merge = %d, want 2", idx.Len())
	}

	// Existing entry should NOT be overwritten.
	entry, _ := idx.IsRevoked(ctx, "wimse://example.com/sa/existing")
	if entry == nil {
		t.Fatal("existing entry missing after import")
	}
	if entry.Reason != "existing-reason" {
		t.Errorf("existing entry reason = %q, want existing-reason (should not be overwritten)", entry.Reason)
	}

	// Imported entry should be present.
	entry, _ = idx.IsRevoked(ctx, "wimse://example.com/sa/imported")
	if entry == nil {
		t.Fatal("imported entry missing after import")
	}
}

func TestRevocationIndex_Export_Empty(t *testing.T) {
	idx := NewRevocationIndex()

	data, err := idx.Export()
	if err != nil {
		t.Fatalf("Export empty index: %v", err)
	}

	idx2 := NewRevocationIndex()
	if err := idx2.Import(data); err != nil {
		t.Fatalf("Import empty export: %v", err)
	}

	if idx2.Len() != 0 {
		t.Errorf("Len after importing empty = %d, want 0", idx2.Len())
	}
}

func TestRevocationIndex_Hash_Stability(t *testing.T) {
	ctx := context.Background()

	// Build a source index and export it so both targets have identical entries
	// (including RevokedAt timestamps set by Revoke).
	source := NewRevocationIndex()
	_ = source.Revoke(ctx, "b-subject", "reason", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	_ = source.Revoke(ctx, "a-subject", "reason", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	data, err := source.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Import the same snapshot into two fresh indexes.
	idx1 := NewRevocationIndex()
	if err := idx1.Import(data); err != nil {
		t.Fatalf("Import idx1: %v", err)
	}

	idx2 := NewRevocationIndex()
	if err := idx2.Import(data); err != nil {
		t.Fatalf("Import idx2: %v", err)
	}

	if idx1.Hash() != idx2.Hash() {
		t.Errorf("hashes differ for indexes with identical entries:\n  idx1: %s\n  idx2: %s", idx1.Hash(), idx2.Hash())
	}

	// Also verify that calling Hash multiple times on the same index is stable.
	h1 := source.Hash()
	h2 := source.Hash()
	if h1 != h2 {
		t.Errorf("hash not stable across calls: %s vs %s", h1, h2)
	}
}

func TestRevocationIndex_Hash_Empty(t *testing.T) {
	idx := NewRevocationIndex()
	h := idx.Hash()
	if h == "" {
		t.Error("hash of empty index should not be empty string")
	}
}

func TestRevocationIndex_Export_ExcludesExpired(t *testing.T) {
	idx := NewRevocationIndex()
	ctx := context.Background()

	// Add one active and one expired entry.
	_ = idx.Revoke(ctx, "active-1", "active", time.Now().Add(1*time.Hour))
	_ = idx.Revoke(ctx, "expired-1", "expired", time.Now().Add(-1*time.Hour))

	data, err := idx.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Import into fresh index and verify only active entry was exported.
	idx2 := NewRevocationIndex()
	if err := idx2.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}

	if idx2.Len() != 1 {
		t.Fatalf("expected 1 entry after import (expired should be excluded), got %d", idx2.Len())
	}

	entry, _ := idx2.IsRevoked(ctx, "active-1")
	if entry == nil {
		t.Error("active-1 should be present after import")
	}

	entry, _ = idx2.IsRevoked(ctx, "expired-1")
	if entry != nil {
		t.Error("expired-1 should NOT be present after import (should be excluded from export)")
	}
}

func TestRevocationIndex_CleanupBeforeHash_Convergence(t *testing.T) {
	ctx := context.Background()

	// Build a common snapshot with only active entries.
	source := NewRevocationIndex()
	_ = source.Revoke(ctx, "active-a", "reason", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	_ = source.Revoke(ctx, "active-b", "reason", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))

	data, err := source.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// idx1: import active entries only.
	idx1 := NewRevocationIndex()
	if err := idx1.Import(data); err != nil {
		t.Fatalf("Import idx1: %v", err)
	}

	// idx2: import active entries, then add an expired entry.
	idx2 := NewRevocationIndex()
	if err := idx2.Import(data); err != nil {
		t.Fatalf("Import idx2: %v", err)
	}
	_ = idx2.Revoke(ctx, "stale-entry", "gone", time.Now().Add(-1*time.Hour))

	// Before cleanup, hashes should differ because idx2 has the stale entry.
	if idx1.Hash() == idx2.Hash() {
		t.Fatal("hashes should differ before cleanup (idx2 has stale entry)")
	}

	// After cleanup, hashes should converge.
	if _, err := idx2.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if idx1.Hash() != idx2.Hash() {
		t.Errorf("hashes should match after cleanup:\n  idx1: %s\n  idx2: %s", idx1.Hash(), idx2.Hash())
	}
}

func TestRevocationIndex_Import_BadJSON(t *testing.T) {
	idx := NewRevocationIndex()
	err := idx.Import([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestRevocationIndex_Import_HashMismatch(t *testing.T) {
	data := []byte(`{"entries":[],"count":0,"hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`)
	idx := NewRevocationIndex()
	err := idx.Import(data)
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
}
