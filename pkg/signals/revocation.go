package signals

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const revocationTracerName = "github.com/starfly-fabrics/starfly/pkg/signals"

// InMemoryRevocationIndex implements core.RevocationIndex with an in-memory map.
// Thread-safe for concurrent read/write. Entries expire and are cleaned up
// by calling Cleanup periodically.
type InMemoryRevocationIndex struct {
	mu      sync.RWMutex
	entries map[string]*core.RevocationEntry
}

// NewRevocationIndex creates an empty in-memory revocation index.
func NewRevocationIndex() *InMemoryRevocationIndex {
	return &InMemoryRevocationIndex{
		entries: make(map[string]*core.RevocationEntry),
	}
}

// Revoke marks a subject as revoked. If the subject is already revoked,
// the entry is updated with the new reason and expiry.
func (idx *InMemoryRevocationIndex) Revoke(ctx context.Context, subjectID string, reason string, expiresAt time.Time) error {
	_, span := otel.Tracer(revocationTracerName).Start(ctx, "revocation.Revoke")
	defer span.End()

	if subjectID == "" {
		return fmt.Errorf("subjectID must not be empty")
	}

	span.SetAttributes(
		attribute.String("subject_id", subjectID),
		attribute.String("reason", reason),
	)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.entries[subjectID] = &core.RevocationEntry{
		SubjectID: subjectID,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}

	return nil
}

// IsRevoked checks whether a subject is currently revoked.
// Returns the RevocationEntry if revoked, nil if not revoked.
// Expired entries are treated as not revoked.
func (idx *InMemoryRevocationIndex) IsRevoked(ctx context.Context, subjectID string) (*core.RevocationEntry, error) {
	_, span := otel.Tracer(revocationTracerName).Start(ctx, "revocation.IsRevoked")
	defer span.End()

	span.SetAttributes(attribute.String("subject_id", subjectID))

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	entry, ok := idx.entries[subjectID]
	if !ok {
		span.SetAttributes(attribute.Bool("revoked", false))
		return nil, nil
	}

	// Check if the revocation entry has expired.
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		span.SetAttributes(attribute.Bool("revoked", false), attribute.Bool("expired", true))
		return nil, nil
	}

	span.SetAttributes(attribute.Bool("revoked", true))
	return entry, nil
}

// Cleanup removes expired revocation entries and returns the count removed.
func (idx *InMemoryRevocationIndex) Cleanup(ctx context.Context) (int, error) {
	_, span := otel.Tracer(revocationTracerName).Start(ctx, "revocation.Cleanup")
	defer span.End()

	idx.mu.Lock()
	defer idx.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, entry := range idx.entries {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(idx.entries, id)
			removed++
		}
	}

	span.SetAttributes(attribute.Int("removed", removed))
	return removed, nil
}

// Len returns the current number of revocation entries (for metrics/testing).
func (idx *InMemoryRevocationIndex) Len() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.entries)
}

// Export serializes the revocation index to a JSON byte slice.
// The output includes all entries and a SHA-256 integrity hash.
// Entries are sorted by SubjectID for hash stability.
func (idx *InMemoryRevocationIndex) Export() ([]byte, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	// Collect active (non-expired) entries sorted by SubjectID for deterministic hashing.
	now := time.Now()
	entries := make([]*core.RevocationEntry, 0, len(idx.entries))
	for _, e := range idx.entries {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			continue // skip expired entries
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SubjectID < entries[j].SubjectID
	})

	payload := core.RevocationSnapshot{
		Entries: entries,
		Count:   len(entries),
	}

	// Compute hash over sorted entries.
	entriesJSON, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("marshaling entries for hash: %w", err)
	}
	h := sha256.Sum256(entriesJSON)
	payload.Hash = fmt.Sprintf("sha256:%x", h)

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling revocation export: %w", err)
	}
	return data, nil
}

// Import deserializes a revocation export and merges entries into the index.
// Import is additive — it does not remove existing entries. This ensures
// entries that arrived via NATS since the last snapshot are preserved.
// The integrity hash is verified before loading.
func (idx *InMemoryRevocationIndex) Import(data []byte) error {
	var payload core.RevocationSnapshot
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshaling revocation import: %w", err)
	}

	// Verify integrity hash.
	entriesJSON, err := json.Marshal(payload.Entries)
	if err != nil {
		return fmt.Errorf("marshaling entries for hash verification: %w", err)
	}
	h := sha256.Sum256(entriesJSON)
	expectedHash := fmt.Sprintf("sha256:%x", h)
	if payload.Hash != expectedHash {
		return fmt.Errorf("integrity check failed: expected %s, got %s", expectedHash, payload.Hash)
	}

	// Merge entries (additive — existing entries are preserved).
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for _, e := range payload.Entries {
		if _, exists := idx.entries[e.SubjectID]; !exists {
			idx.entries[e.SubjectID] = e
		}
	}

	return nil
}

// Hash returns a SHA-256 hash of the current index state.
// Entries are sorted by SubjectID for deterministic output.
func (idx *InMemoryRevocationIndex) Hash() string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	entries := make([]*core.RevocationEntry, 0, len(idx.entries))
	for _, e := range idx.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SubjectID < entries[j].SubjectID
	})

	data, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}

