package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ECTLedgerEntry is a single record in the ECT audit ledger.
// Each entry includes a monotonic sequence number and a hash chain
// linking it to the previous entry, per draft-nennemann-wimse-ect-00 Section 7.
type ECTLedgerEntry struct {
	// Sequence is the monotonic, gap-free sequence number (starts at 1).
	Sequence uint64 `json:"seq"`

	// JTI is the ECT's unique task identifier (used as the index key).
	JTI string `json:"jti"`

	// PrevHash is the SHA-256 hash of the previous entry's canonical JSON.
	// Empty string for the first entry (genesis).
	PrevHash string `json:"prev_hash"`

	// ECTToken is the signed ECT in JWS compact serialization.
	ECTToken string `json:"ect_token"`

	// Issuer is the WIMSE identifier of the agent that generated the ECT.
	Issuer string `json:"iss"`

	// Subject is the agent that executed the tool call.
	Subject string `json:"sub"`

	// ToolID is the tool that was called.
	ToolID string `json:"tool_id"`

	// ExecAct is the operation that was performed.
	ExecAct string `json:"exec_act,omitempty"`

	// WorkflowID links the entry to a workflow DAG.
	WorkflowID string `json:"wid,omitempty"`

	// RecordedAt is when this entry was appended to the ledger.
	RecordedAt time.Time `json:"recorded_at"`
}

// ECTLedger is an append-only, hash-chained audit ledger for Execution Context Tokens.
// It provides O(1) lookup by JTI, monotonic sequencing, and integrity verification.
// Safe for concurrent use.
type ECTLedger struct {
	mu       sync.RWMutex
	entries  []*ECTLedgerEntry
	index    map[string]int // jti → entries slice index
	lastHash string         // hash of the most recent entry
	seq      uint64         // current sequence counter
}

// NewECTLedger creates an empty ECT audit ledger.
func NewECTLedger() *ECTLedger {
	return &ECTLedger{
		index: make(map[string]int),
	}
}

// Append adds an ECT record to the ledger. Returns the assigned sequence number.
// Returns an error if the JTI already exists (duplicate detection).
func (l *ECTLedger) Append(entry *ECTLedgerEntry) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.index[entry.JTI]; exists {
		return 0, fmt.Errorf("ect ledger: duplicate jti %q", entry.JTI)
	}

	// Assign monotonic sequence.
	l.seq++
	entry.Sequence = l.seq

	// Chain to previous entry.
	entry.PrevHash = l.lastHash

	// Set recording timestamp.
	if entry.RecordedAt.IsZero() {
		entry.RecordedAt = time.Now().UTC()
	}

	// Compute this entry's hash for the chain.
	entryHash, err := hashEntry(entry)
	if err != nil {
		l.seq-- // rollback
		return 0, fmt.Errorf("ect ledger: hash computation failed: %w", err)
	}
	l.lastHash = entryHash

	// Append and index.
	l.index[entry.JTI] = len(l.entries)
	l.entries = append(l.entries, entry)

	return entry.Sequence, nil
}

// Lookup retrieves an entry by JTI in O(1).
func (l *ECTLedger) Lookup(jti string) (*ECTLedgerEntry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	idx, ok := l.index[jti]
	if !ok {
		return nil, false
	}
	return l.entries[idx], true
}

// Len returns the number of entries in the ledger.
func (l *ECTLedger) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// LastSequence returns the most recent sequence number (0 if empty).
func (l *ECTLedger) LastSequence() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.seq
}

// Verify checks the integrity of the entire hash chain.
// Returns nil if the chain is valid, or an error describing the first
// integrity violation found.
func (l *ECTLedger) Verify() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	prevHash := ""
	for i, entry := range l.entries {
		// Check sequence monotonicity.
		expectedSeq := uint64(i + 1)
		if entry.Sequence != expectedSeq {
			return fmt.Errorf("ect ledger: sequence gap at position %d: got %d, want %d",
				i, entry.Sequence, expectedSeq)
		}

		// Check prev_hash chain.
		if entry.PrevHash != prevHash {
			return fmt.Errorf("ect ledger: chain broken at seq %d: prev_hash %q, want %q",
				entry.Sequence, entry.PrevHash, prevHash)
		}

		// Compute this entry's hash for next link.
		h, err := hashEntry(entry)
		if err != nil {
			return fmt.Errorf("ect ledger: hash computation failed at seq %d: %w", entry.Sequence, err)
		}
		prevHash = h
	}

	return nil
}

// Entries returns a deep copy of all ledger entries (for export/serialization).
func (l *ECTLedger) Entries() []*ECTLedgerEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*ECTLedgerEntry, len(l.entries))
	for i, e := range l.entries {
		cp := *e
		result[i] = &cp
	}
	return result
}

// hashEntry computes the SHA-256 hash of an entry's canonical JSON representation.
func hashEntry(entry *ECTLedgerEntry) (string, error) {
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
