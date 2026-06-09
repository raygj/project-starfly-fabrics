package audit

import (
	"fmt"
	"sync"
	"testing"
)

func TestECTLedger_Append(t *testing.T) {
	ledger := NewECTLedger()

	seq, err := ledger.Append(&ECTLedgerEntry{
		JTI:     "task-001",
		Issuer:  "wimse://prod/tools/sql-query",
		Subject: "wimse://dev.local/agent/data-bot",
		ToolID:  "sql-query",
		ExecAct: "query",
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if seq != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}
	if ledger.Len() != 1 {
		t.Errorf("Len = %d, want 1", ledger.Len())
	}
}

func TestECTLedger_MonotonicSequence(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 5; i++ {
		seq, err := ledger.Append(&ECTLedgerEntry{
			JTI: fmt.Sprintf("task-%03d", i),
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if seq != uint64(i) {
			t.Errorf("seq = %d, want %d", seq, i)
		}
	}

	if ledger.LastSequence() != 5 {
		t.Errorf("LastSequence = %d, want 5", ledger.LastSequence())
	}
}

func TestECTLedger_DuplicateJTI(t *testing.T) {
	ledger := NewECTLedger()

	_, _ = ledger.Append(&ECTLedgerEntry{JTI: "task-001"})
	_, err := ledger.Append(&ECTLedgerEntry{JTI: "task-001"})
	if err == nil {
		t.Fatal("expected duplicate JTI error")
	}
}

func TestECTLedger_LookupO1(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 100; i++ {
		_, _ = ledger.Append(&ECTLedgerEntry{
			JTI:     fmt.Sprintf("task-%03d", i),
			ExecAct: fmt.Sprintf("op-%d", i),
		})
	}

	// Lookup specific entry.
	entry, ok := ledger.Lookup("task-042")
	if !ok {
		t.Fatal("task-042 not found")
	}
	if entry.ExecAct != "op-42" {
		t.Errorf("ExecAct = %q, want %q", entry.ExecAct, "op-42")
	}
	if entry.Sequence != 42 {
		t.Errorf("Sequence = %d, want 42", entry.Sequence)
	}

	// Lookup nonexistent.
	_, ok = ledger.Lookup("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent JTI")
	}
}

func TestECTLedger_HashChain(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 10; i++ {
		_, err := ledger.Append(&ECTLedgerEntry{
			JTI:    fmt.Sprintf("task-%03d", i),
			ToolID: "test-tool",
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// First entry should have empty prev_hash.
	entries := ledger.Entries()
	if entries[0].PrevHash != "" {
		t.Errorf("genesis prev_hash = %q, want empty", entries[0].PrevHash)
	}

	// Subsequent entries should have non-empty prev_hash.
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash == "" {
			t.Errorf("entry %d has empty prev_hash", i)
		}
	}

	// Each prev_hash should match the hash of the previous entry.
	for i := 1; i < len(entries); i++ {
		prevEntryHash, err := hashEntry(entries[i-1])
		if err != nil {
			t.Fatalf("hash entry %d: %v", i-1, err)
		}
		if entries[i].PrevHash != prevEntryHash {
			t.Errorf("entry %d prev_hash mismatch", i)
		}
	}
}

func TestECTLedger_Verify(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 5; i++ {
		_, _ = ledger.Append(&ECTLedgerEntry{
			JTI: fmt.Sprintf("task-%03d", i),
		})
	}

	// Valid chain.
	if err := ledger.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestECTLedger_VerifyDetectsTampering(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 5; i++ {
		_, _ = ledger.Append(&ECTLedgerEntry{
			JTI:    fmt.Sprintf("task-%03d", i),
			ToolID: "original",
		})
	}

	// Tamper with entry 3.
	ledger.mu.Lock()
	ledger.entries[2].ToolID = "tampered"
	ledger.mu.Unlock()

	err := ledger.Verify()
	if err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}

func TestECTLedger_VerifyDetectsSequenceGap(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 3; i++ {
		_, _ = ledger.Append(&ECTLedgerEntry{
			JTI: fmt.Sprintf("task-%03d", i),
		})
	}

	// Corrupt sequence number.
	ledger.mu.Lock()
	ledger.entries[1].Sequence = 99
	ledger.mu.Unlock()

	err := ledger.Verify()
	if err == nil {
		t.Fatal("expected sequence gap detection")
	}
}

func TestECTLedger_EmptyVerify(t *testing.T) {
	ledger := NewECTLedger()
	if err := ledger.Verify(); err != nil {
		t.Fatalf("empty ledger should verify: %v", err)
	}
}

func TestECTLedger_ConcurrentAppend(t *testing.T) {
	ledger := NewECTLedger()

	var wg sync.WaitGroup
	const n = 100
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _ = ledger.Append(&ECTLedgerEntry{
				JTI: fmt.Sprintf("task-%04d", idx),
			})
		}(i)
	}

	wg.Wait()

	if ledger.Len() != n {
		t.Errorf("Len = %d, want %d", ledger.Len(), n)
	}
	if ledger.LastSequence() != n {
		t.Errorf("LastSequence = %d, want %d", ledger.LastSequence(), n)
	}

	// Chain should still be valid after concurrent appends.
	if err := ledger.Verify(); err != nil {
		t.Fatalf("Verify after concurrent appends: %v", err)
	}
}

func TestECTLedger_Entries(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 3; i++ {
		_, _ = ledger.Append(&ECTLedgerEntry{
			JTI: fmt.Sprintf("task-%03d", i),
		})
	}

	entries := ledger.Entries()
	if len(entries) != 3 {
		t.Fatalf("Entries length = %d, want 3", len(entries))
	}

	// Verify it's a copy (modifying doesn't affect the ledger).
	entries[0].JTI = "modified"
	original, _ := ledger.Lookup("task-001")
	if original.JTI != "task-001" {
		t.Error("Entries() should return copies, not references")
	}
}

func TestECTLedger_VerifyChainBroken(t *testing.T) {
	ledger := NewECTLedger()

	for i := 1; i <= 3; i++ {
		_, _ = ledger.Append(&ECTLedgerEntry{
			JTI: fmt.Sprintf("task-%03d", i),
		})
	}

	// Corrupt the prev_hash of entry 2 (not just the data — the link itself).
	ledger.mu.Lock()
	ledger.entries[1].PrevHash = "corrupted-hash-value"
	ledger.mu.Unlock()

	err := ledger.Verify()
	if err == nil {
		t.Fatal("expected chain broken detection")
	}
}

func TestECTLedger_RecordedAtAutoSet(t *testing.T) {
	ledger := NewECTLedger()

	// Don't set RecordedAt — should be auto-set.
	_, err := ledger.Append(&ECTLedgerEntry{JTI: "task-auto"})
	if err != nil {
		t.Fatal(err)
	}

	entry, _ := ledger.Lookup("task-auto")
	if entry.RecordedAt.IsZero() {
		t.Error("RecordedAt should be auto-set")
	}
}

func TestECTLedger_WorkflowFilter(t *testing.T) {
	ledger := NewECTLedger()

	_, _ = ledger.Append(&ECTLedgerEntry{JTI: "t1", WorkflowID: "wf-a"})
	_, _ = ledger.Append(&ECTLedgerEntry{JTI: "t2", WorkflowID: "wf-b"})
	_, _ = ledger.Append(&ECTLedgerEntry{JTI: "t3", WorkflowID: "wf-a"})

	// Lookup by JTI works regardless of workflow.
	e, ok := ledger.Lookup("t2")
	if !ok {
		t.Fatal("t2 not found")
	}
	if e.WorkflowID != "wf-b" {
		t.Errorf("WorkflowID = %q, want %q", e.WorkflowID, "wf-b")
	}
}
