package soul

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testAnchor(t *testing.T) *FSAnchor {
	t.Helper()
	return NewFSAnchor(t.TempDir())
}

func testManifest(fabricID string, seq uint64) *SoulManifest {
	m := NewManifest(fabricID, seq)
	m.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:aws:kms:us-east-1:123:key/abc", Algorithm: "RS256", KID: "key-1", Status: "active"},
	}
	m.TrustDomains = []TrustDomainSpec{
		{Name: "prod.acme.com", Enabled: true},
	}
	m.Revocations = RevocationSnapshot{Count: 100, Hash: "sha256:abc123", ExportedAt: time.Now().UTC()}
	m.Audit = AuditState{LastFlushedSequence: 500}
	return m
}

func TestFSAnchor_WriteReadManifest(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()
	m := testManifest("test-fabric", 1)

	if err := anchor.WriteManifest(ctx, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	got, err := anchor.ReadManifest(ctx, "test-fabric")
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}

	if got.Metadata.FabricID != "test-fabric" {
		t.Errorf("FabricID = %q, want test-fabric", got.Metadata.FabricID)
	}
	if got.Metadata.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", got.Metadata.Sequence)
	}
	if len(got.Identity.SigningKeys) != 1 {
		t.Errorf("SigningKeys = %d, want 1", len(got.Identity.SigningKeys))
	}
}

func TestFSAnchor_ReadManifest_NotFound(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()

	_, err := anchor.ReadManifest(ctx, "nonexistent-fabric")
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestFSAnchor_WriteReadRevocationSnapshot(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()
	fabricID := "test-fabric"

	snapshot := []byte(`{"entries":[],"count":0,"hash":"sha256:abc"}`)

	if err := anchor.WriteRevocationSnapshot(ctx, fabricID, snapshot); err != nil {
		t.Fatalf("WriteRevocationSnapshot: %v", err)
	}

	got, err := anchor.ReadRevocationSnapshot(ctx, fabricID)
	if err != nil {
		t.Fatalf("ReadRevocationSnapshot: %v", err)
	}

	if string(got) != string(snapshot) {
		t.Errorf("snapshot mismatch: got %q", string(got))
	}
}

func TestFSAnchor_ReadRevocationSnapshot_NotFound(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()

	_, err := anchor.ReadRevocationSnapshot(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing snapshot")
	}
}

func TestFSAnchor_WriteReadAuditBuffer(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()

	data := []byte(`{"event":"test"}` + "\n")
	if err := anchor.WriteAuditBuffer(ctx, "test-fabric", data); err != nil {
		t.Fatalf("WriteAuditBuffer: %v", err)
	}

	path := filepath.Join(anchor.root, "test-fabric", "audit-buffer.jsonl")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit buffer file: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("audit buffer mismatch")
	}
}

func TestFSAnchor_ListManifestVersions(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()

	// Write 3 versions.
	for seq := uint64(1); seq <= 3; seq++ {
		m := testManifest("test-fabric", seq)
		if err := anchor.WriteManifest(ctx, m); err != nil {
			t.Fatalf("WriteManifest seq %d: %v", seq, err)
		}
	}

	versions, err := anchor.ListManifestVersions(ctx, "test-fabric", 10)
	if err != nil {
		t.Fatalf("ListManifestVersions: %v", err)
	}

	if len(versions) != 3 {
		t.Fatalf("versions count = %d, want 3", len(versions))
	}

	// Should be sorted descending by sequence.
	if versions[0].Sequence != 3 {
		t.Errorf("first version sequence = %d, want 3", versions[0].Sequence)
	}
	if versions[2].Sequence != 1 {
		t.Errorf("last version sequence = %d, want 1", versions[2].Sequence)
	}
}

func TestFSAnchor_ListManifestVersions_WithLimit(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()

	for seq := uint64(1); seq <= 5; seq++ {
		m := testManifest("test-fabric", seq)
		if err := anchor.WriteManifest(ctx, m); err != nil {
			t.Fatalf("WriteManifest seq %d: %v", seq, err)
		}
	}

	versions, err := anchor.ListManifestVersions(ctx, "test-fabric", 2)
	if err != nil {
		t.Fatalf("ListManifestVersions: %v", err)
	}

	if len(versions) != 2 {
		t.Fatalf("versions count = %d, want 2", len(versions))
	}
	// Most recent 2.
	if versions[0].Sequence != 5 {
		t.Errorf("first = %d, want 5", versions[0].Sequence)
	}
	if versions[1].Sequence != 4 {
		t.Errorf("second = %d, want 4", versions[1].Sequence)
	}
}

func TestFSAnchor_ListManifestVersions_Empty(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()

	versions, err := anchor.ListManifestVersions(ctx, "nonexistent", 10)
	if err != nil {
		t.Fatalf("ListManifestVersions: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("expected empty list, got %d", len(versions))
	}
}

func TestFSAnchor_OverwriteLatest(t *testing.T) {
	anchor := testAnchor(t)
	ctx := context.Background()

	// Write v1.
	m1 := testManifest("test-fabric", 1)
	if err := anchor.WriteManifest(ctx, m1); err != nil {
		t.Fatalf("WriteManifest v1: %v", err)
	}

	// Write v2 — should overwrite latest but archive both.
	m2 := testManifest("test-fabric", 2)
	if err := anchor.WriteManifest(ctx, m2); err != nil {
		t.Fatalf("WriteManifest v2: %v", err)
	}

	// Latest should be v2.
	got, err := anchor.ReadManifest(ctx, "test-fabric")
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if got.Metadata.Sequence != 2 {
		t.Errorf("latest sequence = %d, want 2", got.Metadata.Sequence)
	}

	// Archive should have both.
	versions, err := anchor.ListManifestVersions(ctx, "test-fabric", 10)
	if err != nil {
		t.Fatalf("ListManifestVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("archive count = %d, want 2", len(versions))
	}
}
