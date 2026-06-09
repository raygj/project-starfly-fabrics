package soul

import (
	"context"
	"testing"
	"time"
)

// These tests validate the full soul lifecycle: snapshot → destroy → recover → verify.

func TestIntegration_FullRecovery(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	// 1. Set up a keeper and snapshot.
	revIdx := &mockRevIndex{
		exportData: []byte(`{"entries":[{"subject_id":"wimse://example.com/sa/revoked","reason":"compromised","revoked_at":"2026-03-07T12:00:00Z","expires_at":"2026-03-08T12:00:00Z"}],"count":1,"hash":"sha256:abc"}`),
		hash:       "sha256:abc",
		len:        1,
	}

	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "integration-fabric",
		Anchor:   anchor,
		RevIndex: revIdx,
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{
			{KMSKeyID: "arn:key/prod-1", Algorithm: "RS256", KID: "prod-key-1", Status: "active"},
			{KMSKeyID: "arn:key/prod-0", Algorithm: "RS256", KID: "prod-key-0", Status: "rotated"},
		},
		[]TrustDomainSpec{
			{Name: "prod.acme.com", Issuer: "https://idp.acme.com", JWKSURL: "https://idp.acme.com/.well-known/jwks.json", Enabled: true},
			{Name: "123456789012", Type: "aws-sts", Enabled: true},
		},
	)
	keeper.SetAuditState(AuditState{LastFlushedSequence: 5000, ExternalSink: "s3://audit/"})

	// Snapshot.
	if err := keeper.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// 2. "Destroy" — forget everything about the keeper.
	keeper = nil

	// 3. Recover from anchor.
	result, err := Recover(ctx, anchor, "integration-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	if result.Mode != ModeRecovery {
		t.Fatalf("Mode = %q, want recovery", result.Mode)
	}

	m := result.Manifest
	if m.Metadata.FabricID != "integration-fabric" {
		t.Errorf("FabricID = %q", m.Metadata.FabricID)
	}
	if m.Metadata.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", m.Metadata.Sequence)
	}

	// Verify signing keys survived.
	if len(m.Identity.SigningKeys) != 2 {
		t.Fatalf("SigningKeys = %d, want 2", len(m.Identity.SigningKeys))
	}
	if m.Identity.SigningKeys[0].KID != "prod-key-1" {
		t.Errorf("key 0 KID = %q", m.Identity.SigningKeys[0].KID)
	}

	// Verify trust domains survived.
	if len(m.TrustDomains) != 2 {
		t.Fatalf("TrustDomains = %d, want 2", len(m.TrustDomains))
	}

	// Verify revocation data survived.
	if result.RevocationData == nil {
		t.Fatal("RevocationData should not be nil")
	}
	if m.Revocations.Count != 1 {
		t.Errorf("Revocations.Count = %d, want 1", m.Revocations.Count)
	}

	// Verify audit state survived.
	if m.Audit.LastFlushedSequence != 5000 {
		t.Errorf("Audit.LastFlushedSequence = %d, want 5000", m.Audit.LastFlushedSequence)
	}
}

func TestIntegration_UpgradeConvergence(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	// 1. Boot with v1 manifest.
	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "upgrade-fabric",
		Anchor:   anchor,
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KMSKeyID: "arn:key/v1", Algorithm: "RS256", KID: "v1-key", Status: "active"}},
		[]TrustDomainSpec{
			{Name: "domain-a.com", Enabled: true},
			{Name: "domain-b.com", Enabled: true},
		},
	)
	if err := keeper.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot v1: %v", err)
	}

	// 2. Read snapshot as "current".
	result, err := Recover(ctx, anchor, "upgrade-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	current := result.Manifest

	// 3. Define v2 spec: add a domain, remove a domain, change signing key.
	spec := NewManifest("upgrade-fabric", 2)
	spec.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:key/v2", Algorithm: "ES256", KID: "v2-key", Status: "active"},
	}
	spec.TrustDomains = []TrustDomainSpec{
		{Name: "domain-a.com", Enabled: true},     // kept
		{Name: "domain-c.com", Enabled: true},      // added
		// domain-b.com removed
	}

	// 4. Converge.
	plan, err := Converge(current, spec, WithImportRevocations(false))
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	// Verify plan.
	if plan.IsEmpty() {
		t.Fatal("plan should not be empty")
	}

	if !findAction(plan, ActionAddTrustDomain, "domain-c.com") {
		t.Error("expected AddTrustDomain for domain-c.com")
	}
	if !findAction(plan, ActionRemoveTrustDomain, "domain-b.com") {
		t.Error("expected RemoveTrustDomain for domain-b.com")
	}
	if !findAction(plan, ActionRotateSigningKey, "v2-key") {
		t.Error("expected RotateSigningKey for v2-key")
	}
	if !findAction(plan, ActionResetRevocations, "") {
		t.Error("expected ResetRevocations")
	}

	// Apply should not error.
	if err := Apply(ctx, plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func TestIntegration_Rollback(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	// 1. v1 state.
	v1 := NewManifest("rollback-fabric", 1)
	v1.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:key/v1", Algorithm: "RS256", KID: "v1-key", Status: "active"},
	}
	v1.TrustDomains = []TrustDomainSpec{
		{Name: "original.com", Enabled: true},
	}
	if err := anchor.WriteManifest(ctx, v1); err != nil {
		t.Fatalf("WriteManifest v1: %v", err)
	}

	// 2. "Upgrade" to v2.
	v2 := NewManifest("rollback-fabric", 2)
	v2.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:key/v2", Algorithm: "ES256", KID: "v2-key", Status: "active"},
	}
	v2.TrustDomains = []TrustDomainSpec{
		{Name: "original.com", Enabled: true},
		{Name: "new.com", Enabled: true},
	}
	if err := anchor.WriteManifest(ctx, v2); err != nil {
		t.Fatalf("WriteManifest v2: %v", err)
	}

	// 3. "Rollback" — converge v2 (current) back to v1 (spec).
	result, err := Recover(ctx, anchor, "rollback-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	current := result.Manifest

	plan, err := Converge(current, v1)
	if err != nil {
		t.Fatalf("Converge rollback: %v", err)
	}

	// Should remove new.com and rotate key back.
	if !findAction(plan, ActionRemoveTrustDomain, "new.com") {
		t.Error("expected RemoveTrustDomain for new.com on rollback")
	}
	if !findAction(plan, ActionRotateSigningKey, "v1-key") {
		t.Error("expected RotateSigningKey for v1-key on rollback")
	}
}

func TestIntegration_SplitBrainDetection(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	// Keeper 1 writes sequence 5.
	k1, err := NewKeeper(KeeperConfig{
		FabricID: "split-fabric",
		Anchor:   anchor,
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper k1: %v", err)
	}
	k1.SetIdentity([]SigningKeyRef{{KID: "k", Status: "active"}}, nil)

	for i := 0; i < 5; i++ {
		if err := k1.Snapshot(ctx); err != nil {
			t.Fatalf("k1 Snapshot %d: %v", i, err)
		}
	}
	if k1.Sequence() != 5 {
		t.Fatalf("k1 sequence = %d, want 5", k1.Sequence())
	}

	// Keeper 2 starts fresh — its sequence starts at 0.
	// When it snapshots, it will detect that the anchor has sequence 5
	// which is >= its local sequence 1.
	// This doesn't error — it logs a warning. We just verify it doesn't panic.
	k2, err := NewKeeper(KeeperConfig{
		FabricID: "split-fabric",
		Anchor:   anchor,
		UnitID:   "unit-2",
	})
	if err != nil {
		t.Fatalf("NewKeeper k2: %v", err)
	}
	k2.SetIdentity([]SigningKeyRef{{KID: "k", Status: "active"}}, nil)

	// This should trigger the split-brain warning but not error.
	if err := k2.Snapshot(ctx); err != nil {
		t.Fatalf("k2 Snapshot: %v", err)
	}
}

func TestIntegration_AnchorFailureResilience(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "resilience-fabric",
		Anchor:   anchor,
		Interval: 50 * time.Millisecond,
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}
	keeper.SetIdentity([]SigningKeyRef{{KID: "k", Status: "active"}}, nil)

	// Start keeper.
	keeper.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Verify some snapshots were written.
	seq := keeper.Sequence()
	if seq < 2 {
		t.Errorf("expected at least 2 snapshots, got %d", seq)
	}

	// Stop — final snapshot.
	if err := keeper.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Verify recovery works.
	result, err := Recover(ctx, anchor, "resilience-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if result.Mode != ModeRecovery {
		t.Errorf("Mode = %q, want recovery", result.Mode)
	}
}

func TestIntegration_MultipleVersionsInArchive(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "archive-fabric",
		Anchor:   anchor,
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}
	keeper.SetIdentity([]SigningKeyRef{{KID: "k", Status: "active"}}, nil)

	// Write 5 snapshots.
	for i := 0; i < 5; i++ {
		if err := keeper.Snapshot(ctx); err != nil {
			t.Fatalf("Snapshot %d: %v", i, err)
		}
	}

	// Verify archive has 5 versions.
	versions, err := anchor.ListManifestVersions(ctx, "archive-fabric", 10)
	if err != nil {
		t.Fatalf("ListManifestVersions: %v", err)
	}
	if len(versions) != 5 {
		t.Errorf("archive versions = %d, want 5", len(versions))
	}

	// Most recent should be sequence 5.
	if versions[0].Sequence != 5 {
		t.Errorf("latest version sequence = %d, want 5", versions[0].Sequence)
	}

	// Latest read should also be sequence 5.
	result, err := Recover(ctx, anchor, "archive-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if result.Manifest.Metadata.Sequence != 5 {
		t.Errorf("recovered sequence = %d, want 5", result.Manifest.Metadata.Sequence)
	}
}
