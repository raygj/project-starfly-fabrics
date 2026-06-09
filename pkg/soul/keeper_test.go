package soul

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// mockRevIndex implements RevocationExporter for testing.
type mockRevIndex struct {
	exportData []byte
	exportErr  error
	hash       string
	len        int
}

func (m *mockRevIndex) Export() ([]byte, error) { return m.exportData, m.exportErr }
func (m *mockRevIndex) Hash() string            { return m.hash }
func (m *mockRevIndex) Len() int                { return m.len }

// mockBus implements core.SyncBus for testing.
type mockBus struct {
	flashed atomic.Int32
}

func (m *mockBus) Flash(_ context.Context, _ *core.Signal) error {
	m.flashed.Add(1)
	return nil
}
func (m *mockBus) Subscribe(_ context.Context, _ string, _ core.SignalHandler) error { return nil }
func (m *mockBus) Replay(_ context.Context, _ time.Time) ([]*core.Signal, error)    { return nil, nil }

func TestKeeper_Snapshot(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	revIdx := &mockRevIndex{
		exportData: []byte(`{"entries":[],"count":0,"hash":"sha256:empty"}`),
		hash:       "sha256:empty",
		len:        0,
	}

	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   anchor,
		RevIndex: revIdx,
		Interval: 1 * time.Hour, // won't fire in test
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KMSKeyID: "arn:key/1", Algorithm: "RS256", KID: "key-1", Status: "active"}},
		[]TrustDomainSpec{{Name: "prod.acme.com", Enabled: true}},
	)

	ctx := context.Background()
	if err := keeper.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if keeper.Sequence() != 1 {
		t.Errorf("Sequence = %d, want 1", keeper.Sequence())
	}

	// Verify manifest was written.
	m, err := anchor.ReadManifest(ctx, "test-fabric")
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if m.Metadata.Sequence != 1 {
		t.Errorf("manifest sequence = %d, want 1", m.Metadata.Sequence)
	}
	if len(m.Identity.SigningKeys) != 1 {
		t.Errorf("signing keys = %d, want 1", len(m.Identity.SigningKeys))
	}
	if len(m.TrustDomains) != 1 {
		t.Errorf("trust domains = %d, want 1", len(m.TrustDomains))
	}

	// Verify revocation snapshot was written.
	_, err = anchor.ReadRevocationSnapshot(ctx, "test-fabric")
	if err != nil {
		t.Fatalf("ReadRevocationSnapshot: %v", err)
	}
}

func TestKeeper_SequenceIncrements(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   anchor,
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KID: "k", Status: "active"}},
		nil,
	)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := keeper.Snapshot(ctx); err != nil {
			t.Fatalf("Snapshot %d: %v", i, err)
		}
	}

	if keeper.Sequence() != 3 {
		t.Errorf("Sequence = %d, want 3", keeper.Sequence())
	}

	// Archive should have 3 versions.
	versions, err := anchor.ListManifestVersions(ctx, "test-fabric", 10)
	if err != nil {
		t.Fatalf("ListManifestVersions: %v", err)
	}
	if len(versions) != 3 {
		t.Errorf("versions = %d, want 3", len(versions))
	}
}

func TestKeeper_PeriodicSnapshot(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   anchor,
		Interval: 100 * time.Millisecond, // fast interval for testing
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KID: "k", Status: "active"}},
		nil,
	)

	ctx := context.Background()
	keeper.Start(ctx)

	// Wait for at least 2 snapshots.
	time.Sleep(350 * time.Millisecond)

	seq := keeper.Sequence()
	if seq < 2 {
		t.Errorf("expected at least 2 snapshots, got %d", seq)
	}

	// Stop should write final snapshot.
	if err := keeper.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	finalSeq := keeper.Sequence()
	if finalSeq > seq {
		// Good — final snapshot was written.
	} else {
		t.Errorf("final sequence %d should be > pre-stop sequence %d", finalSeq, seq)
	}
}

func TestKeeper_FlashesSignal(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	bus := &mockBus{}

	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   anchor,
		Bus:      bus,
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KID: "k", Status: "active"}},
		nil,
	)

	ctx := context.Background()
	if err := keeper.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if bus.flashed.Load() != 1 {
		t.Errorf("bus.flashed = %d, want 1", bus.flashed.Load())
	}
}

func TestKeeper_NoBus_StillWorks(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())

	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   anchor,
		Bus:      nil, // no NATS
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KID: "k", Status: "active"}},
		nil,
	)

	// Should not panic.
	ctx := context.Background()
	if err := keeper.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot without bus: %v", err)
	}
}

func TestKeeper_NoRevIndex_StillWorks(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())

	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   anchor,
		RevIndex: nil, // no revocation index
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KID: "k", Status: "active"}},
		nil,
	)

	ctx := context.Background()
	if err := keeper.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot without revIndex: %v", err)
	}

	// Manifest should have zero revocations.
	m, err := anchor.ReadManifest(ctx, "test-fabric")
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if m.Revocations.Count != 0 {
		t.Errorf("revocation count = %d, want 0", m.Revocations.Count)
	}
}

func TestKeeper_MissingFabricID(t *testing.T) {
	_, err := NewKeeper(KeeperConfig{
		Anchor: NewFSAnchor(t.TempDir()),
	})
	if err == nil {
		t.Fatal("expected error for missing fabricID")
	}
}

func TestKeeper_MissingAnchor(t *testing.T) {
	_, err := NewKeeper(KeeperConfig{
		FabricID: "test",
	})
	if err == nil {
		t.Fatal("expected error for missing anchor")
	}
}

func TestKeeper_GracefulShutdown(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	keeper, err := NewKeeper(KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   anchor,
		Interval: 1 * time.Hour, // won't fire
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}

	keeper.SetIdentity(
		[]SigningKeyRef{{KID: "k", Status: "active"}},
		nil,
	)

	ctx := context.Background()
	keeper.Start(ctx)

	// Stop immediately — should write final snapshot.
	if err := keeper.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Final snapshot should have been written.
	if keeper.Sequence() < 1 {
		t.Error("expected at least 1 snapshot from graceful shutdown")
	}

	m, err := anchor.ReadManifest(ctx, "test-fabric")
	if err != nil {
		t.Fatalf("ReadManifest after stop: %v", err)
	}
	if m.Metadata.FabricID != "test-fabric" {
		t.Errorf("fabricID = %q", m.Metadata.FabricID)
	}
}
