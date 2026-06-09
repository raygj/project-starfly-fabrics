package operator

import (
	"context"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/signals"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

func testExpiry() time.Time {
	return time.Now().Add(1 * time.Hour)
}

func TestInProcessConnection_CurrentManifest_Empty(t *testing.T) {
	conn := NewInProcessConnection("test-fabric")
	manifest, err := conn.CurrentManifest(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest.Metadata.FabricID != "test-fabric" {
		t.Errorf("fabricID = %q, want %q", manifest.Metadata.FabricID, "test-fabric")
	}
	if len(manifest.TrustDomains) != 0 {
		t.Errorf("trust domains = %d, want 0", len(manifest.TrustDomains))
	}
}

func TestInProcessConnection_CurrentManifest_WithTrustDomains(t *testing.T) {
	tds := []core.TrustDomain{
		{Name: "payments.prod", Issuer: "https://pay.example.com", Enabled: true},
		{Name: "k8s.internal", Enabled: true},
	}
	conn := NewInProcessConnection("test-fabric", WithTrustDomains(tds))

	manifest, err := conn.CurrentManifest(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifest.TrustDomains) != 2 {
		t.Fatalf("trust domains = %d, want 2", len(manifest.TrustDomains))
	}
	if manifest.TrustDomains[0].Name != "payments.prod" {
		t.Errorf("td[0].Name = %q, want %q", manifest.TrustDomains[0].Name, "payments.prod")
	}
}

func TestInProcessConnection_CurrentManifest_WithRevocationIndex(t *testing.T) {
	ri := signals.NewRevocationIndex()
	ctx := context.Background()
	_ = ri.Revoke(ctx, "subj-1", "test", testExpiry())

	conn := NewInProcessConnection("test-fabric", WithRevocationIndex(ri))

	manifest, err := conn.CurrentManifest(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest.Revocations.Count != 1 {
		t.Errorf("revocation count = %d, want 1", manifest.Revocations.Count)
	}
	if manifest.Revocations.Hash == "" {
		t.Error("revocation hash should not be empty")
	}
}

func TestInProcessConnection_CurrentManifest_WithTransmitter(t *testing.T) {
	tx, err := signals.NewTransmitter()
	if err != nil {
		t.Fatalf("creating transmitter: %v", err)
	}
	ctx := context.Background()
	_, err = tx.CreateStream(ctx, &core.StreamConfig{
		Audience:        "https://receiver.example.com",
		EventsRequested: []string{"credential-revoked"},
		EndpointURL:     "https://receiver.example.com/events",
	})
	if err != nil {
		t.Fatalf("creating stream: %v", err)
	}

	conn := NewInProcessConnection("test-fabric", WithTransmitter(tx))

	manifest, err := conn.CurrentManifest(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifest.SSFStreams) != 1 {
		t.Fatalf("ssf streams = %d, want 1", len(manifest.SSFStreams))
	}
	if manifest.SSFStreams[0].Transmitter != "https://receiver.example.com/events" {
		t.Errorf("stream transmitter = %q", manifest.SSFStreams[0].Transmitter)
	}
}

func TestInProcessConnection_Health(t *testing.T) {
	ri := signals.NewRevocationIndex()
	tx, err := signals.NewTransmitter()
	if err != nil {
		t.Fatalf("creating transmitter: %v", err)
	}
	tds := []core.TrustDomain{
		{Name: "td1", Enabled: true},
		{Name: "td2", Enabled: true},
	}

	conn := NewInProcessConnection("test-fabric",
		WithRevocationIndex(ri),
		WithTransmitter(tx),
		WithTrustDomains(tds),
	)

	health, err := conn.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !health.Healthy {
		t.Error("expected healthy = true")
	}
	if health.TrustDomainsActive != 2 {
		t.Errorf("trust domains = %d, want 2", health.TrustDomainsActive)
	}
}

func TestInProcessConnection_ApplyAction_AddSSFStream(t *testing.T) {
	tx, err := signals.NewTransmitter()
	if err != nil {
		t.Fatalf("creating transmitter: %v", err)
	}

	conn := NewInProcessConnection("test-fabric", WithTransmitter(tx))
	ctx := context.Background()

	err = conn.ApplyAction(ctx, soul.ConvergenceAction{
		Type:        soul.ActionAddSSFStream,
		Target:      "https://receiver.example.com",
		Description: "add SSF stream for receiver",
	})
	if err != nil {
		t.Fatalf("apply add_ssf_stream: %v", err)
	}
	if tx.StreamCount() != 1 {
		t.Errorf("stream count = %d, want 1", tx.StreamCount())
	}
}

func TestInProcessConnection_ApplyAction_RemoveSSFStream(t *testing.T) {
	tx, err := signals.NewTransmitter()
	if err != nil {
		t.Fatalf("creating transmitter: %v", err)
	}

	ctx := context.Background()
	stream, err := tx.CreateStream(ctx, &core.StreamConfig{
		Audience: "https://receiver.example.com",
	})
	if err != nil {
		t.Fatalf("creating stream: %v", err)
	}

	conn := NewInProcessConnection("test-fabric", WithTransmitter(tx))

	err = conn.ApplyAction(ctx, soul.ConvergenceAction{
		Type:        soul.ActionRemoveSSFStream,
		Target:      stream.ID,
		Description: "remove SSF stream",
	})
	if err != nil {
		t.Fatalf("apply remove_ssf_stream: %v", err)
	}
	if tx.StreamCount() != 0 {
		t.Errorf("stream count = %d, want 0", tx.StreamCount())
	}
}

func TestInProcessConnection_ApplyAction_TrustDomainApply(t *testing.T) {
	keeper, err := soul.NewKeeper(soul.KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   soul.NewFSAnchor(t.TempDir()),
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}
	conn := NewInProcessConnection("test-fabric", WithKeeper(keeper))
	conn.SetDesiredSpec(&soul.SoulManifest{
		TrustDomains: []soul.TrustDomainSpec{
			{Name: "new-domain", Enabled: true, Issuer: "https://idp.example.com"},
		},
	})
	ctx := context.Background()

	if err := conn.ApplyAction(ctx, soul.ConvergenceAction{
		Type:   soul.ActionAddTrustDomain,
		Target: "new-domain",
	}); err != nil {
		t.Fatalf("add_trust_domain: %v", err)
	}
	domains := keeper.TrustDomains()
	if len(domains) != 1 || domains[0].Name != "new-domain" {
		t.Fatalf("trust domains = %+v, want new-domain", domains)
	}

	if err := conn.ApplyAction(ctx, soul.ConvergenceAction{
		Type:   soul.ActionRemoveTrustDomain,
		Target: "new-domain",
	}); err != nil {
		t.Fatalf("remove_trust_domain: %v", err)
	}
	if len(keeper.TrustDomains()) != 0 {
		t.Fatalf("expected empty trust domains after remove")
	}
}

func TestInProcessConnection_ApplyAction_UnknownType(t *testing.T) {
	conn := NewInProcessConnection("test-fabric")
	err := conn.ApplyAction(context.Background(), soul.ConvergenceAction{
		Type: "unknown_action",
	})
	if err != nil {
		t.Fatalf("unknown action should be no-op, got: %v", err)
	}
}

func TestInProcessConnection_ApplyPlan(t *testing.T) {
	tx, err := signals.NewTransmitter()
	if err != nil {
		t.Fatalf("creating transmitter: %v", err)
	}
	conn := NewInProcessConnection("test-fabric", WithTransmitter(tx))
	ctx := context.Background()

	plan := &soul.ConvergencePlan{
		Actions: []soul.ConvergenceAction{
			{Type: soul.ActionAddSSFStream, Target: "https://a.example.com"},
			{Type: soul.ActionAddSSFStream, Target: "https://b.example.com"},
		},
	}
	result, err := conn.ApplyPlan(ctx, plan)
	if err != nil {
		t.Fatalf("apply plan: %v", err)
	}
	if result.ActionsApplied != 2 {
		t.Errorf("actions applied = %d, want 2", result.ActionsApplied)
	}
	if tx.StreamCount() != 2 {
		t.Errorf("stream count = %d, want 2", tx.StreamCount())
	}
}

func TestInProcessConnection_ApplyAction_MissingTransmitter(t *testing.T) {
	conn := NewInProcessConnection("test-fabric") // no transmitter
	ctx := context.Background()

	err := conn.ApplyAction(ctx, soul.ConvergenceAction{
		Type:   soul.ActionAddSSFStream,
		Target: "https://receiver.example.com",
	})
	if err == nil {
		t.Fatal("expected error for missing transmitter")
	}
}

func TestInProcessConnection_ApplyAction_MissingKeyring(t *testing.T) {
	conn := NewInProcessConnection("test-fabric") // no keyring
	ctx := context.Background()

	err := conn.ApplyAction(ctx, soul.ConvergenceAction{
		Type:   soul.ActionRotateSigningKey,
		Target: "key-002",
	})
	if err == nil {
		t.Fatal("expected error for missing keyring")
	}
}

func TestWithKeeper(t *testing.T) {
	conn := NewInProcessConnection("test-fabric", WithKeeper(nil))
	if conn.keeper != nil {
		t.Error("keeper should be nil when set to nil")
	}
}

func TestWithKeyring(t *testing.T) {
	conn := NewInProcessConnection("test-fabric", WithKeyring(nil))
	if conn.keyring != nil {
		t.Error("keyring should be nil when set to nil")
	}
}

func TestWithRegistry(t *testing.T) {
	conn := NewInProcessConnection("test-fabric", WithRegistry(nil))
	if conn.registry != nil {
		t.Error("registry should be nil when set to nil")
	}
}

func TestInProcessConnection_Health_Empty(t *testing.T) {
	conn := NewInProcessConnection("test-fabric")
	health, err := conn.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !health.Healthy {
		t.Error("expected healthy = true for empty connection")
	}
	if health.SigningKeysActive != 0 {
		t.Errorf("expected 0 signing keys, got %d", health.SigningKeysActive)
	}
	if health.SSFStreamsActive != 0 {
		t.Errorf("expected 0 ssf streams, got %d", health.SSFStreamsActive)
	}
	if health.SoulSequence != 0 {
		t.Errorf("expected 0 soul sequence, got %d", health.SoulSequence)
	}
}

func TestInProcessConnection_ApplyAction_RotateKeyMissingTarget(t *testing.T) {
	conn := NewInProcessConnection("test-fabric", WithKeyring(nil))
	err := conn.ApplyAction(context.Background(), soul.ConvergenceAction{
		Type:   soul.ActionRotateSigningKey,
		Target: "k1",
	})
	if err == nil {
		t.Fatal("expected error with nil keyring")
	}
}

func TestInProcessConnection_ApplyAction_UpdateTrustDomain(t *testing.T) {
	keeper, err := soul.NewKeeper(soul.KeeperConfig{
		FabricID: "test-fabric",
		Anchor:   soul.NewFSAnchor(t.TempDir()),
		UnitID:   "unit-1",
	})
	if err != nil {
		t.Fatalf("NewKeeper: %v", err)
	}
	keeper.SetIdentity(nil, []soul.TrustDomainSpec{
		{Name: "updated-domain", Enabled: true, Issuer: "https://old.example.com"},
	})
	conn := NewInProcessConnection("test-fabric", WithKeeper(keeper))
	conn.SetDesiredSpec(&soul.SoulManifest{
		TrustDomains: []soul.TrustDomainSpec{
			{Name: "updated-domain", Enabled: true, Issuer: "https://new.example.com"},
		},
	})

	if err := conn.ApplyAction(context.Background(), soul.ConvergenceAction{
		Type:   soul.ActionUpdateTrustDomain,
		Target: "updated-domain",
	}); err != nil {
		t.Fatalf("update_trust_domain: %v", err)
	}
	domains := keeper.TrustDomains()
	if len(domains) != 1 || domains[0].Issuer != "https://new.example.com" {
		t.Fatalf("updated domain = %+v", domains)
	}
}

func TestInProcessConnection_ApplyAction_ImportRevocations(t *testing.T) {
	conn := NewInProcessConnection("test-fabric")
	err := conn.ApplyAction(context.Background(), soul.ConvergenceAction{
		Type:   soul.ActionImportRevocations,
		Target: "peer-hash",
	})
	if err != nil {
		t.Fatalf("import_revocations should be no-op, got: %v", err)
	}
}

func TestInProcessConnection_ApplyAction_ResetRevocations(t *testing.T) {
	conn := NewInProcessConnection("test-fabric")
	err := conn.ApplyAction(context.Background(), soul.ConvergenceAction{
		Type:   soul.ActionResetRevocations,
		Target: "reset",
	})
	if err != nil {
		t.Fatalf("reset_revocations should be no-op, got: %v", err)
	}
}

func TestInProcessConnection_ApplyAction_RemoveSSFStreamMissingTarget(t *testing.T) {
	tx, err := signals.NewTransmitter()
	if err != nil {
		t.Fatalf("creating transmitter: %v", err)
	}
	conn := NewInProcessConnection("test-fabric", WithTransmitter(tx))

	err = conn.ApplyAction(context.Background(), soul.ConvergenceAction{
		Type:   soul.ActionRemoveSSFStream,
		Target: "",
	})
	if err == nil {
		t.Fatal("expected error for empty target on remove_ssf_stream")
	}
}

func TestInProcessConnection_ApplyAction_RemoveSSFStreamMissingTransmitter(t *testing.T) {
	conn := NewInProcessConnection("test-fabric")
	err := conn.ApplyAction(context.Background(), soul.ConvergenceAction{
		Type:   soul.ActionRemoveSSFStream,
		Target: "stream-1",
	})
	if err == nil {
		t.Fatal("expected error for missing transmitter on remove_ssf_stream")
	}
}
