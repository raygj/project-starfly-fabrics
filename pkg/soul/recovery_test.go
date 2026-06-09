package soul

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecover_FreshInstall(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	result, err := Recover(ctx, anchor, "nonexistent-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if result.Mode != ModeFreshInstall {
		t.Errorf("Mode = %q, want %q", result.Mode, ModeFreshInstall)
	}
	if result.Manifest != nil {
		t.Error("Manifest should be nil for fresh install")
	}
}

func TestRecover_Recovery(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	m := NewManifest("test-fabric", 5)
	m.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:key/1", Algorithm: "RS256", KID: "key-1", Status: "active"},
	}
	m.TrustDomains = []TrustDomainSpec{
		{Name: "prod.acme.com", Enabled: true},
	}
	m.Revocations = RevocationSnapshot{Count: 100, Hash: "sha256:abc", ExportedAt: time.Now().UTC()}

	if err := anchor.WriteManifest(ctx, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	revData := []byte(`{"entries":[],"count":0,"hash":"sha256:empty"}`)
	if err := anchor.WriteRevocationSnapshot(ctx, "test-fabric", revData); err != nil {
		t.Fatalf("WriteRevocationSnapshot: %v", err)
	}

	result, err := Recover(ctx, anchor, "test-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	if result.Mode != ModeRecovery {
		t.Errorf("Mode = %q, want %q", result.Mode, ModeRecovery)
	}
	if result.Manifest == nil {
		t.Fatal("Manifest should not be nil for recovery")
	}
	if result.Manifest.Metadata.Sequence != 5 {
		t.Errorf("Sequence = %d, want 5", result.Manifest.Metadata.Sequence)
	}
	if len(result.Manifest.Identity.SigningKeys) != 1 {
		t.Errorf("SigningKeys = %d, want 1", len(result.Manifest.Identity.SigningKeys))
	}
	if result.RevocationData == nil {
		t.Error("RevocationData should not be nil")
	}
	if result.GapSeconds < 0 {
		t.Errorf("GapSeconds = %f, should be >= 0", result.GapSeconds)
	}
}

func TestRecover_NoRevocationSnapshot(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	m := NewManifest("test-fabric", 1)
	m.Identity.SigningKeys = []SigningKeyRef{
		{KID: "key-1", Status: "active"},
	}
	if err := anchor.WriteManifest(ctx, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	result, err := Recover(ctx, anchor, "test-fabric")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	if result.Mode != ModeRecovery {
		t.Errorf("Mode = %q, want recovery", result.Mode)
	}
	if result.RevocationData != nil {
		t.Error("RevocationData should be nil when no snapshot exists")
	}
}

func TestRecover_InvalidManifest(t *testing.T) {
	anchor := NewFSAnchor(t.TempDir())
	ctx := context.Background()

	// Write manifest with no signing keys — Validate() will fail.
	m := NewManifest("test-fabric", 1)
	if err := anchor.WriteManifest(ctx, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	_, err := Recover(ctx, anchor, "test-fabric")
	if err == nil {
		t.Fatal("expected error for invalid manifest")
	}
}

func TestRecover_SentinelErrors(t *testing.T) {
	if !errors.Is(ErrManifestNotFound, ErrManifestNotFound) {
		t.Error("ErrManifestNotFound should be a sentinel error")
	}
	if !errors.Is(ErrFabricMismatch, ErrFabricMismatch) {
		t.Error("ErrFabricMismatch should be a sentinel error")
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("something happened"), false},
		{errors.New("no manifest found for fabric x: file does not exist"), true},
		{errors.New("no such file or directory"), true},
		{errors.New("NoSuchKey: the specified key does not exist"), true},
		{errors.New("not found"), true},
	}

	for _, tt := range tests {
		name := "nil"
		if tt.err != nil {
			name = tt.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			got := isNotFound(tt.err)
			if got != tt.want {
				t.Errorf("isNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
