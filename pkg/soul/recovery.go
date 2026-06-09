package soul

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// RecoveryMode indicates whether the boot is a recovery or fresh install.
type RecoveryMode string

const (
	ModeRecovery     RecoveryMode = "recovery"
	ModeFreshInstall RecoveryMode = "fresh_install"
)

// RecoveryResult holds the outcome of a boot recovery attempt.
type RecoveryResult struct {
	Mode           RecoveryMode
	Manifest       *SoulManifest
	RevocationData []byte
	GapSeconds     float64 // seconds between last snapshot and now
}

// ErrManifestNotFound indicates no manifest exists at the anchor.
var ErrManifestNotFound = errors.New("soul manifest not found")

// ErrFabricMismatch indicates the anchor contains a manifest for a different fabric.
var ErrFabricMismatch = errors.New("fabric ID mismatch")

// Recover attempts to recover fabric state from the external anchor.
//
// Recovery logic:
//  1. Read soul manifest from anchor for the given fabricID.
//  2. If not found: fresh install (return ModeFreshInstall, nil manifest).
//  3. If found but fabricID doesn't match config: abort with ErrFabricMismatch.
//  4. Validate manifest schema.
//  5. Read revocation snapshot from anchor (optional — may not exist).
//  6. Return RecoveryResult with manifest, revocation data, and gap.
func Recover(ctx context.Context, anchor Anchor, fabricID string) (*RecoveryResult, error) {
	slog.Info("attempting soul recovery", "fabric_id", fabricID)

	// 1. Read manifest.
	manifest, err := anchor.ReadManifest(ctx, fabricID)
	if err != nil {
		if isNotFound(err) {
			slog.Info("no soul manifest found — fresh install", "fabric_id", fabricID)
			return &RecoveryResult{Mode: ModeFreshInstall}, nil
		}
		return nil, fmt.Errorf("reading soul manifest: %w", err)
	}

	// 2. Verify fabric ID matches.
	if manifest.Metadata.FabricID != fabricID {
		return nil, fmt.Errorf("%w: anchor has %q, expected %q",
			ErrFabricMismatch, manifest.Metadata.FabricID, fabricID)
	}

	// 3. Validate manifest.
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("soul manifest validation failed: %w", err)
	}

	// 4. Calculate gap.
	gap := time.Since(manifest.Metadata.GeneratedAt).Seconds()

	// 5. Read revocation snapshot (optional).
	var revData []byte
	revData, err = anchor.ReadRevocationSnapshot(ctx, fabricID)
	if err != nil {
		if isNotFound(err) {
			slog.Warn("no revocation snapshot found — starting with empty index", "fabric_id", fabricID)
			revData = nil
		} else {
			return nil, fmt.Errorf("reading revocation snapshot: %w", err)
		}
	}

	slog.Info("soul recovery complete",
		"fabric_id", fabricID,
		"sequence", manifest.Metadata.Sequence,
		"revocation_count", manifest.Revocations.Count,
		"gap_seconds", gap,
		"signing_keys", len(manifest.Identity.SigningKeys),
		"trust_domains", len(manifest.TrustDomains),
	)

	return &RecoveryResult{
		Mode:           ModeRecovery,
		Manifest:       manifest,
		RevocationData: revData,
		GapSeconds:     gap,
	}, nil
}

// isNotFound checks if an error indicates a missing resource.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, pattern := range []string{"not found", "no such file", "does not exist", "NoSuchKey", "not exist"} {
		if containsSubstring(s, pattern) {
			return true
		}
	}
	return false
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstr(s, substr)
}

func searchSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
