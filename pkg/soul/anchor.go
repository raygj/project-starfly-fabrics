package soul

import (
	"context"
	"time"
)

// Anchor is the external state storage interface for soul manifests
// and revocation snapshots. Implementations write to durable storage
// outside the cluster's blast radius.
type Anchor interface {
	// WriteManifest writes a soul manifest to the anchor.
	WriteManifest(ctx context.Context, manifest *SoulManifest) error

	// ReadManifest reads the latest soul manifest for the given fabric.
	ReadManifest(ctx context.Context, fabricID string) (*SoulManifest, error)

	// WriteRevocationSnapshot writes the revocation index binary export.
	WriteRevocationSnapshot(ctx context.Context, fabricID string, data []byte) error

	// ReadRevocationSnapshot reads the revocation index binary export.
	ReadRevocationSnapshot(ctx context.Context, fabricID string) ([]byte, error)

	// WriteAuditBuffer writes unflushed audit events.
	WriteAuditBuffer(ctx context.Context, fabricID string, data []byte) error

	// ListManifestVersions lists available manifest versions (most recent first).
	ListManifestVersions(ctx context.Context, fabricID string, limit int) ([]ManifestVersion, error)
}

// ManifestVersion is metadata about a stored manifest version.
type ManifestVersion struct {
	Sequence    uint64    `json:"sequence"`
	GeneratedAt time.Time `json:"generatedAt"`
	Size        int64     `json:"size"`
}
