package soul

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// FSAnchor implements Anchor using the local filesystem.
// Layout:
//
//	{root}/{fabricID}/soul-manifest.yaml          (latest)
//	{root}/{fabricID}/archive/soul-manifest-{seq}.yaml (versioned)
//	{root}/{fabricID}/revocation-index.bin
//	{root}/{fabricID}/audit-buffer.jsonl
type FSAnchor struct {
	root string
}

// NewFSAnchor creates a filesystem-backed anchor at the given root directory.
func NewFSAnchor(root string) *FSAnchor {
	return &FSAnchor{root: root}
}

func (a *FSAnchor) fabricDir(fabricID string) string {
	return filepath.Join(a.root, fabricID)
}

func (a *FSAnchor) archiveDir(fabricID string) string {
	return filepath.Join(a.fabricDir(fabricID), "archive")
}

func (a *FSAnchor) WriteManifest(_ context.Context, manifest *SoulManifest) error {
	dir := a.fabricDir(manifest.Metadata.FabricID)
	archDir := a.archiveDir(manifest.Metadata.FabricID)

	if err := os.MkdirAll(archDir, 0o750); err != nil {
		return fmt.Errorf("creating anchor directory: %w", err)
	}

	data, err := manifest.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}

	// Write latest.
	latestPath := filepath.Join(dir, "soul-manifest.yaml")
	if err := os.WriteFile(latestPath, data, 0o640); err != nil {
		return fmt.Errorf("writing latest manifest: %w", err)
	}

	// Write versioned archive.
	archPath := filepath.Join(archDir, fmt.Sprintf("soul-manifest-%d.yaml", manifest.Metadata.Sequence))
	if err := os.WriteFile(archPath, data, 0o640); err != nil {
		return fmt.Errorf("writing archive manifest: %w", err)
	}

	return nil
}

func (a *FSAnchor) ReadManifest(_ context.Context, fabricID string) (*SoulManifest, error) {
	path := filepath.Join(a.fabricDir(fabricID), "soul-manifest.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no manifest found for fabric %s: %w", fabricID, err)
		}
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	return Unmarshal(data)
}

func (a *FSAnchor) WriteRevocationSnapshot(_ context.Context, fabricID string, data []byte) error {
	dir := a.fabricDir(fabricID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating anchor directory: %w", err)
	}

	path := filepath.Join(dir, "revocation-index.bin")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("writing revocation snapshot: %w", err)
	}
	return nil
}

func (a *FSAnchor) ReadRevocationSnapshot(_ context.Context, fabricID string) ([]byte, error) {
	path := filepath.Join(a.fabricDir(fabricID), "revocation-index.bin")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no revocation snapshot for fabric %s: %w", fabricID, err)
		}
		return nil, fmt.Errorf("reading revocation snapshot: %w", err)
	}
	return data, nil
}

func (a *FSAnchor) WriteAuditBuffer(_ context.Context, fabricID string, data []byte) error {
	dir := a.fabricDir(fabricID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating anchor directory: %w", err)
	}

	path := filepath.Join(dir, "audit-buffer.jsonl")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("writing audit buffer: %w", err)
	}
	return nil
}

func (a *FSAnchor) ListManifestVersions(_ context.Context, fabricID string, limit int) ([]ManifestVersion, error) {
	archDir := a.archiveDir(fabricID)
	entries, err := os.ReadDir(archDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No versions yet.
		}
		return nil, fmt.Errorf("listing archive directory: %w", err)
	}

	var versions []ManifestVersion
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(archDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		m, err := Unmarshal(data)
		if err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		versions = append(versions, ManifestVersion{
			Sequence:    m.Metadata.Sequence,
			GeneratedAt: m.Metadata.GeneratedAt,
			Size:        info.Size(),
		})
	}

	// Sort by sequence descending (most recent first).
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Sequence > versions[j].Sequence
	})

	if limit > 0 && len(versions) > limit {
		versions = versions[:limit]
	}

	return versions, nil
}
