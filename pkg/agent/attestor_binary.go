package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// BinaryAttestor computes the SHA-256 hash of the running binary.
// This provides supply chain assurance: Starfly's OPA policy can
// maintain an allowlist of known agent digests.
type BinaryAttestor struct {
	execPath string // override for testing; empty = auto-detect
}

// NewBinaryAttestor creates a BinaryAttestor. Pass an empty path
// to auto-detect via os.Executable().
func NewBinaryAttestor(execPath string) *BinaryAttestor {
	return &BinaryAttestor{execPath: execPath}
}

func (b *BinaryAttestor) Name() string { return "binary-self" }

func (b *BinaryAttestor) Available(_ context.Context) bool { return true }

func (b *BinaryAttestor) Attest(_ context.Context) (*AttestationResult, error) {
	path := b.execPath
	if path == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolving executable path: %w", err)
		}
	}

	hash, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("hashing binary %s: %w", path, err)
	}

	return &AttestationResult{
		Source: "binary-self",
		Metadata: map[string]string{
			"binary_hash": "sha256:" + hash,
		},
	}, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
