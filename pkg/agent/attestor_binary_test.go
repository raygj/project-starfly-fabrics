package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryAttestor_Available(t *testing.T) {
	a := NewBinaryAttestor("")
	if !a.Available(context.Background()) {
		t.Error("BinaryAttestor should always be available")
	}
}

func TestBinaryAttestor_Name(t *testing.T) {
	a := NewBinaryAttestor("")
	if a.Name() != "binary-self" {
		t.Errorf("Name() = %q, want binary-self", a.Name())
	}
}

func TestBinaryAttestor_Attest(t *testing.T) {
	// Use the test binary itself as the target.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable(): %v", err)
	}

	a := NewBinaryAttestor(exe)
	result, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() error: %v", err)
	}

	if result.Source != "binary-self" {
		t.Errorf("Source = %q, want binary-self", result.Source)
	}

	hash := result.Metadata["binary_hash"]
	if hash == "" {
		t.Fatal("expected non-empty binary_hash")
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("binary_hash = %q, want sha256: prefix", hash)
	}
	if len(hash) != len("sha256:")+64 {
		t.Errorf("binary_hash length = %d, want %d", len(hash), len("sha256:")+64)
	}
}

func TestBinaryAttestor_Deterministic(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable(): %v", err)
	}

	a := NewBinaryAttestor(exe)

	r1, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("first Attest() error: %v", err)
	}

	r2, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("second Attest() error: %v", err)
	}

	if r1.Metadata["binary_hash"] != r2.Metadata["binary_hash"] {
		t.Errorf("hash not deterministic: %q != %q",
			r1.Metadata["binary_hash"], r2.Metadata["binary_hash"])
	}
}

func TestBinaryAttestor_BadPath(t *testing.T) {
	a := NewBinaryAttestor("/nonexistent/binary")
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Error("expected error for nonexistent binary path")
	}
}

func TestBinaryAttestor_AutoDetectPath(t *testing.T) {
	a := NewBinaryAttestor("")
	result, err := a.Attest(context.Background())
	if err != nil {
		t.Fatalf("Attest() with auto-detect error: %v", err)
	}
	if result.Source != "binary-self" {
		t.Errorf("Source = %q, want binary-self", result.Source)
	}
	if result.Metadata["binary_hash"] == "" {
		t.Error("expected non-empty binary_hash with auto-detect")
	}
}

func TestBinaryAttestor_DirectoryAsPath(t *testing.T) {
	a := NewBinaryAttestor(t.TempDir())
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Error("expected error when path is a directory")
	}
}

func TestBinaryAttestor_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noperm-binary")
	if err := os.WriteFile(path, []byte("binary-content"), 0000); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0644) })

	a := NewBinaryAttestor(path)
	_, err := a.Attest(context.Background())
	if err == nil {
		t.Error("expected error for permission denied")
	}
}
