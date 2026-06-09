package agent

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileTokenServer_StartCreatesDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "token")

	srv := NewFileTokenServer(path)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Error("Start() did not create parent directory")
	}
}

func TestFileTokenServer_UpdateAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")

	srv := NewFileTokenServer(path)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	token := "eyJhbGciOiJSUzI1NiJ9.test-payload.signature"
	if err := srv.UpdateToken(token); err != nil {
		t.Fatalf("UpdateToken() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	if string(data) != token {
		t.Errorf("token content = %q, want %q", string(data), token)
	}

	// Verify file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestFileTokenServer_AtomicOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")

	srv := NewFileTokenServer(path)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if err := srv.UpdateToken("token-v1"); err != nil {
		t.Fatalf("first UpdateToken() error: %v", err)
	}

	if err := srv.UpdateToken("token-v2"); err != nil {
		t.Fatalf("second UpdateToken() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if string(data) != "token-v2" {
		t.Errorf("token = %q, want token-v2", string(data))
	}

	// Verify no .tmp file left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp file should not exist after successful update")
	}
}

func TestFileTokenServer_ConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")

	srv := NewFileTokenServer(path)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 50)

	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			token := "token-" + string(rune('A'+n%26))
			if err := srv.UpdateToken(token); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent UpdateToken() error: %v", err)
	}

	// File must exist and be non-empty.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if len(data) == 0 {
		t.Error("token file is empty after concurrent writes")
	}
}

func TestFileTokenServer_Name(t *testing.T) {
	srv := NewFileTokenServer("/tmp/token")
	if srv.Name() != "file" {
		t.Errorf("Name() = %q, want file", srv.Name())
	}
}

func TestFileTokenServer_UpdateToken_BadDirectory(t *testing.T) {
	srv := NewFileTokenServer("/dev/null/impossible/token")
	err := srv.UpdateToken("some-token")
	if err == nil {
		t.Error("expected error when writing to impossible path")
	}
}

func TestFileTokenServer_Start_BadPath(t *testing.T) {
	srv := NewFileTokenServer("/dev/null/impossible/nested/token")
	err := srv.Start(context.Background())
	if err == nil {
		t.Error("expected error when creating directory under /dev/null")
	}
}

func TestFileTokenServer_UpdateToken_EmptyToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	srv := NewFileTokenServer(path)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	if err := srv.UpdateToken(""); err != nil {
		t.Fatalf("UpdateToken() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty file, got %d bytes", len(data))
	}
}

func TestFileTokenServer_Start_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readOnlyDir, 0555); err != nil {
		t.Fatalf("Mkdir() error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnlyDir, 0755) })

	srv := NewFileTokenServer(filepath.Join(readOnlyDir, "subdir", "token"))
	err := srv.Start(context.Background())
	if err == nil {
		t.Error("expected error when creating subdirectory in read-only dir")
	}
}
