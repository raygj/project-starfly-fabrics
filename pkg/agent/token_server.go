package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// FileTokenServer writes the WIMSE JWT to a file using atomic rename.
// Concurrent readers never see partial writes.
type FileTokenServer struct {
	path string
	mu   sync.Mutex
}

// NewFileTokenServer creates a FileTokenServer that writes to the given path.
func NewFileTokenServer(path string) *FileTokenServer {
	return &FileTokenServer{path: path}
}

func (f *FileTokenServer) Name() string { return "file" }

// Start creates the parent directory if needed and verifies writability.
func (f *FileTokenServer) Start(_ context.Context) error {
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating token directory %s: %w", dir, err)
	}

	// Verify writability by touching the tmp file.
	tmp := f.path + ".tmp"
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("token path not writable: %w", err)
	}
	_ = tf.Close()
	_ = os.Remove(tmp)

	slog.Info("file token server ready", "path", f.path)
	return nil
}

// UpdateToken writes the token to a temporary file and atomically
// renames it to the target path. File permissions are 0600.
func (f *FileTokenServer) UpdateToken(token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	tmp := f.path + ".tmp"

	if err := os.WriteFile(tmp, []byte(token), 0600); err != nil {
		return fmt.Errorf("writing tmp token file: %w", err)
	}

	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomic rename to %s: %w", f.path, err)
	}

	slog.Debug("token updated", "path", f.path, "bytes", len(token))
	return nil
}
