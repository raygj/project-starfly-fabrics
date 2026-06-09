package lock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/dgraph-io/badger/v4"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// openTestDB returns a temporary in-memory Badger DB for testing.
func openTestDB(t *testing.T) *badger.DB {
	t.Helper()
	opts := badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedEntries writes n StoreEntry values encrypted with locker into db.
func seedEntries(t *testing.T, db *badger.DB, locker core.Locker, n int) {
	t.Helper()
	err := db.Update(func(txn *badger.Txn) error {
		for i := range n {
			entry := core.StoreEntry{
				Key:     fmt.Sprintf("key/%d", i),
				Value:   []byte(fmt.Sprintf("value-%d", i)),
				Version: uint64(i + 1),
			}
			raw, err := json.Marshal(&entry)
			if err != nil {
				return err
			}
			locked, err := locker.Lock(raw)
			if err != nil {
				return err
			}
			if err := txn.Set([]byte(entry.Key), locked); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seeding entries: %v", err)
	}
}

// testLogger returns a slog.Logger that writes to os.Stderr (visible with -v).
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestMigrate(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}
	dst := newKMSLockerWithClient(xorMock(), "test-key")

	seedEntries(t, db, src, 5)

	result, err := Migrate(context.Background(), db, src, dst, nil, "unit-test", testLogger())
	if err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}
	if result.KeyCount != 5 {
		t.Errorf("KeyCount = %d, want 5", result.KeyCount)
	}

	// Verify all entries are readable with the new locker and data is preserved.
	err = db.View(func(txn *badger.Txn) error {
		for i := range 5 {
			key := fmt.Sprintf("key/%d", i)
			item, err := txn.Get([]byte(key))
			if err != nil {
				return fmt.Errorf("get %q: %w", key, err)
			}
			if err := item.Value(func(val []byte) error {
				plain, err := dst.Unlock(val)
				if err != nil {
					return fmt.Errorf("unlock %q: %w", key, err)
				}
				var entry core.StoreEntry
				if err := json.Unmarshal(plain, &entry); err != nil {
					return fmt.Errorf("unmarshal %q: %w", key, err)
				}
				wantVal := fmt.Sprintf("value-%d", i)
				if string(entry.Value) != wantVal {
					return fmt.Errorf("entry %q value = %q, want %q", key, entry.Value, wantVal)
				}
				if entry.Version != uint64(i+1) {
					return fmt.Errorf("entry %q version = %d, want %d", key, entry.Version, i+1)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verification: %v", err)
	}
}

func TestMigrate_EmptyStore(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}
	dst := &DevLocker{}

	result, err := Migrate(context.Background(), db, src, dst, nil, "unit-test", testLogger())
	if err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}
	if result.KeyCount != 0 {
		t.Errorf("KeyCount = %d, want 0", result.KeyCount)
	}
}

func TestMigrate_RollbackOnEncryptError(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}

	seedEntries(t, db, src, 3)

	// dst that fails on the second Lock() call.
	callCount := 0
	failMock := &mockKMSClient{
		encryptFn: func(_ context.Context, input *kms.EncryptInput) (*kms.EncryptOutput, error) {
			callCount++
			if callCount >= 2 {
				return nil, errors.New("kms encrypt failure")
			}
			return xorMock().encryptFn(context.Background(), input)
		},
		decryptFn: xorMock().decryptFn,
	}
	dst := newKMSLockerWithClient(failMock, "test-key")

	_, err := Migrate(context.Background(), db, src, dst, nil, "unit-test", testLogger())
	if err == nil {
		t.Fatal("Migrate() should return error when dst.Lock() fails")
	}

	// Originals still readable with src.
	err = db.View(func(txn *badger.Txn) error {
		for i := range 3 {
			key := fmt.Sprintf("key/%d", i)
			item, err := txn.Get([]byte(key))
			if err != nil {
				return fmt.Errorf("get %q: %w", key, err)
			}
			if err := item.Value(func(val []byte) error {
				plain, err := src.Unlock(val)
				if err != nil {
					return fmt.Errorf("unlock %q with src: %w", key, err)
				}
				var entry core.StoreEntry
				return json.Unmarshal(plain, &entry)
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("originals should be intact: %v", err)
	}
}

func TestMigrate_RollbackOnDecryptError(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}

	seedEntries(t, db, src, 3)

	// Wrap src so Unlock fails.
	failSrc := &failingUnlocker{wrapped: src, failAfter: 1}

	dst := &DevLocker{}

	_, err := Migrate(context.Background(), db, failSrc, dst, nil, "unit-test", testLogger())
	if err == nil {
		t.Fatal("Migrate() should return error when src.Unlock() fails")
	}

	// Originals still readable with the real src.
	err = db.View(func(txn *badger.Txn) error {
		for i := range 3 {
			key := fmt.Sprintf("key/%d", i)
			item, err := txn.Get([]byte(key))
			if err != nil {
				return fmt.Errorf("get %q: %w", key, err)
			}
			if err := item.Value(func(val []byte) error {
				plain, err := src.Unlock(val)
				if err != nil {
					return fmt.Errorf("unlock %q with src: %w", key, err)
				}
				var entry core.StoreEntry
				return json.Unmarshal(plain, &entry)
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("originals should be intact: %v", err)
	}
}

func TestMigrate_WithAuditor(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}
	dst := newKMSLockerWithClient(xorMock(), "test-key")

	seedEntries(t, db, src, 3)

	auditor := &mockAuditor{}

	result, err := Migrate(context.Background(), db, src, dst, auditor, "unit-audit", testLogger())
	if err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}
	if result.KeyCount != 3 {
		t.Errorf("KeyCount = %d, want 3", result.KeyCount)
	}

	actions := auditor.actions()
	if len(actions) < 2 {
		t.Fatalf("auditor got %d events, want at least 2 (started + complete)", len(actions))
	}
	if actions[0] != "lock_migration_started" {
		t.Errorf("first event = %q, want lock_migration_started", actions[0])
	}
	if actions[len(actions)-1] != "lock_migration_complete" {
		t.Errorf("last event = %q, want lock_migration_complete", actions[len(actions)-1])
	}
}

func TestMigrate_WithAuditor_EmptyStore(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}
	dst := &DevLocker{}

	auditor := &mockAuditor{}

	result, err := Migrate(context.Background(), db, src, dst, auditor, "unit-audit", testLogger())
	if err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}
	if result.KeyCount != 0 {
		t.Errorf("KeyCount = %d, want 0", result.KeyCount)
	}

	actions := auditor.actions()
	if len(actions) != 2 {
		t.Fatalf("auditor got %d events, want 2", len(actions))
	}
}

func TestMigrate_WithAuditor_OnError(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}
	seedEntries(t, db, src, 2)

	failMock := &mockKMSClient{
		encryptFn: func(_ context.Context, _ *kms.EncryptInput) (*kms.EncryptOutput, error) {
			return nil, errors.New("kms failure")
		},
		decryptFn: xorMock().decryptFn,
	}
	dst := newKMSLockerWithClient(failMock, "test-key")
	auditor := &mockAuditor{}

	_, err := Migrate(context.Background(), db, src, dst, auditor, "unit-err", testLogger())
	if err == nil {
		t.Fatal("expected error")
	}

	actions := auditor.actions()
	found := false
	for _, a := range actions {
		if a == "lock_migration_failed" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected lock_migration_failed audit event; got %v", actions)
	}
}

func TestMigrate_ProgressInterval(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}
	dst := newKMSLockerWithClient(xorMock(), "test-key")

	seedEntries(t, db, src, 200)

	result, err := Migrate(context.Background(), db, src, dst, nil, "unit-progress", testLogger())
	if err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}
	if result.KeyCount != 200 {
		t.Errorf("KeyCount = %d, want 200", result.KeyCount)
	}
}

func TestMigrate_LargeProgressInterval(t *testing.T) {
	db := openTestDB(t)
	src := &DevLocker{}
	dst := newKMSLockerWithClient(xorMock(), "test-key")

	seedEntries(t, db, src, 1100)

	result, err := Migrate(context.Background(), db, src, dst, nil, "unit-large", testLogger())
	if err != nil {
		t.Fatalf("Migrate() error: %v", err)
	}
	if result.KeyCount != 1100 {
		t.Errorf("KeyCount = %d, want 1100", result.KeyCount)
	}
}

// mockAuditor records audit events for verification.
type mockAuditor struct {
	mu     sync.Mutex
	events []*core.AuditEvent
}

func (m *mockAuditor) Log(_ context.Context, event *core.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuditor) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.events))
	for i, e := range m.events {
		out[i] = e.Action
	}
	return out
}

// failingUnlocker wraps a Locker and fails Unlock after N successful calls.
type failingUnlocker struct {
	wrapped   core.Locker
	failAfter int
	calls     int
}

func (f *failingUnlocker) Lock(data []byte) ([]byte, error) {
	return f.wrapped.Lock(data)
}

func (f *failingUnlocker) Unlock(data []byte) ([]byte, error) {
	f.calls++
	if f.calls > f.failAfter {
		return nil, errors.New("simulated decrypt failure")
	}
	return f.wrapped.Unlock(data)
}
