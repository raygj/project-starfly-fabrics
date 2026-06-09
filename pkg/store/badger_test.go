package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/lock"
	"github.com/starfly-fabrics/starfly/pkg/store"
)

func newTestStore(t *testing.T) *store.BadgerStore {
	t.Helper()
	s, err := store.New(t.TempDir(), &lock.DevLocker{})
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBadgerStore_DB(t *testing.T) {
	s := newTestStore(t)
	if s.DB() == nil {
		t.Error("DB() should return non-nil database")
	}
}

type failLocker struct {
	lockErr   error
	unlockErr error
}

func (f *failLocker) Lock(data []byte) ([]byte, error) {
	if f.lockErr != nil {
		return nil, f.lockErr
	}
	return data, nil
}

func (f *failLocker) Unlock(data []byte) ([]byte, error) {
	if f.unlockErr != nil {
		return nil, f.unlockErr
	}
	return data, nil
}

func newTestStoreWithLocker(t *testing.T, locker interface{ Lock([]byte) ([]byte, error); Unlock([]byte) ([]byte, error) }) *store.BadgerStore {
	t.Helper()
	s, err := store.New(t.TempDir(), locker)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBadgerStore_Put_LockError(t *testing.T) {
	fl := &failLocker{lockErr: errors.New("lock broken")}
	s := newTestStoreWithLocker(t, fl)
	ctx := context.Background()

	_, err := s.Put(ctx, "k1", []byte("val"))
	if err == nil {
		t.Error("expected error when locker.Lock fails")
	}
}

func TestBadgerStore_Put_UpdateWithUnlockError(t *testing.T) {
	ctx := context.Background()

	// Use a locker that succeeds first put, then fails unlock on second put.
	switchLocker := &switchingLocker{
		inner:     &lock.DevLocker{},
		failAfter: 0,
	}
	s := newTestStoreWithLocker(t, switchLocker)

	if _, err := s.Put(ctx, "k1", []byte("v1")); err != nil {
		t.Fatalf("first put: %v", err)
	}

	// Second put needs to read the existing entry (which calls Unlock).
	_, err := s.Put(ctx, "k1", []byte("v2"))
	if err == nil {
		t.Error("expected error when unlock fails during put update")
	}
}

// switchingLocker succeeds for the first N unlock calls, then fails.
type switchingLocker struct {
	inner     *lock.DevLocker
	failAfter int
	calls     int
}

func (s *switchingLocker) Lock(data []byte) ([]byte, error) {
	return s.inner.Lock(data)
}

func (s *switchingLocker) Unlock(data []byte) ([]byte, error) {
	s.calls++
	if s.calls > s.failAfter {
		return nil, errors.New("simulated unlock failure")
	}
	return s.inner.Unlock(data)
}

func TestBadgerStore_New_BadPath(t *testing.T) {
	_, err := store.New("/dev/null/impossible", &lock.DevLocker{})
	if err == nil {
		t.Error("expected error for impossible path")
	}
}

func TestBadgerStore(t *testing.T) {
	ctx := context.Background()

	t.Run("put and get roundtrip", func(t *testing.T) {
		s := newTestStore(t)
		entry, err := s.Put(ctx, "k1", []byte("hello"))
		if err != nil {
			t.Fatalf("put: %v", err)
		}
		if entry.Key != "k1" {
			t.Errorf("key = %q, want %q", entry.Key, "k1")
		}
		if string(entry.Value) != "hello" {
			t.Errorf("value = %q, want %q", entry.Value, "hello")
		}
		if entry.Version != 1 {
			t.Errorf("version = %d, want 1", entry.Version)
		}
		if entry.CreatedAt.IsZero() || entry.UpdatedAt.IsZero() {
			t.Error("timestamps should be set")
		}

		got, err := s.Get(ctx, "k1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if string(got.Value) != "hello" {
			t.Errorf("get value = %q, want %q", got.Value, "hello")
		}
		if got.Version != 1 {
			t.Errorf("get version = %d, want 1", got.Version)
		}
	})

	t.Run("versioning increments and preserves CreatedAt", func(t *testing.T) {
		s := newTestStore(t)
		e1, err := s.Put(ctx, "k1", []byte("v1"))
		if err != nil {
			t.Fatalf("put 1: %v", err)
		}
		createdAt := e1.CreatedAt

		time.Sleep(5 * time.Millisecond) // ensure UpdatedAt differs

		e2, err := s.Put(ctx, "k1", []byte("v2"))
		if err != nil {
			t.Fatalf("put 2: %v", err)
		}
		if e2.Version != 2 {
			t.Errorf("version = %d, want 2", e2.Version)
		}
		if !e2.CreatedAt.Equal(createdAt) {
			t.Errorf("CreatedAt changed: %v → %v", createdAt, e2.CreatedAt)
		}
		if !e2.UpdatedAt.After(e1.UpdatedAt) {
			t.Error("UpdatedAt should advance on second put")
		}
	})

	t.Run("delete removes key", func(t *testing.T) {
		s := newTestStore(t)
		if _, err := s.Put(ctx, "k1", []byte("v")); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := s.Delete(ctx, "k1"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		_, err := s.Get(ctx, "k1")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("get after delete: got %v, want ErrNotFound", err)
		}
	})

	t.Run("delete idempotent on missing key", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.Delete(ctx, "nonexistent"); err != nil {
			t.Errorf("delete nonexistent: %v", err)
		}
	})

	t.Run("list with prefix", func(t *testing.T) {
		s := newTestStore(t)
		for _, k := range []string{"app/a", "app/b", "other/c"} {
			if _, err := s.Put(ctx, k, []byte("x")); err != nil {
				t.Fatalf("put %s: %v", k, err)
			}
		}
		keys, err := s.List(ctx, "app/")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("list len = %d, want 2; keys = %v", len(keys), keys)
		}
	})

	t.Run("list empty store returns empty slice", func(t *testing.T) {
		s := newTestStore(t)
		keys, err := s.List(ctx, "any/")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("list len = %d, want 0", len(keys))
		}
	})

	t.Run("get not found", func(t *testing.T) {
		s := newTestStore(t)
		_, err := s.Get(ctx, "missing")
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})
}
