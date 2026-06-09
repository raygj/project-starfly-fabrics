package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ErrNotFound is returned when a key does not exist in the store.
var ErrNotFound = errors.New("key not found")

// Compile-time check that BadgerStore implements core.Store.
var _ core.Store = (*BadgerStore)(nil)

// BadgerStore implements core.Store backed by badger with locked values.
type BadgerStore struct {
	db     *badger.DB
	locker core.Locker
}

// New opens a badger database at path and returns a BadgerStore.
func New(path string, locker core.Locker) (*BadgerStore, error) {
	opts := badger.DefaultOptions(path).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &BadgerStore{db: db, locker: locker}, nil
}

// Get retrieves a single entry by key. Returns ErrNotFound if the key does not exist.
func (s *BadgerStore) Get(_ context.Context, key string) (*core.StoreEntry, error) {
	var entry core.StoreEntry
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return ErrNotFound
			}
			return err
		}
		return item.Value(func(val []byte) error {
			plain, err := s.locker.Unlock(val)
			if err != nil {
				return err
			}
			return json.Unmarshal(plain, &entry)
		})
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// Put creates or updates a key. Version is incremented on each write and
// CreatedAt is preserved across updates.
func (s *BadgerStore) Put(_ context.Context, key string, value []byte) (*core.StoreEntry, error) {
	var result core.StoreEntry
	err := s.db.Update(func(txn *badger.Txn) error {
		now := time.Now().UTC()
		var version uint64
		createdAt := now

		// Check for existing entry to preserve version and CreatedAt.
		item, err := txn.Get([]byte(key))
		if err == nil {
			// Key exists — read existing entry.
			if err := item.Value(func(val []byte) error {
				plain, err := s.locker.Unlock(val)
				if err != nil {
					return err
				}
				var existing core.StoreEntry
				if err := json.Unmarshal(plain, &existing); err != nil {
					return err
				}
				version = existing.Version
				createdAt = existing.CreatedAt
				return nil
			}); err != nil {
				return err
			}
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}

		result = core.StoreEntry{
			Key:       key,
			Value:     value,
			Version:   version + 1,
			CreatedAt: createdAt,
			UpdatedAt: now,
		}

		jsonBytes, err := json.Marshal(&result)
		if err != nil {
			return err
		}
		locked, err := s.locker.Lock(jsonBytes)
		if err != nil {
			return err
		}
		return txn.Set([]byte(key), locked)
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// Delete removes a key from the store. It is idempotent — deleting a
// non-existent key returns nil.
func (s *BadgerStore) Delete(_ context.Context, key string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete([]byte(key))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	})
}

// List returns all keys matching the given prefix.
func (s *BadgerStore) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = []byte(prefix)
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			keys = append(keys, string(it.Item().Key()))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []string{}
	}
	return keys, nil
}

// DB returns the underlying badger database for direct access (e.g. migrations).
func (s *BadgerStore) DB() *badger.DB { return s.db }

// Close closes the underlying badger database.
func (s *BadgerStore) Close() error {
	return s.db.Close()
}
