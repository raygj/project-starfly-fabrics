package secrets

import (
	"context"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// EncryptionKeyStore stores workload encryption public keys for JWE.
type EncryptionKeyStore interface {
	// Register stores a workload's public encryption key.
	Register(ctx context.Context, workloadID string, key jwk.Key) error

	// Get retrieves the encryption key for a workload.
	// Returns an error if no key is registered.
	Get(ctx context.Context, workloadID string) (jwk.Key, error)
}

// InMemoryKeyStore is a thread-safe in-memory EncryptionKeyStore.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]jwk.Key
}

// NewInMemoryKeyStore creates an empty in-memory key store.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{keys: make(map[string]jwk.Key)}
}

// Register stores or overwrites the encryption key for a workload.
func (s *InMemoryKeyStore) Register(_ context.Context, workloadID string, key jwk.Key) error {
	if workloadID == "" {
		return fmt.Errorf("workload ID is required")
	}
	if key == nil {
		return fmt.Errorf("key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[workloadID] = key
	return nil
}

// Get retrieves the encryption key for a workload.
func (s *InMemoryKeyStore) Get(_ context.Context, workloadID string) (jwk.Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[workloadID]
	if !ok {
		return nil, fmt.Errorf("no encryption key registered for %q", workloadID)
	}
	return key, nil
}
