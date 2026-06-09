package identity

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Registry implements core.IdentityProvider by dispatching to
// the correct provider based on credType. This is the composite
// pattern from ADR-0006 — the exchange engine doesn't know or
// care about multi-provider dispatch.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]core.IdentityProvider // credType → provider
}

// NewRegistry creates an empty credential registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]core.IdentityProvider)}
}

// Register adds a provider for the given credential type.
// Logs a warning if a provider is already registered for the credType.
func (r *Registry) Register(credType string, p core.IdentityProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[credType]; exists {
		slog.Warn("overwriting identity provider registration", "cred_type", credType)
	}
	r.providers[credType] = p
}

// ValidateWorkload dispatches to the provider registered for credType.
// Returns a clear error listing supported types if no provider is registered.
func (r *Registry) ValidateWorkload(ctx context.Context, credential string, credType string) (*core.WorkloadIdentity, error) {
	r.mu.RLock()
	p, ok := r.providers[credType]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no provider registered for credential type %q (supported: %s)", credType, r.supportedTypes())
	}
	return p.ValidateWorkload(ctx, credential, credType)
}

// Unregister removes the provider for the given credential type.
// Returns false if no provider was registered for that type.
func (r *Registry) Unregister(credType string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, exists := r.providers[credType]
	if exists {
		delete(r.providers, credType)
		slog.Info("identity provider unregistered", "cred_type", credType)
	}
	return exists
}

// List returns a sorted list of registered credential types.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.providers))
	for t := range r.providers {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// Len returns the number of registered providers.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// supportedTypes returns a sorted, comma-separated list of registered credential types.
// Caller must NOT hold r.mu (this method acquires its own read lock).
func (r *Registry) supportedTypes() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	types := make([]string, 0, len(r.providers))
	for t := range r.providers {
		types = append(types, t)
	}
	sort.Strings(types)
	return strings.Join(types, ", ")
}
