// Package secrets implements converged credential management (ADR-0014).
//
// Secret Phase 1 delivers encrypted secrets inside WIMSE JWTs via JWE (RFC 7516).
// Workloads exchange a credential and receive identity + secrets in one round-trip.
// Secrets inherit JWT properties: 5-min TTL, DPoP-bound, revocable via CAEP, audited.
package secrets

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SecretRef identifies a secret to be fetched from a source.
type SecretRef struct {
	// Source is the name of the SecretSource to fetch from (e.g., "static", "vault").
	Source string `json:"source"`

	// Path is the source-specific path to the secret (e.g., Vault KV path).
	Path string `json:"path"`

	// Key is the specific key within the secret data at Path.
	Key string `json:"key"`

	// Alias is the claim name under which this secret appears in the bundle.
	// If empty, Key is used.
	Alias string `json:"alias,omitempty"`
}

// SecretBundle is the result of fetching secrets — a map of alias→value
// with a TTL that should not exceed the enclosing JWT's TTL.
type SecretBundle struct {
	// Claims maps alias (or key) → secret value.
	Claims map[string]string `json:"claims"`

	// TTL is the maximum lifetime for the bundle. The enclosing JWT's exp
	// should be min(jwt_ttl, bundle_ttl).
	TTL time.Duration `json:"ttl"`
}

// SecretSource fetches secrets from a backend (static config, Vault, etc.).
type SecretSource interface {
	// Name returns the source identifier (e.g., "static", "vault").
	Name() string

	// Available reports whether the source is reachable.
	Available(ctx context.Context) bool

	// Fetch retrieves the secrets identified by refs. All refs MUST target
	// this source (caller is responsible for dispatching).
	Fetch(ctx context.Context, refs []SecretRef) (*SecretBundle, error)
}

// Registry holds multiple SecretSources keyed by name and dispatches
// Fetch calls to the correct source.
type Registry struct {
	mu      sync.RWMutex
	sources map[string]SecretSource
}

// NewRegistry creates an empty secret source registry.
func NewRegistry() *Registry {
	return &Registry{sources: make(map[string]SecretSource)}
}

// Register adds a source. Overwrites if a source with the same name exists.
func (r *Registry) Register(source SecretSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[source.Name()] = source
}

// Fetch groups refs by source name and fetches from each, merging results.
func (r *Registry) Fetch(ctx context.Context, refs []SecretRef) (*SecretBundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Group refs by source.
	grouped := make(map[string][]SecretRef)
	for _, ref := range refs {
		grouped[ref.Source] = append(grouped[ref.Source], ref)
	}

	merged := &SecretBundle{Claims: make(map[string]string)}

	for srcName, srcRefs := range grouped {
		src, ok := r.sources[srcName]
		if !ok {
			return nil, fmt.Errorf("unknown secret source: %q", srcName)
		}
		if !src.Available(ctx) {
			return nil, fmt.Errorf("secret source %q unavailable", srcName)
		}
		bundle, err := src.Fetch(ctx, srcRefs)
		if err != nil {
			return nil, fmt.Errorf("fetching from %q: %w", srcName, err)
		}
		for k, v := range bundle.Claims {
			merged.Claims[k] = v
		}
		// Use the shortest TTL across sources.
		if bundle.TTL > 0 && (merged.TTL == 0 || bundle.TTL < merged.TTL) {
			merged.TTL = bundle.TTL
		}
	}

	return merged, nil
}

// Available reports whether a named source is registered and reachable.
func (r *Registry) Available(ctx context.Context, sourceName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src, ok := r.sources[sourceName]
	if !ok {
		return false
	}
	return src.Available(ctx)
}

// Sources returns the names of all registered sources.
func (r *Registry) Sources() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.sources))
	for name := range r.sources {
		names = append(names, name)
	}
	return names
}
