package federation

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Resolver implements cross-cluster JWKS resolution by wrapping a local
// JWKSResolver and maintaining per-peer background prefetch goroutines.
//
// Resolution order:
//  1. Local cache (existing JWKSResolver)
//  2. Federated peer caches (matched by issuer URL)
//
// The resolver is transparent to identity providers — they call ResolveKey
// with an issuer URL and get back a key, whether local or federated.
type Resolver struct {
	local core.JWKSResolver

	mu    sync.RWMutex
	peers map[string]*peer // fabricId → peer

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// peer tracks a single federated peer's JWKS state.
type peer struct {
	config PeerConfig

	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey // kid → public key
	lastSeen    time.Time
	lastAttempt time.Time
	lastError   string
	fetchCount  atomic.Uint64
	errorCount  atomic.Uint64

	client *http.Client
}

// ResolverConfig configures the federated resolver.
type ResolverConfig struct {
	// Local is the existing JWKS resolver for local key resolution.
	Local core.JWKSResolver

	// Peers is the list of federated peer configurations.
	Peers []PeerConfig

	// HTTPClient is used for JWKS fetches. Nil uses a default with 10s timeout.
	HTTPClient *http.Client
}

// NewResolver creates a federated resolver and starts background prefetch
// goroutines for each configured peer. Call Close to stop all goroutines.
func NewResolver(cfg ResolverConfig) *Resolver {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = core.NewDefaultHTTPClient()
	}

	r := &Resolver{
		local:  cfg.Local,
		peers:  make(map[string]*peer, len(cfg.Peers)),
		stopCh: make(chan struct{}),
	}

	for _, pc := range cfg.Peers {
		pc.ApplyDefaults()
		p := &peer{
			config: pc,
			keys:   make(map[string]crypto.PublicKey),
			client: httpClient,
		}
		r.peers[pc.FabricID] = p

		// Start background prefetch goroutine for this peer.
		r.wg.Add(1)
		go r.refreshLoop(p)

		slog.Info("federation peer configured",
			"fabric_id", pc.FabricID,
			"jwks_endpoint", pc.JWKSEndpoint,
			"refresh_interval", pc.RefreshInterval,
		)
	}

	return r
}

// ResolveKey resolves a public key by issuer and kid.
// Checks local cache first, then federated peer caches.
func (r *Resolver) ResolveKey(ctx context.Context, issuer string, kid string) (crypto.PublicKey, error) {
	// 1. Try local resolver first.
	if r.local != nil {
		key, err := r.local.ResolveKey(ctx, issuer, kid)
		if err == nil {
			return key, nil
		}
		// Local miss — fall through to federation.
	}

	// 2. Check federated peer caches.
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.peers {
		// Match by JWKS endpoint URL (issuer may be the JWKS URL itself).
		if p.config.JWKSEndpoint != issuer {
			continue
		}

		p.mu.RLock()
		key, ok := p.keys[kid]
		p.mu.RUnlock()

		if ok {
			return key, nil
		}
	}

	// 3. Try on-demand fetch from any peer whose endpoint matches.
	for _, p := range r.peers {
		if p.config.JWKSEndpoint != issuer {
			continue
		}

		// Fetch and retry lookup.
		if err := r.fetchPeerKeys(ctx, p); err != nil {
			slog.Warn("federation on-demand fetch failed",
				"fabric_id", p.config.FabricID, "error", err)
			continue
		}

		p.mu.RLock()
		key, ok := p.keys[kid]
		p.mu.RUnlock()

		if ok {
			return key, nil
		}
	}

	return nil, fmt.Errorf("key %q not found for issuer %q (checked local + %d federation peers)", kid, issuer, len(r.peers))
}

// Prefetch warms the cache for known issuers. Delegates to local resolver
// and triggers immediate fetch for all federation peers.
func (r *Resolver) Prefetch(ctx context.Context, issuers []string) error {
	// Prefetch local.
	if r.local != nil {
		if err := r.local.Prefetch(ctx, issuers); err != nil {
			slog.Warn("local prefetch error", "error", err)
		}
	}

	// Prefetch all federation peers.
	r.mu.RLock()
	peers := make([]*peer, 0, len(r.peers))
	for _, p := range r.peers {
		peers = append(peers, p)
	}
	r.mu.RUnlock()

	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p *peer) {
			defer wg.Done()
			if err := r.fetchPeerKeys(ctx, p); err != nil {
				slog.Warn("federation prefetch failed",
					"fabric_id", p.config.FabricID, "error", err)
			}
		}(p)
	}
	wg.Wait()

	return nil
}

// Stats returns cache stats from the local resolver.
func (r *Resolver) Stats() core.JWKSCacheStats {
	if r.local != nil {
		return r.local.Stats()
	}
	return core.JWKSCacheStats{}
}

// State returns the current federation state for all peers.
func (r *Resolver) State() *FederationState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	state := &FederationState{
		Peers:     make(map[string]*PeerState, len(r.peers)),
		UpdatedAt: time.Now(),
	}

	for id, p := range r.peers {
		p.mu.RLock()
		ps := &PeerState{
			Config:     p.config,
			LastSeen:   p.lastSeen,
			LastAttempt: p.lastAttempt,
			LastError:  p.lastError,
			KeyCount:   len(p.keys),
			FetchCount: p.fetchCount.Load(),
			ErrorCount: p.errorCount.Load(),
		}
		p.mu.RUnlock()

		// Compute status.
		ps.Status = r.computePeerStatus(p)
		state.Peers[id] = ps
	}

	return state
}

// Close stops all background prefetch goroutines.
func (r *Resolver) Close() {
	close(r.stopCh)
	r.wg.Wait()
}

// refreshLoop runs the background prefetch for a single peer.
func (r *Resolver) refreshLoop(p *peer) {
	defer r.wg.Done()

	// Initial fetch.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := r.fetchPeerKeys(ctx, p); err != nil {
		slog.Warn("federation initial fetch failed",
			"fabric_id", p.config.FabricID, "error", err)
	}
	cancel()

	ticker := time.NewTicker(p.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := r.fetchPeerKeys(ctx, p); err != nil {
				slog.Warn("federation refresh failed",
					"fabric_id", p.config.FabricID, "error", err)
			}
			cancel()
		}
	}
}

// fetchPeerKeys fetches the JWKS from a peer's endpoint and updates the cache.
func (r *Resolver) fetchPeerKeys(ctx context.Context, p *peer) error {
	p.mu.Lock()
	p.lastAttempt = time.Now()
	p.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.JWKSEndpoint, nil)
	if err != nil {
		p.errorCount.Add(1)
		p.mu.Lock()
		p.lastError = err.Error()
		p.mu.Unlock()
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		p.errorCount.Add(1)
		p.mu.Lock()
		p.lastError = err.Error()
		p.mu.Unlock()
		return fmt.Errorf("fetching JWKS from %s: %w", p.config.JWKSEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		p.errorCount.Add(1)
		p.mu.Lock()
		p.lastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
		p.mu.Unlock()
		return fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	keys, err := parseJWKSResponse(resp)
	if err != nil {
		p.errorCount.Add(1)
		p.mu.Lock()
		p.lastError = err.Error()
		p.mu.Unlock()
		return err
	}

	// Update cache.
	p.mu.Lock()
	p.keys = keys
	p.lastSeen = time.Now()
	p.lastError = ""
	p.mu.Unlock()
	p.fetchCount.Add(1)

	slog.Debug("federation JWKS refreshed",
		"fabric_id", p.config.FabricID,
		"key_count", len(keys),
	)

	return nil
}

// computePeerStatus determines the health status of a peer.
func (r *Resolver) computePeerStatus(p *peer) PeerStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.lastSeen.IsZero() {
		if p.lastError != "" {
			return PeerUnreachable
		}
		return PeerStale // never fetched
	}

	age := time.Since(p.lastSeen)
	if age > p.config.StalenessThreshold {
		if p.lastError != "" {
			return PeerUnreachable
		}
		return PeerStale
	}

	return PeerHealthy
}
