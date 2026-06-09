package federation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── Test helpers ──────────────────────────────────────────────────────

// generateTestKey creates a test ECDSA key pair and returns it as a JWK Set JSON.
func generateTestKey(kid string) ([]byte, crypto.PublicKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	key, err := jwk.Import(priv.Public())
	if err != nil {
		panic(err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		panic(err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		panic(err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		panic(err)
	}

	data, err := json.Marshal(set)
	if err != nil {
		panic(err)
	}

	return data, priv.Public()
}

// serveJWKS creates a test HTTP server that serves a JWKS with the given keys.
func serveJWKS(t *testing.T, kids ...string) (*httptest.Server, map[string]crypto.PublicKey) {
	t.Helper()
	pubKeys := make(map[string]crypto.PublicKey)

	set := jwk.NewSet()
	for _, kid := range kids {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubKeys[kid] = priv.Public()

		key, err := jwk.Import(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatal(err)
		}
		if err := set.AddKey(key); err != nil {
			t.Fatal(err)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(set)
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	return srv, pubKeys
}

// mockLocalResolver is a test double for the local JWKSResolver.
type mockLocalResolver struct {
	keys   map[string]map[string]crypto.PublicKey // issuer → kid → key
	called atomic.Int64
}

func newMockLocalResolver() *mockLocalResolver {
	return &mockLocalResolver{
		keys: make(map[string]map[string]crypto.PublicKey),
	}
}

func (m *mockLocalResolver) AddKey(issuer, kid string, key crypto.PublicKey) {
	if m.keys[issuer] == nil {
		m.keys[issuer] = make(map[string]crypto.PublicKey)
	}
	m.keys[issuer][kid] = key
}

func (m *mockLocalResolver) ResolveKey(_ context.Context, issuer string, kid string) (crypto.PublicKey, error) {
	m.called.Add(1)
	if keys, ok := m.keys[issuer]; ok {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key %q not found for issuer %q", kid, issuer)
}

func (m *mockLocalResolver) Prefetch(_ context.Context, _ []string) error {
	return nil
}

func (m *mockLocalResolver) Stats() core.JWKSCacheStats {
	return core.JWKSCacheStats{}
}

// ── Tests ─────────────────────────────────────────────────────────────

func TestResolver_LocalFirst(t *testing.T) {
	local := newMockLocalResolver()
	_, pubKey := generateTestKey("local-key-1")
	local.AddKey("https://local.example.com", "local-key-1", pubKey)

	r := NewResolver(ResolverConfig{Local: local})
	defer r.Close()

	key, err := r.ResolveKey(context.Background(), "https://local.example.com", "local-key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
	if local.called.Load() != 1 {
		t.Errorf("local resolver called %d times, want 1", local.called.Load())
	}
}

func TestResolver_FederatedFallback(t *testing.T) {
	srv, pubKeys := serveJWKS(t, "peer-key-1", "peer-key-2")

	local := newMockLocalResolver()
	r := NewResolver(ResolverConfig{
		Local: local,
		Peers: []PeerConfig{
			{
				FabricID:     "peer-1",
				JWKSEndpoint: srv.URL,
			},
		},
	})
	defer r.Close()

	// Wait for initial fetch.
	time.Sleep(200 * time.Millisecond)

	key, err := r.ResolveKey(context.Background(), srv.URL, "peer-key-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected key, got nil")
	}
	_ = pubKeys // keys generated but we verify by non-nil return
}

func TestResolver_FederatedFallback_OnDemandFetch(t *testing.T) {
	// Create server but don't configure it as a peer initially.
	srv, _ := serveJWKS(t, "demand-key-1")

	local := newMockLocalResolver()
	r := NewResolver(ResolverConfig{
		Local: local,
		Peers: []PeerConfig{
			{
				FabricID:        "on-demand",
				JWKSEndpoint:    srv.URL,
				RefreshInterval: 1 * time.Hour, // won't auto-fetch in time
			},
		},
	})
	defer r.Close()

	// Don't wait — the key should be fetched on-demand.
	key, err := r.ResolveKey(context.Background(), srv.URL, "demand-key-1")
	if err != nil {
		t.Fatalf("on-demand fetch should resolve: %v", err)
	}
	if key == nil {
		t.Fatal("expected key")
	}
}

func TestResolver_UnknownIssuer(t *testing.T) {
	local := newMockLocalResolver()
	r := NewResolver(ResolverConfig{Local: local})
	defer r.Close()

	_, err := r.ResolveKey(context.Background(), "https://unknown.example.com", "no-key")
	if err == nil {
		t.Fatal("expected error for unknown issuer")
	}
}

func TestResolver_PeerUnreachable(t *testing.T) {
	local := newMockLocalResolver()
	r := NewResolver(ResolverConfig{
		Local: local,
		Peers: []PeerConfig{
			{
				FabricID:        "down-peer",
				JWKSEndpoint:    "http://127.0.0.1:1", // unreachable
				RefreshInterval: 1 * time.Hour,
			},
		},
	})
	defer r.Close()

	// Wait for initial fetch attempt to complete.
	time.Sleep(200 * time.Millisecond)

	state := r.State()
	ps, ok := state.Peers["down-peer"]
	if !ok {
		t.Fatal("peer not found in state")
	}
	if ps.Status == PeerHealthy {
		t.Errorf("unreachable peer should not be healthy, got %q", ps.Status)
	}
	if ps.LastError == "" {
		t.Error("expected last error to be set")
	}
}

func TestResolver_State(t *testing.T) {
	srv, _ := serveJWKS(t, "state-key-1")

	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:     "state-peer",
				JWKSEndpoint: srv.URL,
			},
		},
	})
	defer r.Close()

	// Wait for initial fetch.
	time.Sleep(200 * time.Millisecond)

	state := r.State()
	if state.PeerCount() != 1 {
		t.Fatalf("PeerCount() = %d, want 1", state.PeerCount())
	}

	ps := state.Peers["state-peer"]
	if ps == nil {
		t.Fatal("state-peer not found")
	}
	if ps.Status != PeerHealthy {
		t.Errorf("status = %q, want %q", ps.Status, PeerHealthy)
	}
	if ps.KeyCount != 1 {
		t.Errorf("key count = %d, want 1", ps.KeyCount)
	}
	if ps.FetchCount < 1 {
		t.Errorf("fetch count = %d, want >= 1", ps.FetchCount)
	}
}

func TestResolver_Prefetch(t *testing.T) {
	srv, _ := serveJWKS(t, "prefetch-key")

	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:        "prefetch-peer",
				JWKSEndpoint:    srv.URL,
				RefreshInterval: 1 * time.Hour,
			},
		},
	})
	defer r.Close()

	err := r.Prefetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Prefetch error: %v", err)
	}

	// Key should be available after prefetch.
	key, err := r.ResolveKey(context.Background(), srv.URL, "prefetch-key")
	if err != nil {
		t.Fatalf("ResolveKey after prefetch: %v", err)
	}
	if key == nil {
		t.Fatal("expected key after prefetch")
	}
}

func TestResolver_Close(t *testing.T) {
	srv, _ := serveJWKS(t, "close-key")

	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:        "close-peer",
				JWKSEndpoint:    srv.URL,
				RefreshInterval: 50 * time.Millisecond,
			},
		},
	})

	// Close should not hang.
	done := make(chan struct{})
	go func() {
		r.Close()
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return within 5s")
	}
}

func TestResolver_StaleKeys_StillServed(t *testing.T) {
	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requestCount.Add(1)
		if count == 1 {
			// First request: serve keys.
			_, pubKey := generateTestKey("stale-key")
			_ = pubKey
			set := jwk.NewSet()
			priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			key, _ := jwk.Import(priv.Public())
			_ = key.Set(jwk.KeyIDKey, "stale-key")
			_ = set.AddKey(key)
			data, _ := json.Marshal(set)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		} else {
			// Subsequent requests: fail.
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:           "stale-peer",
				JWKSEndpoint:       srv.URL,
				RefreshInterval:    100 * time.Millisecond,
				StalenessThreshold: 10 * time.Second,
			},
		},
	})
	defer r.Close()

	// Wait for initial fetch + one failed refresh.
	time.Sleep(300 * time.Millisecond)

	// Key should still be served from cache despite refresh failure.
	key, err := r.ResolveKey(context.Background(), srv.URL, "stale-key")
	if err != nil {
		t.Fatalf("stale key should still be served: %v", err)
	}
	if key == nil {
		t.Fatal("expected stale key")
	}
}

func TestResolver_Stats_WithLocal(t *testing.T) {
	local := newMockLocalResolver()
	r := NewResolver(ResolverConfig{Local: local})
	defer r.Close()

	stats := r.Stats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Errorf("expected zero stats from mock, got %+v", stats)
	}
}

func TestResolver_Stats_NilLocal(t *testing.T) {
	r := NewResolver(ResolverConfig{})
	defer r.Close()

	stats := r.Stats()
	if stats.Hits != 0 || stats.Misses != 0 || stats.CachedKeys != 0 {
		t.Errorf("expected zero stats for nil local, got %+v", stats)
	}
}

func TestResolver_ComputePeerStatus_NeverFetchedNoError(t *testing.T) {
	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:        "never-fetched",
				JWKSEndpoint:    "http://127.0.0.1:1",
				RefreshInterval: 1 * time.Hour,
			},
		},
		HTTPClient: &http.Client{Timeout: 1 * time.Millisecond},
	})
	defer r.Close()

	r.mu.RLock()
	p := r.peers["never-fetched"]
	r.mu.RUnlock()

	p.mu.Lock()
	p.lastSeen = time.Time{}
	p.lastError = ""
	p.mu.Unlock()

	status := r.computePeerStatus(p)
	if status != PeerStale {
		t.Errorf("expected PeerStale for never-fetched peer with no error, got %q", status)
	}
}

func TestResolver_ComputePeerStatus_StaleWithError(t *testing.T) {
	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:           "stale-err",
				JWKSEndpoint:       "http://127.0.0.1:1",
				RefreshInterval:    1 * time.Hour,
				StalenessThreshold: 1 * time.Minute,
			},
		},
		HTTPClient: &http.Client{Timeout: 1 * time.Millisecond},
	})
	defer r.Close()

	r.mu.RLock()
	p := r.peers["stale-err"]
	r.mu.RUnlock()

	p.mu.Lock()
	p.lastSeen = time.Now().Add(-10 * time.Minute)
	p.lastError = "connection refused"
	p.mu.Unlock()

	status := r.computePeerStatus(p)
	if status != PeerUnreachable {
		t.Errorf("expected PeerUnreachable for stale peer with error, got %q", status)
	}
}

func TestResolver_ComputePeerStatus_StaleNoError(t *testing.T) {
	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:           "stale-ok",
				JWKSEndpoint:       "http://127.0.0.1:1",
				RefreshInterval:    1 * time.Hour,
				StalenessThreshold: 1 * time.Minute,
			},
		},
		HTTPClient: &http.Client{Timeout: 1 * time.Millisecond},
	})
	defer r.Close()

	r.mu.RLock()
	p := r.peers["stale-ok"]
	r.mu.RUnlock()

	p.mu.Lock()
	p.lastSeen = time.Now().Add(-10 * time.Minute)
	p.lastError = ""
	p.mu.Unlock()

	status := r.computePeerStatus(p)
	if status != PeerStale {
		t.Errorf("expected PeerStale for stale peer without error, got %q", status)
	}
}

func TestResolver_FetchPeerKeys_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{
				FabricID:        "forbidden-peer",
				JWKSEndpoint:    srv.URL,
				RefreshInterval: 1 * time.Hour,
			},
		},
	})
	defer r.Close()

	r.mu.RLock()
	p := r.peers["forbidden-peer"]
	r.mu.RUnlock()

	err := r.fetchPeerKeys(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for HTTP 403")
	}
	if p.errorCount.Load() < 1 {
		t.Error("expected errorCount to be incremented")
	}
}

func TestResolver_ResolveKey_NilLocal(t *testing.T) {
	srv, _ := serveJWKS(t, "nolocal-key")

	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{FabricID: "nolocal-peer", JWKSEndpoint: srv.URL},
		},
	})
	defer r.Close()

	time.Sleep(200 * time.Millisecond)

	key, err := r.ResolveKey(context.Background(), srv.URL, "nolocal-key")
	if err != nil {
		t.Fatalf("ResolveKey with nil local: %v", err)
	}
	if key == nil {
		t.Fatal("expected key from peer")
	}
}

func TestResolver_MultiPeer(t *testing.T) {
	srv1, _ := serveJWKS(t, "peer1-key")
	srv2, _ := serveJWKS(t, "peer2-key")

	r := NewResolver(ResolverConfig{
		Peers: []PeerConfig{
			{FabricID: "peer-a", JWKSEndpoint: srv1.URL},
			{FabricID: "peer-b", JWKSEndpoint: srv2.URL},
		},
	})
	defer r.Close()

	time.Sleep(200 * time.Millisecond)

	// Resolve from peer 1.
	key1, err := r.ResolveKey(context.Background(), srv1.URL, "peer1-key")
	if err != nil {
		t.Fatalf("peer1 resolve: %v", err)
	}
	if key1 == nil {
		t.Fatal("expected peer1 key")
	}

	// Resolve from peer 2.
	key2, err := r.ResolveKey(context.Background(), srv2.URL, "peer2-key")
	if err != nil {
		t.Fatalf("peer2 resolve: %v", err)
	}
	if key2 == nil {
		t.Fatal("expected peer2 key")
	}

	state := r.State()
	if state.HealthyCount() != 2 {
		t.Errorf("healthy count = %d, want 2", state.HealthyCount())
	}
}
