package jwks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// genRSAKey generates a test RSA key pair.
func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// genECKey generates a test ECDSA key pair.
func genECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newTestServer creates an httptest.Server that serves a JWKS endpoint
// at /.well-known/jwks.json with the given keys.
func newTestServer(t *testing.T, keys map[string]crypto.PublicKey) *httptest.Server {
	t.Helper()
	body, err := jwksResponseForTesting(keys)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

// newTestServerWithCounter serves JWKS and counts requests.
func newTestServerWithCounter(t *testing.T, keys map[string]crypto.PublicKey, counter *atomic.Int32) *httptest.Server {
	t.Helper()
	body, err := jwksResponseForTesting(keys)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func TestResolveKey_CacheHit(t *testing.T) {
	key := genRSAKey(t)
	keys := map[string]crypto.PublicKey{"kid-1": &key.PublicKey}
	srv := newTestServer(t, keys)
	defer srv.Close()

	c := New(Config{TTL: 1 * time.Minute, Grace: 5 * time.Minute})
	defer c.Close()

	ctx := context.Background()
	issuer := srv.URL

	// First call: cache miss → fetch.
	pub, err := c.ResolveKey(ctx, issuer, "kid-1")
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil key")
	}

	// Second call: cache hit → no fetch.
	pub2, err := c.ResolveKey(ctx, issuer, "kid-1")
	if err != nil {
		t.Fatalf("ResolveKey (cached): %v", err)
	}
	if pub2 == nil {
		t.Fatal("expected non-nil key from cache")
	}

	stats := c.Stats()
	if stats.Hits < 1 {
		t.Errorf("expected at least 1 hit, got %d", stats.Hits)
	}
	if stats.Fetches < 1 {
		t.Errorf("expected at least 1 fetch, got %d", stats.Fetches)
	}
}

func TestResolveKey_KidMissRefetch(t *testing.T) {
	key1 := genRSAKey(t)
	key2 := genRSAKey(t)

	// Start server with only kid-1.
	keys1 := map[string]crypto.PublicKey{"kid-1": &key1.PublicKey}
	body1, _ := jwksResponseForTesting(keys1)

	// Build body with both keys (simulates key rotation).
	keys2 := map[string]crypto.PublicKey{
		"kid-1": &key1.PublicKey,
		"kid-2": &key2.PublicKey,
	}
	body2, _ := jwksResponseForTesting(keys2)

	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write(body1)
		} else {
			_, _ = w.Write(body2)
		}
	}))
	defer srv.Close()

	c := New(Config{TTL: 1 * time.Hour}) // Long TTL so it doesn't expire.
	defer c.Close()

	ctx := context.Background()

	// Resolve kid-1 → fetches and caches.
	_, err := c.ResolveKey(ctx, srv.URL, "kid-1")
	if err != nil {
		t.Fatalf("ResolveKey kid-1: %v", err)
	}

	// Resolve kid-2 → kid miss → refetch → finds kid-2.
	_, err = c.ResolveKey(ctx, srv.URL, "kid-2")
	if err != nil {
		t.Fatalf("ResolveKey kid-2: %v", err)
	}

	if got := callCount.Load(); got != 2 {
		t.Errorf("expected 2 fetches (initial + kid-miss), got %d", got)
	}
}

func TestResolveKey_TTLExpiry(t *testing.T) {
	key := genRSAKey(t)
	keys := map[string]crypto.PublicKey{"kid-1": &key.PublicKey}
	var counter atomic.Int32
	srv := newTestServerWithCounter(t, keys, &counter)
	defer srv.Close()

	c := New(Config{TTL: 50 * time.Millisecond, Grace: 5 * time.Second})
	defer c.Close()

	ctx := context.Background()

	// First resolve.
	_, err := c.ResolveKey(ctx, srv.URL, "kid-1")
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}

	// Wait for TTL to expire.
	time.Sleep(100 * time.Millisecond)

	// Resolve again — TTL expired, should refetch.
	_, err = c.ResolveKey(ctx, srv.URL, "kid-1")
	if err != nil {
		t.Fatalf("ResolveKey after TTL: %v", err)
	}

	if got := counter.Load(); got < 2 {
		t.Errorf("expected >= 2 fetches after TTL expiry, got %d", got)
	}
}

func TestResolveKey_IssuerUnreachableWithGrace(t *testing.T) {
	key := genRSAKey(t)
	keys := map[string]crypto.PublicKey{"kid-1": &key.PublicKey}

	var healthy atomic.Bool
	healthy.Store(true)
	body, _ := jwksResponseForTesting(keys)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := New(Config{TTL: 50 * time.Millisecond, Grace: 5 * time.Second})
	defer c.Close()

	ctx := context.Background()

	// Populate cache.
	_, err := c.ResolveKey(ctx, srv.URL, "kid-1")
	if err != nil {
		t.Fatalf("initial ResolveKey: %v", err)
	}

	// Make issuer unreachable and expire TTL.
	healthy.Store(false)
	time.Sleep(100 * time.Millisecond)

	// Should serve stale key within grace period.
	pub, err := c.ResolveKey(ctx, srv.URL, "kid-1")
	if err != nil {
		t.Fatalf("ResolveKey during grace: %v", err)
	}
	if pub == nil {
		t.Fatal("expected stale key within grace period")
	}
}

func TestResolveKey_IssuerUnreachableNoGrace(t *testing.T) {
	key := genRSAKey(t)
	keys := map[string]crypto.PublicKey{"kid-1": &key.PublicKey}

	body, _ := jwksResponseForTesting(keys)
	var healthy atomic.Bool
	healthy.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Grace = 50ms, TTL = 50ms.
	c := New(Config{TTL: 50 * time.Millisecond, Grace: 50 * time.Millisecond})
	defer c.Close()

	ctx := context.Background()

	// Populate cache.
	_, err := c.ResolveKey(ctx, srv.URL, "kid-1")
	if err != nil {
		t.Fatalf("initial ResolveKey: %v", err)
	}

	// Make unreachable and wait past grace.
	healthy.Store(false)
	time.Sleep(150 * time.Millisecond)

	// Should fail — past grace period.
	_, err = c.ResolveKey(ctx, srv.URL, "kid-1")
	if err == nil {
		t.Fatal("expected error past grace period, got nil")
	}
}

func TestResolveKey_KidNotFound(t *testing.T) {
	key := genRSAKey(t)
	keys := map[string]crypto.PublicKey{"kid-1": &key.PublicKey}
	srv := newTestServer(t, keys)
	defer srv.Close()

	c := New(Config{TTL: 1 * time.Minute})
	defer c.Close()

	_, err := c.ResolveKey(context.Background(), srv.URL, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent kid")
	}
}

func TestResolveKey_ECDSAKey(t *testing.T) {
	key := genECKey(t)
	keys := map[string]crypto.PublicKey{"ec-kid": &key.PublicKey}
	srv := newTestServer(t, keys)
	defer srv.Close()

	c := New(Config{TTL: 1 * time.Minute})
	defer c.Close()

	pub, err := c.ResolveKey(context.Background(), srv.URL, "ec-kid")
	if err != nil {
		t.Fatalf("ResolveKey ECDSA: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestPrefetch(t *testing.T) {
	key := genRSAKey(t)
	keys := map[string]crypto.PublicKey{"kid-1": &key.PublicKey}
	srv := newTestServer(t, keys)
	defer srv.Close()

	c := New(Config{TTL: 1 * time.Minute})
	defer c.Close()

	err := c.Prefetch(context.Background(), []string{srv.URL})
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}

	stats := c.Stats()
	if stats.Issuers != 1 {
		t.Errorf("expected 1 issuer after prefetch, got %d", stats.Issuers)
	}
	if stats.CachedKeys < 1 {
		t.Errorf("expected at least 1 cached key after prefetch, got %d", stats.CachedKeys)
	}

	// ResolveKey should be a cache hit now.
	pub, err := c.ResolveKey(context.Background(), srv.URL, "kid-1")
	if err != nil {
		t.Fatalf("ResolveKey after prefetch: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil key after prefetch")
	}
}

func TestPrefetch_MaxIssuersLimit(t *testing.T) {
	key := genRSAKey(t)
	keys := map[string]crypto.PublicKey{"kid-1": &key.PublicKey}
	srv := newTestServer(t, keys)
	defer srv.Close()

	c := New(Config{TTL: 1 * time.Minute, MaxIssuers: 1})
	defer c.Close()

	// Prefetch two issuers with max=1.
	err := c.Prefetch(context.Background(), []string{srv.URL, srv.URL + "/other"})
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}

	stats := c.Stats()
	if stats.Issuers > 1 {
		t.Errorf("expected max 1 issuer, got %d", stats.Issuers)
	}
}

func TestStats(t *testing.T) {
	c := New(Config{TTL: 1 * time.Minute})
	defer c.Close()

	stats := c.Stats()
	if stats.Hits != 0 || stats.Misses != 0 || stats.Fetches != 0 {
		t.Errorf("expected zero stats on fresh cache: %+v", stats)
	}
}

func TestMaxKeysPerIssuer(t *testing.T) {
	// Generate 5 keys but limit to 2.
	keys := make(map[string]crypto.PublicKey)
	for i := 0; i < 5; i++ {
		k := genRSAKey(t)
		keys[fmt.Sprintf("kid-%d", i)] = &k.PublicKey
	}
	srv := newTestServer(t, keys)
	defer srv.Close()

	c := New(Config{TTL: 1 * time.Minute, MaxKeysPerIssuer: 2})
	defer c.Close()

	// Prefetch to populate.
	_ = c.Prefetch(context.Background(), []string{srv.URL})

	stats := c.Stats()
	if stats.CachedKeys > 2 {
		t.Errorf("expected max 2 keys, got %d", stats.CachedKeys)
	}
}

