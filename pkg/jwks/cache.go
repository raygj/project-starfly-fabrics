package jwks

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/starfly-fabrics/starfly/pkg/jwks"

// Default configuration values per ADR-0003.
const (
	DefaultTTL             = 5 * time.Minute
	DefaultGrace           = 30 * time.Minute
	DefaultMaxIssuers      = 500
	DefaultMaxKeysPerIssuer = 20
)

// Config holds JWKS cache settings.
type Config struct {
	TTL              time.Duration // Cache entry TTL (default 5m).
	Grace            time.Duration // Serve stale keys for this long when issuer unreachable (default 30m).
	MaxIssuers       int           // Maximum cached issuers (default 500).
	MaxKeysPerIssuer int           // Maximum keys per issuer (default 20).
	Prefetch         bool          // Prefetch trust domains on boot (default true).
	HTTPClient       *http.Client  // HTTP client for JWKS fetches. Nil uses http.DefaultClient.
}

func (c Config) withDefaults() Config {
	if c.TTL == 0 {
		c.TTL = DefaultTTL
	}
	if c.Grace == 0 {
		c.Grace = DefaultGrace
	}
	if c.MaxIssuers == 0 {
		c.MaxIssuers = DefaultMaxIssuers
	}
	if c.MaxKeysPerIssuer == 0 {
		c.MaxKeysPerIssuer = DefaultMaxKeysPerIssuer
	}
	if c.HTTPClient == nil {
		c.HTTPClient = core.NewDefaultHTTPClient()
	}
	return c
}

// issuerEntry holds cached keys for a single issuer.
type issuerEntry struct {
	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey // keyed by kid
	fetchedAt time.Time
	jwksURL   string
}

func (e *issuerEntry) isExpired(ttl time.Duration) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Since(e.fetchedAt) > ttl
}

func (e *issuerEntry) isWithinGrace(grace time.Duration) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return time.Since(e.fetchedAt) <= grace
}

func (e *issuerEntry) getKey(kid string) (crypto.PublicKey, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	k, ok := e.keys[kid]
	return k, ok
}

func (e *issuerEntry) keyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.keys)
}

// Cache implements core.JWKSResolver with in-memory caching, TTL-based
// refresh, kid-miss refetch, and stale-while-revalidate.
type Cache struct {
	cfg Config

	mu      sync.RWMutex
	issuers map[string]*issuerEntry // keyed by issuer URL

	// Metrics (atomic counters).
	hits    atomic.Uint64
	misses  atomic.Uint64
	fetches atomic.Uint64
	errors  atomic.Uint64

	// Prometheus collectors.
	promHits      prometheus.Counter
	promMisses    prometheus.Counter
	promFetchDur  prometheus.Histogram
	promCacheSize prometheus.GaugeFunc

	// Background refresh.
	stopOnce sync.Once
	stopCh   chan struct{}
}

// Compile-time check: Cache implements core.JWKSResolver.
var _ core.JWKSResolver = (*Cache)(nil)

// New creates a Cache with the given config and starts a background TTL
// refresh goroutine. Call Close to stop background work.
func New(cfg Config) *Cache {
	cfg = cfg.withDefaults()

	c := &Cache{
		cfg:     cfg,
		issuers: make(map[string]*issuerEntry),
		stopCh:  make(chan struct{}),
	}

	c.promHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "starfly_jwks_cache_hits_total",
		Help: "Total JWKS cache hits.",
	})
	c.promMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "starfly_jwks_cache_misses_total",
		Help: "Total JWKS cache misses.",
	})
	c.promFetchDur = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "starfly_jwks_fetch_duration_seconds",
		Help:    "Duration of JWKS HTTP fetches.",
		Buckets: prometheus.DefBuckets,
	})
	c.promCacheSize = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "starfly_jwks_cache_size",
		Help: "Number of cached JWKS issuers.",
	}, func() float64 {
		c.mu.RLock()
		defer c.mu.RUnlock()
		return float64(len(c.issuers))
	})

	// Best-effort registration — no-op if already registered.
	_ = prometheus.DefaultRegisterer.Register(c.promHits)
	_ = prometheus.DefaultRegisterer.Register(c.promMisses)
	_ = prometheus.DefaultRegisterer.Register(c.promFetchDur)
	_ = prometheus.DefaultRegisterer.Register(c.promCacheSize)

	go c.backgroundRefresh()

	return c
}

// Close stops the background refresh goroutine.
func (c *Cache) Close() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// ResolveKey returns the public key for the given issuer and kid.
// On cache hit, returns immediately. On kid miss or TTL expiry, refetches
// the issuer's JWKS and retries. Serves stale keys within the grace period
// when the issuer is unreachable.
func (c *Cache) ResolveKey(ctx context.Context, issuer string, kid string) (crypto.PublicKey, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "jwks.ResolveKey")
	defer span.End()

	span.SetAttributes(
		attribute.String("issuer", issuer),
		attribute.String("kid", kid),
	)

	entry := c.getEntry(issuer)

	// Fast path: entry exists, not expired, kid found.
	if entry != nil && !entry.isExpired(c.cfg.TTL) {
		if key, ok := entry.getKey(kid); ok {
			c.hits.Add(1)
			c.promHits.Inc()
			return key, nil
		}
	}

	// Slow path: kid miss or TTL expired — refetch.
	c.misses.Add(1)
	c.promMisses.Inc()

	jwksURL := jwksURLForIssuer(issuer)
	newEntry, err := c.fetchAndCache(ctx, issuer, jwksURL)
	if err != nil {
		// Stale-while-revalidate: serve cached key within grace period.
		if entry != nil && entry.isWithinGrace(c.cfg.Grace) {
			if key, ok := entry.getKey(kid); ok {
				slog.Warn("jwks: serving stale key, issuer unreachable",
					"issuer", issuer, "kid", kid, "error", err)
				c.hits.Add(1)
				c.promHits.Inc()
				return key, nil
			}
		}
		telemetry.SpanError(span, err)
		return nil, fmt.Errorf("resolving key for issuer %s kid %s: %w", issuer, kid, err)
	}

	if key, ok := newEntry.getKey(kid); ok {
		c.hits.Add(1)
		c.promHits.Inc()
		return key, nil
	}

	err = fmt.Errorf("kid %q not found in JWKS for issuer %s", kid, issuer)
	telemetry.SpanError(span, err)
	return nil, err
}

// Prefetch warms the cache for the given issuers. Errors are logged but
// do not fail the call — partial prefetch is acceptable.
func (c *Cache) Prefetch(ctx context.Context, issuers []string) error {
	_, span := otel.Tracer(tracerName).Start(ctx, "jwks.Prefetch")
	defer span.End()

	span.SetAttributes(attribute.Int("issuer_count", len(issuers)))

	var wg sync.WaitGroup
	for _, issuer := range issuers {
		// Respect max issuers limit.
		c.mu.RLock()
		count := len(c.issuers)
		c.mu.RUnlock()
		if count >= c.cfg.MaxIssuers {
			slog.Warn("jwks: max issuers reached, skipping prefetch", "issuer", issuer)
			break
		}

		wg.Add(1)
		go func(iss string) {
			defer wg.Done()
			jwksURL := jwksURLForIssuer(iss)
			if _, err := c.fetchAndCache(ctx, iss, jwksURL); err != nil {
				slog.Warn("jwks: prefetch failed", "issuer", iss, "error", err)
			}
		}(issuer)
	}
	wg.Wait()
	return nil
}

// Stats returns cache performance metrics.
func (c *Cache) Stats() core.JWKSCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalKeys := 0
	for _, entry := range c.issuers {
		totalKeys += entry.keyCount()
	}

	return core.JWKSCacheStats{
		Hits:       c.hits.Load(),
		Misses:     c.misses.Load(),
		Fetches:    c.fetches.Load(),
		Errors:     c.errors.Load(),
		CachedKeys: totalKeys,
		Issuers:    len(c.issuers),
	}
}

// getEntry returns the cached entry for an issuer, or nil if not cached.
func (c *Cache) getEntry(issuer string) *issuerEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.issuers[issuer]
}

// fetchAndCache fetches the JWKS from the given URL and caches the keys.
func (c *Cache) fetchAndCache(ctx context.Context, issuer string, jwksURL string) (*issuerEntry, error) {
	start := time.Now()
	c.fetches.Add(1)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		c.errors.Add(1)
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		c.errors.Add(1)
		return nil, fmt.Errorf("fetching JWKS from %s: %w", jwksURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	c.promFetchDur.Observe(time.Since(start).Seconds())

	if resp.StatusCode != http.StatusOK {
		c.errors.Add(1)
		return nil, fmt.Errorf("JWKS fetch returned %d for %s", resp.StatusCode, jwksURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.errors.Add(1)
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}

	keyset, err := jwk.Parse(body)
	if err != nil {
		c.errors.Add(1)
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	for i := 0; i < keyset.Len() && i < c.cfg.MaxKeysPerIssuer; i++ {
		key, ok := keyset.Key(i)
		if !ok {
			continue
		}
		kid, ok := key.KeyID()
		if !ok || kid == "" {
			continue
		}
		var rawKey interface{}
		if err := jwk.Export(key, &rawKey); err != nil {
			slog.Warn("jwks: failed to export key", "kid", kid, "error", err)
			continue
		}
		pubKey, ok := rawKey.(crypto.PublicKey)
		if !ok {
			slog.Warn("jwks: exported key is not a crypto.PublicKey", "kid", kid)
			continue
		}
		keys[kid] = pubKey
	}

	entry := &issuerEntry{
		keys:      keys,
		fetchedAt: time.Now(),
		jwksURL:   jwksURL,
	}

	c.mu.Lock()
	if len(c.issuers) < c.cfg.MaxIssuers || c.issuers[issuer] != nil {
		c.issuers[issuer] = entry
	}
	c.mu.Unlock()

	return entry, nil
}

// backgroundRefresh periodically checks for expired entries and refreshes
// them in the background. This implements stale-while-revalidate.
func (c *Cache) backgroundRefresh() {
	ticker := time.NewTicker(c.cfg.TTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.refreshExpired()
		}
	}
}

// refreshExpired refetches JWKS for all expired entries that are still
// within the grace period.
func (c *Cache) refreshExpired() {
	c.mu.RLock()
	var toRefresh []struct {
		issuer  string
		jwksURL string
	}
	for issuer, entry := range c.issuers {
		if entry.isExpired(c.cfg.TTL) && entry.isWithinGrace(c.cfg.Grace) {
			toRefresh = append(toRefresh, struct {
				issuer  string
				jwksURL string
			}{issuer, entry.jwksURL})
		}
	}
	c.mu.RUnlock()

	for _, r := range toRefresh {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if _, err := c.fetchAndCache(ctx, r.issuer, r.jwksURL); err != nil {
			slog.Warn("jwks: background refresh failed", "issuer", r.issuer, "error", err)
		}
		cancel()
	}
}

// jwksURLForIssuer constructs the JWKS URL from an issuer URL.
func jwksURLForIssuer(issuer string) string {
	return issuer + "/.well-known/jwks.json"
}

// jwksResponseForTesting is used by tests to build mock JWKS responses.
// It is not exported — tests in this package use it directly.
func jwksResponseForTesting(keys map[string]crypto.PublicKey) ([]byte, error) {
	set := jwk.NewSet()
	for kid, pubKey := range keys {
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, err
		}
		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			return nil, err
		}
		if err := set.AddKey(key); err != nil {
			return nil, err
		}
	}
	return json.Marshal(set)
}
