package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/metrics"
	"golang.org/x/time/rate"
)

// ipLimiter pairs a rate limiter with a last-seen timestamp for cleanup.
// lastSeen is stored as UnixNano in an atomic.Int64 to avoid data races.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // UnixNano
}

// rateLimitMiddleware wraps an http.Handler with global and per-IP token-bucket
// rate limiting. When devMode is true, the middleware is a no-op passthrough.
func rateLimitMiddleware(next http.Handler, cfg core.RateLimitConfig, devMode bool, m *metrics.Metrics, ctx ...context.Context) http.Handler {
	if devMode {
		return next
	}

	// Use the provided context for goroutine lifecycle, default to Background.
	var shutdownCtx context.Context
	if len(ctx) > 0 && ctx[0] != nil {
		shutdownCtx = ctx[0]
	} else {
		shutdownCtx = context.Background()
	}

	global := rate.NewLimiter(rate.Limit(cfg.GlobalRate), cfg.GlobalBurst)
	trustedNets := parseTrustedProxies(cfg.TrustedProxies)

	var ips sync.Map // map[string]*ipLimiter

	// Background cleanup: remove stale per-IP entries every 5 minutes.
	// Stops when shutdownCtx is cancelled.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-10 * time.Minute).UnixNano()
				ips.Range(func(key, value any) bool {
					if il, ok := value.(*ipLimiter); ok && il.lastSeen.Load() < cutoff {
						ips.Delete(key)
					}
					return true
				})
			}
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIPWith(r, trustedNets)

		// Check global limit first.
		if !global.Allow() {
			m.RateLimitRejectedTotal.WithLabelValues("global").Inc()
			writeRateLimited(w, global.Reserve().Delay())
			slog.Warn("rate limit exceeded", "scope", "global", "client_ip", ip)
			return
		}

		// Per-IP limit.
		newIL := &ipLimiter{
			limiter: rate.NewLimiter(rate.Limit(cfg.PerIPRate), cfg.PerIPBurst),
		}
		newIL.lastSeen.Store(time.Now().UnixNano())
		val, _ := ips.LoadOrStore(ip, newIL)
		il := val.(*ipLimiter)
		il.lastSeen.Store(time.Now().UnixNano())

		if !il.limiter.Allow() {
			m.RateLimitRejectedTotal.WithLabelValues("per_ip").Inc()
			writeRateLimited(w, il.limiter.Reserve().Delay())
			slog.Warn("rate limit exceeded", "scope", "per_ip", "client_ip", ip)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// parseTrustedProxies parses a slice of CIDR strings into net.IPNet values.
// Invalid CIDRs are silently skipped (logged at startup by the caller).
func parseTrustedProxies(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}

// remoteHost extracts the host portion from r.RemoteAddr.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientIPWith extracts the real client IP, honoring X-Forwarded-For only when
// the direct peer (RemoteAddr) is in the trusted proxy set.
func clientIPWith(r *http.Request, trusted []*net.IPNet) string {
	peer := remoteHost(r)
	if len(trusted) > 0 {
		peerIP := net.ParseIP(peer)
		fromTrustedProxy := false
		if peerIP != nil {
			for _, ipnet := range trusted {
				if ipnet.Contains(peerIP) {
					fromTrustedProxy = true
					break
				}
			}
		}
		if fromTrustedProxy {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
					return ip
				}
			}
		}
		return peer
	}
	// No trusted proxies configured — fall back to legacy behavior (trust XFF unconditionally).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	return peer
}

// clientIP is kept for tests; production code uses clientIPWith.
func clientIP(r *http.Request) string { return clientIPWith(r, nil) }

// writeRateLimited writes a 429 Too Many Requests response with Retry-After
// header and a JSON error body.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
	w.WriteHeader(http.StatusTooManyRequests)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":             "rate_limit_exceeded",
		"error_description": "Too many requests. Please retry after the indicated delay.",
	}); err != nil {
		slog.Error("writing rate limit response", "error", err)
	}
}
