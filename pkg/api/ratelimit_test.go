package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/metrics"
)

func testMetrics() *metrics.Metrics {
	return metrics.New("test", "test-unit", "test-domain")
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimiter_UnderLimit(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 100, GlobalBurst: 100,
		PerIPRate: 10, PerIPBurst: 10,
	}
	h := rateLimitMiddleware(okHandler(), cfg, false, testMetrics())

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i, rr.Code)
		}
	}
}

func TestRateLimiter_GlobalOverLimit(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 1, GlobalBurst: 3,
		PerIPRate: 100, PerIPBurst: 100,
	}
	h := rateLimitMiddleware(okHandler(), cfg, false, testMetrics())

	// Exhaust the global burst from different IPs (so per-IP doesn't trigger).
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
		req.RemoteAddr = "192.168.1." + string(rune('1'+i)) + ":12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// Next request should be rate limited globally.
	req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "192.168.1.99:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", rr.Code)
	}
}

func TestRateLimiter_PerIPOverLimit(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 100, GlobalBurst: 100,
		PerIPRate: 1, PerIPBurst: 3,
	}
	h := rateLimitMiddleware(okHandler(), cfg, false, testMetrics())

	// Exhaust per-IP burst.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// Next from same IP should be rate limited.
	req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", rr.Code)
	}
}

func TestRateLimiter_PerIPIsolation(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 100, GlobalBurst: 100,
		PerIPRate: 1, PerIPBurst: 2,
	}
	h := rateLimitMiddleware(okHandler(), cfg, false, testMetrics())

	// Exhaust IP-A's burst.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("IP-A request %d: got status %d, want 200", i, rr.Code)
		}
	}

	// IP-A is now limited.
	req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("IP-A overflow: got status %d, want 429", rr.Code)
	}

	// IP-B should still work fine.
	req = httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("IP-B: got status %d, want 200", rr.Code)
	}
}

func TestRateLimiter_RetryAfterHeader(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 100, GlobalBurst: 100,
		PerIPRate: 1, PerIPBurst: 1,
	}
	h := rateLimitMiddleware(okHandler(), cfg, false, testMetrics())

	// Use up the single burst token.
	req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// Second request should be limited.
	req = httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", rr.Code)
	}

	ra := rr.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("Retry-After header missing")
	}
}

func TestRateLimiter_DevModeBypass(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 1, GlobalBurst: 1,
		PerIPRate: 1, PerIPBurst: 1,
	}
	h := rateLimitMiddleware(okHandler(), cfg, true, testMetrics())

	// In dev mode, even after exceeding burst, requests should pass.
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("dev mode request %d: got status %d, want 200", i, rr.Code)
		}
	}
}

func TestRateLimiter_ResponseBody(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 100, GlobalBurst: 100,
		PerIPRate: 1, PerIPBurst: 1,
	}
	h := rateLimitMiddleware(okHandler(), cfg, false, testMetrics())

	// Consume burst.
	req := httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// Trigger 429.
	req = httptest.NewRequest("POST", "/v1/exchange/token", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if body["error"] != "rate_limit_exceeded" {
		t.Fatalf("error = %q, want rate_limit_exceeded", body["error"])
	}
	if body["error_description"] == "" {
		t.Fatal("error_description is empty")
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")

	got := clientIP(req)
	if got != "203.0.113.50" {
		t.Fatalf("clientIP = %q, want 203.0.113.50", got)
	}
}

func TestClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:54321"

	got := clientIP(req)
	if got != "192.168.1.1" {
		t.Fatalf("clientIP = %q, want 192.168.1.1", got)
	}
}
