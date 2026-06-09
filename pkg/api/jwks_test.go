package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// mockJWKS implements JWKSProvider with a pre-built key set.
type mockJWKS struct {
	set jwk.Set
	err error
}

func (m *mockJWKS) PublicKeySet() (jwk.Set, error) {
	return m.set, m.err
}

func buildTestKeySet(t *testing.T) jwk.Set {
	t.Helper()
	// Use the exchange engine to get a real key set.
	// For unit tests, build a minimal RSA key.
	raw := `{"keys":[{"kty":"RSA","kid":"test-kid","alg":"RS256","use":"sig","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}`
	set := jwk.NewSet()
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		t.Fatalf("building test keyset: %v", err)
	}
	return set
}

func TestJWKSEndpoint(t *testing.T) {
	set := buildTestKeySet(t)
	cfg := &core.Config{ListenAddr: ":0", RateLimit: core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10}}
	s := New(cfg, "test", nil, WithJWKS(&mockJWKS{set: set}))

	req := httptest.NewRequest(http.MethodGet, "/v1/identity/jwks", nil)
	w := httptest.NewRecorder()

	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Parse the response as a JWK Set.
	var respSet struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(w.Body).Decode(&respSet); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if len(respSet.Keys) == 0 {
		t.Fatal("expected at least one key in JWKS response")
	}

	key := respSet.Keys[0]
	if key["kty"] != "RSA" {
		t.Errorf("kty = %v, want RSA", key["kty"])
	}
	if key["kid"] != "test-kid" {
		t.Errorf("kid = %v, want test-kid", key["kid"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("alg = %v, want RS256", key["alg"])
	}
	if key["use"] != "sig" {
		t.Errorf("use = %v, want sig", key["use"])
	}
}

func TestJWKSEndpoint_DevModeCacheControl(t *testing.T) {
	set := buildTestKeySet(t)
	cfg := &core.Config{ListenAddr: ":0", DevMode: true, RateLimit: core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10}}
	s := New(cfg, "test", nil, WithJWKS(&mockJWKS{set: set}))

	req := httptest.NewRequest(http.MethodGet, "/v1/identity/jwks", nil)
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q (dev mode)", cc, "no-store")
	}
}

func TestJWKSEndpoint_ProdCacheControl(t *testing.T) {
	set := buildTestKeySet(t)
	cfg := &core.Config{ListenAddr: ":0", DevMode: false, RateLimit: core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10}}
	s := New(cfg, "test", nil, WithJWKS(&mockJWKS{set: set}))

	req := httptest.NewRequest(http.MethodGet, "/v1/identity/jwks", nil)
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q (prod mode)", cc, "public, max-age=3600")
	}
}

func TestJWKSEndpoint_NoProvider(t *testing.T) {
	cfg := &core.Config{ListenAddr: ":0", RateLimit: core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10}}
	s := New(cfg, "test", nil) // no JWKS provider

	req := httptest.NewRequest(http.MethodGet, "/v1/identity/jwks", nil)
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}
