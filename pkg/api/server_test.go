package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func newTestServer() *Server {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	return New(cfg, "test-version", nil)
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	w := httptest.NewRecorder()

	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if !resp.Initialized {
		t.Error("initialized = false, want true")
	}
	if resp.Locked {
		t.Error("locked = true, want false")
	}
	if resp.Version != "test-version" {
		t.Errorf("version = %q, want %q", resp.Version, "test-version")
	}
	if resp.UnitID == "" {
		t.Error("unit_id should not be empty")
	}
}

func TestRequestIDHeader(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	w := httptest.NewRecorder()

	s.httpServer.Handler.ServeHTTP(w, req)

	reqID := w.Header().Get("X-Request-ID")
	if reqID == "" {
		t.Error("X-Request-ID header should be present")
	}
	// UUID v4 format: 8-4-4-4-12 = 36 chars
	if len(reqID) != 36 {
		t.Errorf("X-Request-ID length = %d, want 36 (UUID v4 format)", len(reqID))
	}
}

func TestStubEndpoints_501(t *testing.T) {
	s := newTestServer()

	endpoints := []struct {
		method   string
		path     string
		wantBody string
	}{
		{http.MethodPost, "/v1/signals/events", "not_implemented"},
		{http.MethodPost, "/v1/identity/agent", "not_implemented"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()

			s.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusNotImplemented {
				t.Errorf("status = %d, want %d", w.Code, http.StatusNotImplemented)
			}

			var resp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			if resp["error"] != ep.wantBody {
				t.Errorf("error = %q, want %q", resp["error"], ep.wantBody)
			}
		})
	}
}

func TestUnknownRoute_404(t *testing.T) {
	s := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/v1/nonexistent", nil)
	w := httptest.NewRecorder()

	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestFederationEndpoints_WithRevocationIndex(t *testing.T) {
	export, err := json.Marshal(core.RevocationSnapshot{
		Entries: nil,
		Count:   0,
		Hash:    "sha256:test",
	})
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}

	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test-version", nil, WithRevocationIndex(&mockRevocationIndex{
		hash:       "sha256:test",
		exportData: export,
	}))

	t.Run("revocation-hash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/federation/revocation-hash", nil)
		w := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
		}
		var resp revocationHashResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Hash != "sha256:test" {
			t.Errorf("hash = %q, want sha256:test", resp.Hash)
		}
	})

	t.Run("revocation-export", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/federation/revocation-export", nil)
		w := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d body=%s", w.Code, http.StatusOK, w.Body.String())
		}
		if w.Body.String() != string(export) {
			t.Errorf("export body mismatch: got %s", w.Body.String())
		}
	})
}
