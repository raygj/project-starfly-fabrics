package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ── Mock revocation index ────────────────────────────────────────────

type mockRevocationIndex struct {
	hash      string
	exportData []byte
	exportErr  error
}

func (m *mockRevocationIndex) Hash() string {
	return m.hash
}

func (m *mockRevocationIndex) Export() ([]byte, error) {
	return m.exportData, m.exportErr
}

// ── Federation revocation-hash endpoint tests ────────────────────────

func TestHandleFederationRevocationHash(t *testing.T) {
	validExport, _ := json.Marshal(core.RevocationSnapshot{
		Entries: nil,
		Count:   3,
		Hash:    "sha256:abc123",
	})

	tests := []struct {
		name       string
		index      FederationRevocationIndex
		wantStatus int
		wantError  string
		wantHash   string
	}{
		{
			name:       "no revocation index returns 503",
			index:      nil,
			wantStatus: http.StatusServiceUnavailable,
			wantError:  "service_unavailable",
		},
		{
			name: "valid index returns hash",
			index: &mockRevocationIndex{
				hash:       "sha256:deadbeef",
				exportData: validExport,
			},
			wantStatus: http.StatusOK,
			wantHash:   "sha256:deadbeef",
		},
		{
			name: "export error still returns hash with zero count",
			index: &mockRevocationIndex{
				hash:      "sha256:abc",
				exportErr: fmt.Errorf("export failed"),
			},
			wantStatus: http.StatusOK,
			wantHash:   "sha256:abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{revocationIndex: tt.index}

			req := httptest.NewRequest(http.MethodGet, "/v1/federation/revocation-hash", nil)
			rec := httptest.NewRecorder()

			s.handleFederationRevocationHash(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantError != "" {
				var resp errorResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding error response: %v", err)
				}
				if resp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", resp.Error, tt.wantError)
				}
				return
			}

			var resp revocationHashResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decoding response: %v", err)
			}

			if resp.Hash != tt.wantHash {
				t.Errorf("hash = %q, want %q", resp.Hash, tt.wantHash)
			}
			if resp.Timestamp == "" {
				t.Error("timestamp should not be empty")
			}
		})
	}
}

// ── Federation revocation-export endpoint tests ──────────────────────

func TestHandleFederationRevocationExport(t *testing.T) {
	snapshot := core.RevocationSnapshot{
		Entries: []*core.RevocationEntry{
			{SubjectID: "spiffe://example.com/agent-1", Reason: "session-revoked"},
		},
		Count: 1,
		Hash:  "sha256:abc123",
	}
	validExport, _ := json.Marshal(snapshot)

	tests := []struct {
		name       string
		index      FederationRevocationIndex
		wantStatus int
		wantError  string
	}{
		{
			name:       "no revocation index returns 503",
			index:      nil,
			wantStatus: http.StatusServiceUnavailable,
			wantError:  "service_unavailable",
		},
		{
			name: "valid index returns export JSON",
			index: &mockRevocationIndex{
				exportData: validExport,
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "export error returns 500",
			index: &mockRevocationIndex{
				exportErr: fmt.Errorf("marshal failed"),
			},
			wantStatus: http.StatusInternalServerError,
			wantError:  "server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{revocationIndex: tt.index}

			req := httptest.NewRequest(http.MethodGet, "/v1/federation/revocation-export", nil)
			rec := httptest.NewRecorder()

			s.handleFederationRevocationExport(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantError != "" {
				var resp errorResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding error response: %v", err)
				}
				if resp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", resp.Error, tt.wantError)
				}
				return
			}

			// Verify the response is valid JSON matching the snapshot format.
			var exported core.RevocationSnapshot
			if err := json.NewDecoder(rec.Body).Decode(&exported); err != nil {
				t.Fatalf("decoding export response: %v", err)
			}
			if exported.Count != 1 {
				t.Errorf("count = %d, want 1", exported.Count)
			}
			if exported.Hash != "sha256:abc123" {
				t.Errorf("hash = %q, want %q", exported.Hash, "sha256:abc123")
			}
			if len(exported.Entries) != 1 {
				t.Fatalf("entries = %d, want 1", len(exported.Entries))
			}
			if exported.Entries[0].SubjectID != "spiffe://example.com/agent-1" {
				t.Errorf("subject_id = %q, want %q", exported.Entries[0].SubjectID, "spiffe://example.com/agent-1")
			}
		})
	}
}

// ── HARDEN-008: federation peer auth tests ───────────────────────────

func TestRequireFederationPeerAuth(t *testing.T) {
	validExport, _ := json.Marshal(core.RevocationSnapshot{Count: 1, Hash: "sha256:x"})
	idx := &mockRevocationIndex{hash: "sha256:x", exportData: validExport}

	tests := []struct {
		name       string
		secret     string
		authHeader string
		wantStatus int
		wantError  string
	}{
		{
			name:       "no secret configured — open access",
			secret:     "",
			authHeader: "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "valid secret accepted",
			secret:     "supersecret",
			authHeader: "Bearer supersecret",
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing Authorization header",
			secret:     "supersecret",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantError:  "unauthorized",
		},
		{
			name:       "wrong secret",
			secret:     "supersecret",
			authHeader: "Bearer wrongsecret",
			wantStatus: http.StatusUnauthorized,
			wantError:  "unauthorized",
		},
		{
			name:       "non-Bearer scheme",
			secret:     "supersecret",
			authHeader: "Basic dXNlcjpwYXNz",
			wantStatus: http.StatusUnauthorized,
			wantError:  "unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{revocationIndex: idx, federationPeerSecret: tt.secret}

			req := httptest.NewRequest(http.MethodGet, "/v1/federation/revocation-hash", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			s.handleFederationRevocationHash(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantError != "" {
				var resp errorResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding error response: %v", err)
				}
				if resp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", resp.Error, tt.wantError)
				}
			}
		})
	}
}

func TestRequireFederationPeerAuth_Export(t *testing.T) {
	validExport, _ := json.Marshal(core.RevocationSnapshot{Count: 1, Hash: "sha256:x"})
	idx := &mockRevocationIndex{hash: "sha256:x", exportData: validExport}

	s := &Server{revocationIndex: idx, federationPeerSecret: "s3cr3t"}

	// Correct secret — should get the export.
	req := httptest.NewRequest(http.MethodGet, "/v1/federation/revocation-export", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	rec := httptest.NewRecorder()
	s.handleFederationRevocationExport(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	// No secret — should get 401.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/federation/revocation-export", nil)
	rec2 := httptest.NewRecorder()
	s.handleFederationRevocationExport(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d, want 401", rec2.Code)
	}
}

// ── Integration: routes are registered on dev-mode server ────────────

func TestFederationEndpoints_DevMode(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		DevMode:    true,
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test-version", nil)

	// Without revocation index, both endpoints should return 503.
	endpoints := []string{
		"/v1/federation/revocation-hash",
		"/v1/federation/revocation-export",
	}

	for _, ep := range endpoints {
		t.Run("no_index "+ep, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, ep, nil)
			rec := httptest.NewRecorder()

			s.httpServer.Handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
			}
		})
	}
}
