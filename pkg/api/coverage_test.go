package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
	"github.com/starfly-fabrics/starfly/pkg/mcp"
	"github.com/starfly-fabrics/starfly/pkg/metrics"
	"github.com/starfly-fabrics/starfly/pkg/secrets"
)

// ── Server accessor tests ────────────────────────────────────────────

func TestServer_TLSEnabled(t *testing.T) {
	s := newTestServer()
	if s.TLSEnabled() {
		t.Error("TLSEnabled should be false for dev server")
	}
}

func TestServer_Metrics(t *testing.T) {
	s := newTestServer()
	if s.Metrics() == nil {
		t.Error("Metrics() should not be nil")
	}
}

func TestServer_Broadcaster(t *testing.T) {
	s := newTestServer()
	if s.Broadcaster() == nil {
		t.Error("Broadcaster() should not be nil")
	}
}

func TestWithUnitID(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil, WithUnitID("my-unit"))
	if s.unitID != "my-unit" {
		t.Errorf("unitID = %q, want %q", s.unitID, "my-unit")
	}
}

func TestWithSignalReceiver(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	rx := &mockSignalReceiver{}
	s := New(cfg, "test", nil, WithSignalReceiver(rx))
	if s.signalReceiver == nil {
		t.Error("signalReceiver should not be nil")
	}
}

func TestWithSignalTransmitter(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	tx := &mockSignalTransmitter{
		createStream: func(_ context.Context, _ *core.StreamConfig) (*core.Stream, error) { return nil, nil },
		deleteStream: func(_ context.Context, _ string) error { return nil },
		getStatus:    func(_ context.Context, _ string) (*core.StreamStatus, error) { return nil, nil },
	}
	s := New(cfg, "test", nil, WithSignalTransmitter(tx))
	if s.signalTransmitter == nil {
		t.Error("signalTransmitter should not be nil")
	}
}

func TestWithOpenAPISpec(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil, WithOpenAPISpec([]byte("openapi: 3.1")))
	if s.openapiSpec == nil {
		t.Error("openapiSpec should not be nil")
	}
}

func TestWithRevocationIndex(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	idx := &mockRevocationIndex{hash: "abc"}
	s := New(cfg, "test", nil, WithRevocationIndex(idx))
	if s.revocationIndex == nil {
		t.Error("revocationIndex should not be nil")
	}
}

func TestWithMCPRegistry(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil, WithMCPRegistry(mcp.NewRegistry()))
	if s.mcpRegistry == nil {
		t.Error("mcpRegistry should not be nil")
	}
}

func TestWithEncryptionKeyStore(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil, WithEncryptionKeyStore(secrets.NewInMemoryKeyStore()))
	if s.encryptionKeyStore == nil {
		t.Error("encryptionKeyStore should not be nil")
	}
}

func TestWithMCPDeps(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil, WithMCPDeps(nil, nil, nil, nil))
	// Just ensure it doesn't panic.
	if s == nil {
		t.Error("server should not be nil")
	}
}

// ── handleOpenAPI tests ──────────────────────────────────────────────

func TestHandleOpenAPI_Configured(t *testing.T) {
	spec := []byte("openapi: '3.1.0'\ninfo:\n  title: Starfly\n")
	s := &Server{openapiSpec: spec}

	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	s.handleOpenAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("Content-Type = %q, want application/yaml", ct)
	}
	if rec.Body.String() != string(spec) {
		t.Errorf("body = %q, want %q", rec.Body.String(), string(spec))
	}
}

func TestHandleOpenAPI_NotConfigured(t *testing.T) {
	s := &Server{}

	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	s.handleOpenAPI(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ── handleExchangeToken attestation header tests ─────────────────────

func TestHandleExchangeToken_AttestationHeader(t *testing.T) {
	s := newTestServerWithExchanger(&mockExchanger{
		resp: &core.TokenExchangeResponse{
			AccessToken:     "tok",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
			TokenType:       "Bearer",
			ExpiresIn:       300,
		},
	})

	body := `{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token":"x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","audience":"a"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/exchange/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(exchange.AttestationHeaderName, "BAD_HEADER_VALUE")
	w := httptest.NewRecorder()

	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for bad attestation header", w.Code, http.StatusBadRequest)
	}
}

// ── MCP handler tests ────────────────────────────────────────────────

func newTestServerWithMCP() *Server {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	reg := mcp.NewRegistry()
	return New(cfg, "test", nil, WithMCPRegistry(reg))
}

func TestHandleMCPToolList_NoRegistry(t *testing.T) {
	s := &Server{metrics: metrics.New("t", "u", "d")}

	req := httptest.NewRequest(http.MethodGet, "/v1/mcp/tools", nil)
	rec := httptest.NewRecorder()
	s.handleMCPToolList(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleMCPToolList_Empty(t *testing.T) {
	s := newTestServerWithMCP()

	req := httptest.NewRequest(http.MethodGet, "/v1/mcp/tools", nil)
	rec := httptest.NewRecorder()
	s.handleMCPToolList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["count"].(float64) != 0 {
		t.Errorf("count = %v, want 0", resp["count"])
	}
}

func TestHandleMCPToolRegister_Success(t *testing.T) {
	s := newTestServerWithMCP()

	body := `{"tool_id":"tool-1","name":"Test Tool","description":"A test tool"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPToolRegister(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestHandleMCPToolRegister_NoRegistry(t *testing.T) {
	s := &Server{metrics: metrics.New("t", "u", "d")}

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	s.handleMCPToolRegister(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleMCPToolRegister_MalformedJSON(t *testing.T) {
	s := newTestServerWithMCP()

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPToolRegister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleMCPToolRegister_MissingToolID(t *testing.T) {
	s := newTestServerWithMCP()

	body := `{"name":"No ID"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPToolRegister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleMCPToolRegister_Duplicate(t *testing.T) {
	s := newTestServerWithMCP()

	body := `{"tool_id":"dup-tool","name":"Dup"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPToolRegister(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("first register: status = %d, want %d", rec.Code, http.StatusCreated)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/mcp/tools", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.handleMCPToolRegister(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("duplicate register: status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestHandleMCPToolDeregister_NoRegistry(t *testing.T) {
	s := &Server{metrics: metrics.New("t", "u", "d")}

	req := httptest.NewRequest(http.MethodDelete, "/v1/mcp/tools?tool_id=x", nil)
	rec := httptest.NewRecorder()
	s.handleMCPToolDeregister(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleMCPToolDeregister_MissingToolID(t *testing.T) {
	s := newTestServerWithMCP()

	req := httptest.NewRequest(http.MethodDelete, "/v1/mcp/tools", nil)
	rec := httptest.NewRecorder()
	s.handleMCPToolDeregister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleMCPToolDeregister_NotFound(t *testing.T) {
	s := newTestServerWithMCP()

	req := httptest.NewRequest(http.MethodDelete, "/v1/mcp/tools?tool_id=nonexistent", nil)
	rec := httptest.NewRecorder()
	s.handleMCPToolDeregister(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleMCPToolDeregister_Success(t *testing.T) {
	s := newTestServerWithMCP()

	// Register first.
	body := `{"tool_id":"del-tool","name":"Del"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPToolRegister(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d", rec.Code)
	}

	// Deregister.
	req = httptest.NewRequest(http.MethodDelete, "/v1/mcp/tools?tool_id=del-tool", nil)
	rec = httptest.NewRecorder()
	s.handleMCPToolDeregister(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("deregister: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleMCPVerify_MalformedJSON(t *testing.T) {
	s := newTestServerWithMCP()

	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/verify", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPVerify(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleMCPVerify_MissingToken(t *testing.T) {
	s := newTestServerWithMCP()

	body := `{"tool_id":"t1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPVerify(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleMCPVerify_InvalidToken(t *testing.T) {
	s := newTestServerWithMCP()

	body := `{"token":"not-a-jwt","tool_id":"t1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleMCPVerify(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// ── Encryption key handler tests ─────────────────────────────────────

func TestHandleEncryptionKeyRegister_NoStore(t *testing.T) {
	s := &Server{}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key", nil)
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleEncryptionKeyRegister_NoAuth(t *testing.T) {
	s := &Server{encryptionKeyStore: secrets.NewInMemoryKeyStore()}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key", nil)
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleEncryptionKeyRegister_NoJWKS(t *testing.T) {
	s := &Server{encryptionKeyStore: secrets.NewInMemoryKeyStore()}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestHandleEncryptionKeyRegister_JWKSError(t *testing.T) {
	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               &mockJWKS{err: errors.New("keyset error")},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestHandleEncryptionKeyRegister_InvalidToken(t *testing.T) {
	set := buildTestKeySet(t)
	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               &mockJWKS{set: set},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key",
		strings.NewReader(`{"public_key":{}}`))
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// ── JWKS error path ──────────────────────────────────────────────────

func TestJWKSEndpoint_ProviderError(t *testing.T) {
	cfg := &core.Config{ListenAddr: ":0", RateLimit: core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10}}
	s := New(cfg, "test", nil, WithJWKS(&mockJWKS{err: errors.New("key failure")}))

	req := httptest.NewRequest(http.MethodGet, "/v1/identity/jwks", nil)
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// ── Middleware edge cases ────────────────────────────────────────────

func TestResponseWriter_Flush(t *testing.T) {
	inner := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}
	rw.Flush()
	// httptest.ResponseRecorder implements http.Flusher; no panic = success.
}

func TestResponseWriter_Unwrap(t *testing.T) {
	inner := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: inner, statusCode: http.StatusOK}
	if rw.Unwrap() != inner {
		t.Error("Unwrap should return inner ResponseWriter")
	}
}

// ── schemeHost TLS path ──────────────────────────────────────────────

func TestSchemeHost_HTTPS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ssf-configuration", nil)
	req.Host = "secure.example.com"
	req.TLS = &tls.ConnectionState{}
	got := schemeHost(req)
	if got != "https://secure.example.com" {
		t.Errorf("schemeHost = %q, want https://secure.example.com", got)
	}
}

// ── clientIP fallback ────────────────────────────────────────────────

func TestClientIP_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1" // no port
	got := clientIP(req)
	if got != "192.168.1.1" {
		t.Errorf("clientIP = %q, want 192.168.1.1", got)
	}
}

func TestClientIP_XForwardedFor_Single(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	got := clientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("clientIP = %q, want 10.0.0.1", got)
	}
}

// ── Rate limit context cancellation ──────────────────────────────────

func TestRateLimiter_WithContext(t *testing.T) {
	cfg := core.RateLimitConfig{
		GlobalRate: 100, GlobalBurst: 100,
		PerIPRate: 10, PerIPBurst: 10,
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := rateLimitMiddleware(okHandler(), cfg, false, testMetrics(), ctx)
	cancel() // Stop the cleanup goroutine.

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// ── ShutdownMTLS nil ─────────────────────────────────────────────────

func TestShutdownMTLS_NilServer(t *testing.T) {
	s := newTestServer()
	if err := s.ShutdownMTLS(context.Background()); err != nil {
		t.Errorf("ShutdownMTLS with nil mtlsServer: %v", err)
	}
}

func TestListenAndServeTLS_NilServer(t *testing.T) {
	s := newTestServer()
	if err := s.ListenAndServeTLS(); err != nil {
		t.Errorf("ListenAndServeTLS with nil mtlsServer: %v", err)
	}
}

// ── EventBroadcaster double-unsubscribe ──────────────────────────────

func TestEventBroadcaster_DoubleUnsubscribe(t *testing.T) {
	b := NewEventBroadcaster()
	ch := b.Subscribe()
	b.Unsubscribe(ch)
	b.Unsubscribe(ch) // should not panic
}

// ── writeJSON with valid struct ──────────────────────────────────────

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{"key": "value"})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if body["key"] != "value" {
		t.Errorf("body key = %q, want value", body["key"])
	}
}

// ── MCP list with tools registered ───────────────────────────────────

func TestHandleMCPToolList_WithTools(t *testing.T) {
	s := newTestServerWithMCP()

	// Register a tool.
	_ = s.mcpRegistry.Register(&mcp.ToolEntry{ToolID: "t1", Name: "Tool 1"})

	req := httptest.NewRequest(http.MethodGet, "/v1/mcp/tools", nil)
	rec := httptest.NewRecorder()
	s.handleMCPToolList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp["count"].(float64) != 1 {
		t.Errorf("count = %v, want 1", resp["count"])
	}
}

// ── New server with trust domains ────────────────────────────────────

func TestNew_WithTrustDomains(t *testing.T) {
	cfg := &core.Config{
		ListenAddr:   ":0",
		TrustDomains: []core.TrustDomain{{Name: "spiffe://example.com", Enabled: true}},
		RateLimit:    core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil)
	if s == nil {
		t.Fatal("server should not be nil")
	}
}

// ── handleHealth via full server (routes registered) ─────────────────

func TestHandleTrustDomains_ViaRouter(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	domains := []core.TrustDomain{
		{Name: "dev.local", Issuer: "https://kubernetes.default.svc.cluster.local", Enabled: true},
	}
	s := New(cfg, "test", nil, WithTrustDomains(domains))

	req := httptest.NewRequest(http.MethodGet, "/v1/sys/trust-domains", nil)
	rec := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		Count        int `json:"count"`
		TrustDomains []struct {
			Name    string `json:"name"`
			Issuer  string `json:"issuer"`
			Enabled bool   `json:"enabled"`
		} `json:"trust_domains"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("count = %d, want 1", resp.Count)
	}
	if len(resp.TrustDomains) != 1 || resp.TrustDomains[0].Name != "dev.local" {
		t.Errorf("trust_domains = %+v, want dev.local", resp.TrustDomains)
	}
}

func TestHandleOpenAPI_ViaRouter(t *testing.T) {
	spec := []byte("openapi: 3.1")
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil, WithOpenAPISpec(spec))

	req := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ── Unused function coverage: newUUID ────────────────────────────────

func TestNewUUID(t *testing.T) {
	id := newUUID()
	if len(id) != 36 {
		t.Errorf("UUID length = %d, want 36", len(id))
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("UUID parts = %d, want 5", len(parts))
	}
}

// ── updateTLSCertExpiryMetric edge cases ─────────────────────────────

func TestUpdateTLSCertExpiryMetric_NilReloader(t *testing.T) {
	s := &Server{metrics: metrics.New("t", "u", "d")}
	s.updateTLSCertExpiryMetric() // should not panic
}

func TestUpdateTLSCertExpiryMetric_NilMetrics(t *testing.T) {
	s := &Server{}
	s.updateTLSCertExpiryMetric() // should not panic
}

// ── handleEncryptionKeyRegister bad body after valid JWT parse ────────

func TestHandleEncryptionKeyRegister_BadRequestBody(t *testing.T) {
	// This tests the path where JWT is parsed but body is invalid JSON.
	// We need a valid JWT signed with a known key.
	// Instead, test the no-subject path by creating a JWT without sub.

	s := &Server{
		encryptionKeyStore: secrets.NewInMemoryKeyStore(),
		jwks:               &mockJWKS{set: jwk.NewSet()},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent/encryption-key",
		strings.NewReader(`not json`))
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0In0.")
	rec := httptest.NewRecorder()
	s.handleEncryptionKeyRegister(rec, req)

	// Will fail at JWT parsing with empty keyset — expect 401.
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// ── SSF configuration with HTTPS ─────────────────────────────────────

func TestHandleSSFConfiguration_HTTPS(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ssf-configuration", nil)
	req.Host = "secure.example.com"
	req.TLS = &tls.ConnectionState{}

	rec := httptest.NewRecorder()
	s.handleSSFConfiguration(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var cfg core.SSFConfiguration
	_ = json.NewDecoder(rec.Body).Decode(&cfg)
	if !strings.HasPrefix(cfg.JWKsURI, "https://") {
		t.Errorf("jwks_uri = %q, want https:// prefix", cfg.JWKsURI)
	}
}

// ── Exchange attestation valid header ────────────────────────────────

func TestHandleExchangeToken_NoAttestation(t *testing.T) {
	s := newTestServerWithExchanger(&mockExchanger{
		resp: &core.TokenExchangeResponse{
			AccessToken:     "tok",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
			TokenType:       "Bearer",
			ExpiresIn:       300,
		},
	})

	body := `{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token":"x","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","audience":"a"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/exchange/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
