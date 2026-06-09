package toolcall

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ── stub adapter ─────────────────────────────────────────────────────────────

type stubAdapter struct {
	proto      Protocol
	confidence MatchConfidence
	toolID     string
	token      string
}

func (s *stubAdapter) Protocol() Protocol { return s.proto }

func (s *stubAdapter) ExtractFromHTTP(_ *http.Request) (*MatchResult, error) {
	if s.confidence == MatchNone {
		return &MatchResult{Confidence: MatchNone}, nil
	}
	return &MatchResult{
		Confidence: s.confidence,
		Request: &ToolCallRequest{
			Protocol: s.proto,
			ToolID:   s.toolID,
			Token:    s.token,
		},
	}, nil
}

func (s *stubAdapter) ExtractFromMessage(_ []byte) (*MatchResult, error) {
	return &MatchResult{Confidence: MatchNone}, nil
}

func (s *stubAdapter) FormatError(w http.ResponseWriter, code, _ string, status int) {
	w.Header().Set("X-Adapter-Protocol", string(s.proto))
	http.Error(w, code, status)
}

// ── stub verifier ─────────────────────────────────────────────────────────────

type stubVerifier struct {
	identity *VerifiedIdentity
	err      error
}

func (v *stubVerifier) Verify(_ context.Context, req *ToolCallRequest) (*VerifiedIdentity, error) {
	if v.err != nil {
		return nil, v.err
	}
	id := v.identity
	if id == nil {
		id = &VerifiedIdentity{Subject: "agent", Protocol: req.Protocol, ToolID: req.ToolID}
	}
	return id, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func okHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFromContext(r.Context())
		if !ok || id == nil {
			t.Error("identity missing from context")
		}
		w.WriteHeader(http.StatusOK)
	})
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestMiddleware_DefinitiveMatchReachesHandler(t *testing.T) {
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchDefinitive, toolID: "my-tool", token: "tok"}
	v := &stubVerifier{}
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v}, okHandler(t))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
}

func TestMiddleware_NoAdapterMatch_Returns401(t *testing.T) {
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchNone}
	v := &stubVerifier{}
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v}, okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
}

func TestMiddleware_PassThroughOnNoMatch(t *testing.T) {
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchNone}
	v := &stubVerifier{}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	})
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v, PassThrough: true}, next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Error("next handler not reached in pass-through mode")
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("status: got %d, want 418", w.Code)
	}
}

func TestMiddleware_VerifierError_Returns401(t *testing.T) {
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchDefinitive, toolID: "t", token: "tok"}
	v := &stubVerifier{err: ErrMissingToken}
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v}, okHandler(t))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
}

func TestMiddleware_VerifierCapabilityDenied_Returns403(t *testing.T) {
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchDefinitive, toolID: "t", token: "tok"}
	v := &stubVerifier{err: ErrCapabilityDenied}
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v}, okHandler(t))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", w.Code)
	}
}

func TestMiddleware_HigherConfidenceWins(t *testing.T) {
	// MCP adapter returns Definitive; HTTP adapter returns Likely.
	// MCP should win regardless of order.
	mcpA := &stubAdapter{proto: ProtocolMCP, confidence: MatchDefinitive, toolID: "mcp-tool", token: "tok"}
	httpA := &stubAdapter{proto: ProtocolHTTP, confidence: MatchLikely, toolID: "http-tool", token: "tok"}

	var seenProtocol Protocol
	v := &stubVerifier{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := IdentityFromContext(r.Context()); ok {
			seenProtocol = id.Protocol
		}
		w.WriteHeader(http.StatusOK)
	})

	// HTTP adapter listed first — MCP should still win on confidence.
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{httpA, mcpA}, Verifier: v}, next)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if seenProtocol != ProtocolMCP {
		t.Errorf("expected MCP adapter to win, got %q", seenProtocol)
	}
}

func TestMiddleware_TieBrokenByOrder(t *testing.T) {
	// Two adapters with the same confidence — adapter order decides.
	first := &stubAdapter{proto: ProtocolMCP, confidence: MatchLikely, toolID: "first", token: "tok"}
	second := &stubAdapter{proto: ProtocolHTTP, confidence: MatchLikely, toolID: "second", token: "tok"}

	var seenToolID string
	v := &stubVerifier{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := IdentityFromContext(r.Context()); ok {
			seenToolID = id.ToolID
		}
		w.WriteHeader(http.StatusOK)
	})

	h := Middleware(MiddlewareConfig{Adapters: []Adapter{first, second}, Verifier: v}, next)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if seenToolID != "first" {
		t.Errorf("expected first adapter to win tie, got %q", seenToolID)
	}
}

func TestMiddleware_BelowMinConfidencePassThrough(t *testing.T) {
	// Adapter returns Likely but MinConfidence is Definitive.
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchLikely, toolID: "t", token: "tok"}
	v := &stubVerifier{}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(MiddlewareConfig{
		Adapters:      []Adapter{a},
		Verifier:      v,
		MinConfidence: MatchDefinitive,
		PassThrough:   true,
	}, next)

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Error("next handler not reached when below MinConfidence with PassThrough")
	}
}

func TestMiddleware_ErrorFormattedByWinningAdapter(t *testing.T) {
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchDefinitive, toolID: "t", token: "tok"}
	v := &stubVerifier{err: ErrCapabilityDenied}
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v}, okHandler(t))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if proto := w.Header().Get("X-Adapter-Protocol"); proto != string(ProtocolMCP) {
		t.Errorf("error formatted by wrong adapter: %q", proto)
	}
}

func TestMiddleware_IdentityFromContext_Missing(t *testing.T) {
	_, ok := IdentityFromContext(context.Background())
	if ok {
		t.Error("expected false for empty context")
	}
}

// TestClassifyVerifyError ensures every sentinel maps to the right HTTP status
// and error code — including wrapped errors (errors.Is semantics).
func TestClassifyVerifyError(t *testing.T) {
	import_fmt_errorf := func(sentinel error) error {
		return fmt.Errorf("verify: %w: tool \"search\"", sentinel)
	}

	cases := []struct {
		err        error
		wantCode   string
		wantStatus int
	}{
		// Plain sentinels.
		{ErrMissingToken, "missing_token", http.StatusUnauthorized},
		{ErrInvalidToken, "invalid_token", http.StatusUnauthorized},
		{ErrTokenRevoked, "token_revoked", http.StatusUnauthorized},
		{ErrToolNotRegistered, "tool_not_found", http.StatusNotFound},
		{ErrCapabilityDenied, "insufficient_capabilities", http.StatusForbidden},
		{ErrBlastRadiusExceeded, "blast_radius_exceeded", http.StatusForbidden},
		{ErrAudienceMismatch, "audience_mismatch", http.StatusForbidden},
		{ErrPolicyDenied, "policy_denied", http.StatusForbidden},
		{ErrProtocolDenied, "protocol_denied", http.StatusForbidden},
		{ErrExecBindingRequired, "exec_binding_invalid", http.StatusForbidden},
		{ErrExecPayloadMissing, "exec_binding_invalid", http.StatusForbidden},
		{ErrExecPayloadMismatch, "exec_binding_invalid", http.StatusForbidden},
		{ErrExecOpMismatch, "exec_binding_invalid", http.StatusForbidden},
		{ErrExecTargetMismatch, "exec_binding_invalid", http.StatusForbidden},
		// Wrapped sentinels — errors.Is must unwrap correctly.
		{import_fmt_errorf(ErrProtocolDenied), "protocol_denied", http.StatusForbidden},
		{import_fmt_errorf(ErrCapabilityDenied), "insufficient_capabilities", http.StatusForbidden},
		{import_fmt_errorf(ErrTokenRevoked), "token_revoked", http.StatusUnauthorized},
		// Unknown error → internal_error.
		{fmt.Errorf("something unexpected"), "internal_error", http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.wantCode+"/"+tc.err.Error()[:min(len(tc.err.Error()), 30)], func(t *testing.T) {
			code, _, status := classifyVerifyError(tc.err)
			if code != tc.wantCode {
				t.Errorf("code: got %q, want %q", code, tc.wantCode)
			}
			if status != tc.wantStatus {
				t.Errorf("status: got %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestMiddleware_MetricsHooks verifies that MiddlewareMetrics callbacks fire
// for pass and deny outcomes.
func TestMiddleware_MetricsHooks(t *testing.T) {
	var (
		recordedProtocol string
		recordedDecision string
		durationProtocol string
		tieFired         bool
	)
	metrics := &MiddlewareMetrics{
		RecordCall:      func(protocol, decision string) { recordedProtocol, recordedDecision = protocol, decision },
		ObserveDuration: func(protocol string, _ float64) { durationProtocol = protocol },
		IncTie:          func() { tieFired = true },
	}

	// Pass case.
	a := &stubAdapter{proto: ProtocolMCP, confidence: MatchDefinitive, toolID: "t", token: "tok"}
	v := &stubVerifier{}
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v, Metrics: metrics}, okHandler(t))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if recordedDecision != "allowed" {
		t.Errorf("decision: got %q, want allowed", recordedDecision)
	}
	if recordedProtocol != string(ProtocolMCP) {
		t.Errorf("protocol: got %q, want mcp", recordedProtocol)
	}
	if durationProtocol != string(ProtocolMCP) {
		t.Errorf("duration protocol: got %q, want mcp", durationProtocol)
	}

	// Deny case.
	v2 := &stubVerifier{err: ErrCapabilityDenied}
	h2 := Middleware(MiddlewareConfig{Adapters: []Adapter{a}, Verifier: v2, Metrics: metrics}, okHandler(t))
	h2.ServeHTTP(httptest.NewRecorder(), r)

	if recordedDecision != "denied" {
		t.Errorf("decision: got %q, want denied", recordedDecision)
	}

	if tieFired {
		t.Error("tie should not have fired for single adapter")
	}
}

// TestMiddleware_TieIncrementsCounter verifies that equal-confidence adapters
// trigger the IncTie metric.
func TestMiddleware_TieIncrementsCounter(t *testing.T) {
	var tieFired bool
	metrics := &MiddlewareMetrics{
		RecordCall:      func(_, _ string) {},
		ObserveDuration: func(_ string, _ float64) {},
		IncTie:          func() { tieFired = true },
	}
	a1 := &stubAdapter{proto: ProtocolMCP, confidence: MatchLikely, toolID: "t1", token: "tok"}
	a2 := &stubAdapter{proto: ProtocolHTTP, confidence: MatchLikely, toolID: "t2", token: "tok"}
	h := Middleware(MiddlewareConfig{
		Adapters: []Adapter{a1, a2},
		Verifier: &stubVerifier{},
		Metrics:  metrics,
	}, okHandler(t))

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if !tieFired {
		t.Error("expected IncTie to fire for equal-confidence adapters")
	}
}

// ── RED: protocol confusion ───────────────────────────────────────────────────

// TestMiddleware_ProtocolConfusion verifies that a request detected as HTTP
// cannot gain MCP-level access even if the token claims MCP audience.
// The winning adapter sets Protocol=ProtocolHTTP on the ToolCallRequest, and
// the verifier enforces that the tool must allow that protocol.
func TestMiddleware_ProtocolConfusion_HTTPCannotMasqueradeMCP(t *testing.T) {
	// Register a tool that only accepts MCP.
	reg := NewRegistry()
	_ = reg.Register(&ToolEntry{
		ToolID:      "mcp-only",
		ResourceURI: "mcp://mcp-only",
		Protocols:   []Protocol{ProtocolMCP},
	})
	v := NewVerifier(VerifierConfig{DevMode: true, Registry: reg})

	// HTTP adapter wins — sets Protocol=ProtocolHTTP.
	httpA := &stubAdapter{proto: ProtocolHTTP, confidence: MatchDefinitive, toolID: "mcp-only", token: "tok"}

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(MiddlewareConfig{Adapters: []Adapter{httpA}, Verifier: v}, next)

	// Build a minimal token that would look valid for mcp-only.
	tok := buildDevToken(t, func(b *jwt.Builder) *jwt.Builder {
		return b.Audience([]string{"mcp://mcp-only"})
	})
	httpA.token = tok

	r := httptest.NewRequest(http.MethodPost, "/api/mcp-only/call", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if reached {
		t.Error("next handler must not be reached: HTTP protocol should be denied for MCP-only tool")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}
