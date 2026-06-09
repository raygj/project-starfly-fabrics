package a2a

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

func post(t *testing.T, path, body, auth string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	return r
}

const agentCard = `{
  "name": "test-agent",
  "url": "https://agent.example.com",
  "version": "1.0",
  "capabilities": ["search", "summarize"],
  "authentication": {"type": "oidc"}
}`

func taskBody(taskType string) string {
	return `{"jsonrpc":"2.0","method":"a2a/tasks/send","params":{"taskType":"` + taskType + `","agentCard":` + agentCard + `,"input":{"q":"test"}},"id":1}`
}

// ── Protocol() ───────────────────────────────────────────────────────────────

func TestProtocol(t *testing.T) {
	a := New()
	if string(a.Protocol()) != "a2a/"+SpecRevision {
		t.Errorf("Protocol: %q", a.Protocol())
	}
}

func TestProtocol_CustomRevision(t *testing.T) {
	a := New(WithSpecRevision("custom-rev"))
	if string(a.Protocol()) != "a2a/custom-rev" {
		t.Errorf("Protocol: %q", a.Protocol())
	}
}

// ── ExtractFromHTTP ───────────────────────────────────────────────────────────

func TestExtractFromHTTP_A2ATask(t *testing.T) {
	a := New()
	r := post(t, "/a2a", taskBody("search"), "tok-123")
	result, err := a.ExtractFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchLikely {
		t.Errorf("confidence: got %d, want %d", result.Confidence, toolcall.MatchLikely)
	}
	if result.Request.Token != "tok-123" {
		t.Errorf("Token: %q", result.Request.Token)
	}
	if result.Request.Operation != "search" {
		t.Errorf("Operation: %q", result.Request.Operation)
	}
}

func TestExtractFromHTTP_AgentCardHash(t *testing.T) {
	a := New()
	r := post(t, "/a2a", taskBody("summarize"), "")
	result, _ := a.ExtractFromHTTP(r)
	if result.Request == nil || result.Request.TransportMeta == nil {
		t.Fatal("nil TransportMeta")
	}
	hash, ok := result.Request.TransportMeta.Custom["a2a_card_hash"].(string)
	if !ok || hash == "" {
		t.Error("a2a_card_hash should be set in TransportMeta.Custom")
	}
	if len(hash) != 64 {
		t.Errorf("expected SHA-256 hex (64 chars), got len=%d: %q", len(hash), hash)
	}
}

func TestExtractFromHTTP_AgentCardParsed(t *testing.T) {
	a := New()
	r := post(t, "/a2a", taskBody("search"), "")
	result, _ := a.ExtractFromHTTP(r)
	if result.Request.TransportMeta.A2AAgentCard == nil {
		t.Error("A2AAgentCard should be populated")
	}
	if result.Request.TransportMeta.A2AAgentCard["name"] != "test-agent" {
		t.Errorf("agentCard.name: %v", result.Request.TransportMeta.A2AAgentCard["name"])
	}
}

func TestExtractFromHTTP_GetMethodReturnsNone(t *testing.T) {
	a := New()
	r := httptest.NewRequest(http.MethodGet, "/a2a", nil)
	result, _ := a.ExtractFromHTTP(r)
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("GET should return MatchNone, got %d", result.Confidence)
	}
}

func TestExtractFromHTTP_NonA2AMethod(t *testing.T) {
	a := New()
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{},"id":1}`
	r := post(t, "/", body, "tok")
	result, _ := a.ExtractFromHTTP(r)
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("non-A2A JSON-RPC should be MatchNone, got %d", result.Confidence)
	}
}

func TestExtractFromHTTP_InvalidJSON(t *testing.T) {
	a := New()
	r := post(t, "/a2a", "not json", "tok")
	result, _ := a.ExtractFromHTTP(r)
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("invalid JSON should be MatchNone, got %d", result.Confidence)
	}
}

func TestExtractFromHTTP_XA2AVersionHeader(t *testing.T) {
	a := New()
	r := httptest.NewRequest(http.MethodPost, "/a2a", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-A2A-Version", "2025-draft-01")
	result, err := a.ExtractFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchPossible {
		t.Errorf("X-A2A-Version heuristic: got %d, want %d", result.Confidence, toolcall.MatchPossible)
	}
}

func TestExtractFromHTTP_SpecRevisionInMeta(t *testing.T) {
	a := New(WithSpecRevision("test-rev-42"))
	r := post(t, "/a2a", taskBody("act"), "")
	result, _ := a.ExtractFromHTTP(r)
	if rev, ok := result.Request.TransportMeta.Custom["spec_revision"]; !ok || rev != "test-rev-42" {
		t.Errorf("spec_revision not in TransportMeta: %v", result.Request.TransportMeta.Custom)
	}
}

// ── ExtractFromMessage ────────────────────────────────────────────────────────

func TestExtractFromMessage_Valid(t *testing.T) {
	a := New()
	msg := []byte(`{"jsonrpc":"2.0","method":"a2a/tasks/send","params":{"taskType":"search","agentCard":` + agentCard + `},"id":2}`)
	result, err := a.ExtractFromMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchLikely {
		t.Errorf("confidence: got %d, want %d", result.Confidence, toolcall.MatchLikely)
	}
}

func TestExtractFromMessage_Invalid(t *testing.T) {
	a := New()
	result, _ := a.ExtractFromMessage([]byte("not json"))
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("invalid JSON should return MatchNone")
	}
}

func TestExtractFromMessage_NonA2A(t *testing.T) {
	a := New()
	msg := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{},"id":1}`)
	result, _ := a.ExtractFromMessage(msg)
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("non-A2A message should return MatchNone")
	}
}

// ── FormatError ───────────────────────────────────────────────────────────────

func TestFormatError(t *testing.T) {
	a := New()
	w := httptest.NewRecorder()
	a.FormatError(w, "access_denied", "insufficient capabilities", http.StatusForbidden)
	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: %q", ct)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc field: %v", resp["jsonrpc"])
	}
}

func TestFormatError_SpecRevisionInBody(t *testing.T) {
	a := New(WithSpecRevision("test-rev"))
	w := httptest.NewRecorder()
	a.FormatError(w, "denied", "msg", http.StatusForbidden)
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	errObj, _ := resp["error"].(map[string]interface{})
	data, _ := errObj["data"].(map[string]interface{})
	if data["spec_revision"] != "test-rev" {
		t.Errorf("spec_revision not in error body: %v", data)
	}
}

// ── parseAgentCard ────────────────────────────────────────────────────────────

func TestParseAgentCard_HashConsistency(t *testing.T) {
	raw := json.RawMessage(agentCard)
	hash1, _ := parseAgentCard(raw)
	hash2, _ := parseAgentCard(raw)
	if hash1 != hash2 {
		t.Error("hash is not deterministic")
	}
	if len(hash1) != 64 {
		t.Errorf("expected 64-char hex hash, got %d", len(hash1))
	}
}

func TestParseAgentCard_DifferentCardsHaveDifferentHash(t *testing.T) {
	card1 := json.RawMessage(`{"name":"agent-a"}`)
	card2 := json.RawMessage(`{"name":"agent-b"}`)
	h1, _ := parseAgentCard(card1)
	h2, _ := parseAgentCard(card2)
	if h1 == h2 {
		t.Error("different cards should have different hashes")
	}
}

func TestParseAgentCard_Empty(t *testing.T) {
	hash, parsed := parseAgentCard(nil)
	if hash != "" || parsed != nil {
		t.Error("empty input should return empty hash and nil map")
	}
}
