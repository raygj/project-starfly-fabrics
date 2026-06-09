package mcp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

func post(t *testing.T, path, body, contentType, auth string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	return r
}

func TestExtractFromHTTP_MCPBody(t *testing.T) {
	a := New()
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"my-tool","arguments":{"q":"test"}},"id":1}`
	result, err := a.ExtractFromHTTP(post(t, "/", body, "application/json", "tok123"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchDefinitive {
		t.Errorf("confidence: got %d, want %d", result.Confidence, toolcall.MatchDefinitive)
	}
	if result.Request.ToolID != "my-tool" {
		t.Errorf("ToolID: %q", result.Request.ToolID)
	}
	if result.Request.Token != "tok123" {
		t.Errorf("Token: %q", result.Request.Token)
	}
	if result.Request.Protocol != toolcall.ProtocolMCP {
		t.Errorf("Protocol: %q", result.Request.Protocol)
	}
}

func TestExtractFromHTTP_PathBased(t *testing.T) {
	a := New()
	// /v1/mcp/tools/{id}/call pattern.
	r := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/search-tool/call", nil)
	r.Header.Set("Authorization", "Bearer abc")
	result, err := a.ExtractFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchLikely {
		t.Errorf("confidence: got %d, want %d", result.Confidence, toolcall.MatchLikely)
	}
	if result.Request.ToolID != "search-tool" {
		t.Errorf("ToolID: %q", result.Request.ToolID)
	}
}

func TestExtractFromHTTP_NonMCPBody(t *testing.T) {
	a := New()
	body := `{"action":"buy","amount":100}`
	result, err := a.ExtractFromHTTP(post(t, "/", body, "application/json", "tok"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("expected MatchNone for non-MCP JSON, got %d", result.Confidence)
	}
}

func TestExtractFromHTTP_GetMethodReturnsNone(t *testing.T) {
	a := New()
	r := httptest.NewRequest(http.MethodGet, "/v1/mcp/tools/foo", nil)
	result, err := a.ExtractFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("GET should return MatchNone, got %d", result.Confidence)
	}
}

func TestExtractFromHTTP_WrongJSONRPCVersion(t *testing.T) {
	a := New()
	body := `{"jsonrpc":"1.0","method":"tools/call","params":{"name":"t"},"id":1}`
	result, _ := a.ExtractFromHTTP(post(t, "/", body, "application/json", "tok"))
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("wrong jsonrpc version should return MatchNone, got %d", result.Confidence)
	}
}

func TestExtractFromMessage_Valid(t *testing.T) {
	a := New()
	msg := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"stdio-tool","arguments":{}},"id":2}`)
	result, err := a.ExtractFromMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Confidence != toolcall.MatchDefinitive {
		t.Errorf("stdio MCP should be MatchDefinitive, got %d", result.Confidence)
	}
	if result.Request.ToolID != "stdio-tool" {
		t.Errorf("ToolID: %q", result.Request.ToolID)
	}
	if result.Request.TransportMeta.MCPTransport != "stdio" {
		t.Errorf("MCPTransport: %q", result.Request.TransportMeta.MCPTransport)
	}
}

func TestExtractFromMessage_Invalid(t *testing.T) {
	a := New()
	result, _ := a.ExtractFromMessage([]byte(`not json`))
	if result.Confidence != toolcall.MatchNone {
		t.Errorf("invalid JSON should return MatchNone")
	}
}

func TestFormatError(t *testing.T) {
	a := New()
	w := httptest.NewRecorder()
	a.FormatError(w, "invalid_token", "token expired", http.StatusUnauthorized)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: %q", ct)
	}
}

func TestXMCPToolIDHeader(t *testing.T) {
	a := New()
	r := httptest.NewRequest(http.MethodPost, "/v1/mcp/tools/ignored/call", nil)
	r.Header.Set("Authorization", "Bearer tok")
	r.Header.Set("X-MCP-Tool-ID", "override-tool")
	result, _ := a.ExtractFromHTTP(r)
	if result.Request.ToolID != "override-tool" {
		t.Errorf("X-MCP-Tool-ID should override path tool ID, got %q", result.Request.ToolID)
	}
}
