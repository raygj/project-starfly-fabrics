package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

// newTestServerWithTools builds a minimal Server with a toolcall.Registry.
func newTestServerWithTools() *Server {
	reg := toolcall.NewRegistry()
	return &Server{
		toolRegistry: reg,
		devMode:      true,
	}
}

func registerTool(t *testing.T, s *Server, entry toolcall.ToolEntry) {
	t.Helper()
	if err := s.toolRegistry.Register(&entry); err != nil {
		t.Fatalf("pre-register tool %q: %v", entry.ToolID, err)
	}
}

// ── GET /v1/tools ─────────────────────────────────────────────────────────────

func TestHandleToolList_Empty(t *testing.T) {
	s := newTestServerWithTools()
	r := httptest.NewRequest(http.MethodGet, "/v1/tools", nil)
	w := httptest.NewRecorder()
	s.handleToolList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["count"].(float64) != 0 {
		t.Errorf("count: got %v, want 0", resp["count"])
	}
}

func TestHandleToolList_WithProtocolFilter(t *testing.T) {
	s := newTestServerWithTools()
	registerTool(t, s, toolcall.ToolEntry{
		ToolID:      "mcp-tool",
		ResourceURI: "mcp://mcp-tool",
		Protocols:   []toolcall.Protocol{toolcall.ProtocolMCP},
	})
	registerTool(t, s, toolcall.ToolEntry{
		ToolID:      "http-tool",
		ResourceURI: "http://http-tool",
		Protocols:   []toolcall.Protocol{toolcall.ProtocolHTTP},
	})

	// Filter by mcp — should return 1.
	r := httptest.NewRequest(http.MethodGet, "/v1/tools?protocol=mcp", nil)
	w := httptest.NewRecorder()
	s.handleToolList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["count"].(float64) != 1 {
		t.Errorf("expected 1 mcp tool, got %v", resp["count"])
	}
}

func TestHandleToolList_NoRegistry(t *testing.T) {
	s := &Server{devMode: true}
	r := httptest.NewRequest(http.MethodGet, "/v1/tools", nil)
	w := httptest.NewRecorder()
	s.handleToolList(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// ── POST /v1/tools ────────────────────────────────────────────────────────────

func TestHandleToolRegister_Success(t *testing.T) {
	s := newTestServerWithTools()
	entry := toolcall.ToolEntry{
		ToolID:      "new-tool",
		Name:        "New Tool",
		ResourceURI: "mcp://new-tool",
		Protocols:   []toolcall.Protocol{toolcall.ProtocolMCP},
	}
	body, _ := json.Marshal(entry)
	r := httptest.NewRequest(http.MethodPost, "/v1/tools", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleToolRegister(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("status: got %d, want 201", w.Code)
	}
	_, ok := s.toolRegistry.Get("new-tool")
	if !ok {
		t.Error("tool was not stored in registry")
	}
}

func TestHandleToolRegister_MissingToolID(t *testing.T) {
	s := newTestServerWithTools()
	body := []byte(`{"name":"No ID"}`)
	r := httptest.NewRequest(http.MethodPost, "/v1/tools", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleToolRegister(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleToolRegister_Duplicate(t *testing.T) {
	s := newTestServerWithTools()
	registerTool(t, s, toolcall.ToolEntry{ToolID: "dup-tool", ResourceURI: "mcp://dup-tool"})

	body, _ := json.Marshal(toolcall.ToolEntry{ToolID: "dup-tool"})
	r := httptest.NewRequest(http.MethodPost, "/v1/tools", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleToolRegister(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func TestHandleToolRegister_InvalidJSON(t *testing.T) {
	s := newTestServerWithTools()
	r := httptest.NewRequest(http.MethodPost, "/v1/tools", bytes.NewReader([]byte(`not json`)))
	w := httptest.NewRecorder()
	s.handleToolRegister(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ── GET /v1/tools/{tool_id} ───────────────────────────────────────────────────

func TestHandleToolGet_Found(t *testing.T) {
	s := newTestServerWithTools()
	registerTool(t, s, toolcall.ToolEntry{ToolID: "find-me", ResourceURI: "mcp://find-me"})

	r := httptest.NewRequest(http.MethodGet, "/v1/tools/find-me", nil)
	r.SetPathValue("tool_id", "find-me")
	w := httptest.NewRecorder()
	s.handleToolGet(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var got toolcall.ToolEntry
	_ = json.NewDecoder(w.Body).Decode(&got)
	if got.ToolID != "find-me" {
		t.Errorf("ToolID: %q", got.ToolID)
	}
}

func TestHandleToolGet_NotFound(t *testing.T) {
	s := newTestServerWithTools()
	r := httptest.NewRequest(http.MethodGet, "/v1/tools/missing", nil)
	r.SetPathValue("tool_id", "missing")
	w := httptest.NewRecorder()
	s.handleToolGet(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ── DELETE /v1/tools/{tool_id} ────────────────────────────────────────────────

func TestHandleToolDeregister_Success(t *testing.T) {
	s := newTestServerWithTools()
	registerTool(t, s, toolcall.ToolEntry{ToolID: "gone", ResourceURI: "mcp://gone"})

	r := httptest.NewRequest(http.MethodDelete, "/v1/tools/gone", nil)
	r.SetPathValue("tool_id", "gone")
	w := httptest.NewRecorder()
	s.handleToolDeregister(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if _, ok := s.toolRegistry.Get("gone"); ok {
		t.Error("tool should be gone from registry")
	}
}

func TestHandleToolDeregister_NotFound(t *testing.T) {
	s := newTestServerWithTools()
	r := httptest.NewRequest(http.MethodDelete, "/v1/tools/nope", nil)
	r.SetPathValue("tool_id", "nope")
	w := httptest.NewRecorder()
	s.handleToolDeregister(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ── GET /v1/tools/{tool_id}/audit ────────────────────────────────────────────

func TestHandleToolAudit_Found(t *testing.T) {
	s := newTestServerWithTools()
	registerTool(t, s, toolcall.ToolEntry{ToolID: "audited", ResourceURI: "mcp://audited"})

	r := httptest.NewRequest(http.MethodGet, "/v1/tools/audited/audit", nil)
	r.SetPathValue("tool_id", "audited")
	w := httptest.NewRecorder()
	s.handleToolAudit(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["tool_id"] != "audited" {
		t.Errorf("tool_id: %v", resp["tool_id"])
	}
}

func TestHandleToolAudit_NotFound(t *testing.T) {
	s := newTestServerWithTools()
	r := httptest.NewRequest(http.MethodGet, "/v1/tools/ghost/audit", nil)
	r.SetPathValue("tool_id", "ghost")
	w := httptest.NewRecorder()
	s.handleToolAudit(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ── MCP alias parity ─────────────────────────────────────────────────────────

// TestToolRegistryMCPAliasParity verifies that a tool registered via /v1/tools
// with protocol=mcp is visible from the universal list when filtered by mcp.
func TestToolRegistryMCPAliasParity(t *testing.T) {
	s := newTestServerWithTools()
	entry := toolcall.ToolEntry{
		ToolID:      "shared-tool",
		ResourceURI: "mcp://shared-tool",
		Protocols:   []toolcall.Protocol{toolcall.ProtocolMCP},
	}
	if err := s.toolRegistry.Register(&entry); err != nil {
		t.Fatal(err)
	}

	// /v1/tools unfiltered.
	r := httptest.NewRequest(http.MethodGet, "/v1/tools", nil)
	w := httptest.NewRecorder()
	s.handleToolList(w, r)
	var all map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&all)

	// /v1/tools?protocol=mcp filtered.
	r2 := httptest.NewRequest(http.MethodGet, "/v1/tools?protocol=mcp", nil)
	w2 := httptest.NewRecorder()
	s.handleToolList(w2, r2)
	var filtered map[string]interface{}
	_ = json.NewDecoder(w2.Body).Decode(&filtered)

	if all["count"] != filtered["count"] {
		t.Errorf("unfiltered count %v != filtered mcp count %v", all["count"], filtered["count"])
	}
}
