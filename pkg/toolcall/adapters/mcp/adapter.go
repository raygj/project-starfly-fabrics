// Package mcp provides the MCP adapter for the universal tool-call layer.
//
// It detects MCP JSON-RPC requests (method "tools/call"), extracts the token
// and tool name, and returns a ToolCallRequest for the universal Verifier.
//
// The existing pkg/mcp middleware is preserved for backward compatibility.
// New deployments should use pkg/toolcall.Middleware with this adapter.
package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

const (
	// ToolIDPrefix is the URI scheme used for MCP tool resource identifiers.
	ToolIDPrefix = "mcp://"
)

// Adapter implements toolcall.Adapter for the Model Context Protocol.
type Adapter struct {
	// ToolIDPrefix overrides the default "mcp://" prefix for resource URI construction.
	toolIDPrefix string
}

// New creates an MCP adapter. Use ToolIDPrefixOption to override the default prefix.
func New(opts ...Option) *Adapter {
	a := &Adapter{toolIDPrefix: ToolIDPrefix}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Option configures the MCP adapter.
type Option func(*Adapter)

// WithToolIDPrefix sets the URI scheme prefix for MCP resource identifiers.
func WithToolIDPrefix(prefix string) Option {
	return func(a *Adapter) { a.toolIDPrefix = prefix }
}

// Protocol implements toolcall.Adapter.
func (a *Adapter) Protocol() toolcall.Protocol { return toolcall.ProtocolMCP }

// mcpRequest is the JSON-RPC request shape for MCP tool calls.
type mcpRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	} `json:"params"`
	ID interface{} `json:"id"`
}

// ExtractFromHTTP detects MCP JSON-RPC tool call requests.
//
// Detection criteria (MatchDefinitive):
//   - Content-Type contains "application/json"
//   - Method is POST
//   - Body is valid JSON-RPC with method "tools/call"
//
// Returns MatchLikely for POST /v1/mcp/tools/{id}/call URL pattern.
// Returns MatchNone for everything else.
func (a *Adapter) ExtractFromHTTP(r *http.Request) (*toolcall.MatchResult, error) {
	// Fast reject: MCP uses POST.
	if r.Method != http.MethodPost {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}

	token := extractBearer(r)

	// Path-based heuristic: /v1/mcp/tools/{id}/call
	if toolID := extractPathToolID(r.URL.Path); toolID != "" {
		req := &toolcall.ToolCallRequest{
			Protocol:  toolcall.ProtocolMCP,
			ToolID:    toolID,
			Operation: "call",
			Token:     token,
			TransportMeta: &toolcall.TransportMeta{
				OriginalHeaders: r.Header.Clone(),
				MCPTransport:    "http",
			},
		}
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			req.RequestBody = body
		}
		// Check for X-MCP-Tool-ID override.
		if id := r.Header.Get("X-MCP-Tool-ID"); id != "" {
			req.ToolID = id
		}
		return &toolcall.MatchResult{Confidence: toolcall.MatchLikely, Request: req}, nil
	}

	// Body-based definitive detection: parse JSON-RPC.
	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}

	if r.Body == nil {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	var rpc mcpRequest
	if err := json.Unmarshal(body, &rpc); err != nil {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}
	if rpc.JSONRPC != "2.0" || rpc.Method != "tools/call" {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}

	req := &toolcall.ToolCallRequest{
		Protocol:    toolcall.ProtocolMCP,
		ToolID:      rpc.Params.Name,
		Operation:   "call",
		Params:      rpc.Params.Arguments,
		Token:       token,
		RequestBody: body,
		TransportMeta: &toolcall.TransportMeta{
			OriginalHeaders: r.Header.Clone(),
			MCPTransport:    "http",
		},
	}
	return &toolcall.MatchResult{Confidence: toolcall.MatchDefinitive, Request: req}, nil
}

// ExtractFromMessage extracts an MCP tool call from a raw message payload
// (e.g., stdio frame or SSE event body).
func (a *Adapter) ExtractFromMessage(msg []byte) (*toolcall.MatchResult, error) {
	var rpc mcpRequest
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}
	if rpc.JSONRPC != "2.0" || rpc.Method != "tools/call" {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}
	req := &toolcall.ToolCallRequest{
		Protocol:    toolcall.ProtocolMCP,
		ToolID:      rpc.Params.Name,
		Operation:   "call",
		Params:      rpc.Params.Arguments,
		RequestBody: msg,
		TransportMeta: &toolcall.TransportMeta{
			MCPTransport: "stdio",
		},
	}
	return &toolcall.MatchResult{Confidence: toolcall.MatchDefinitive, Request: req}, nil
}

// FormatError writes an MCP-spec JSON-RPC error response.
func (a *Adapter) FormatError(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    mcpErrorCode(status),
			"message": description,
			"data":    map[string]string{"error": code},
		},
		"id": nil,
	})
}

func mcpErrorCode(httpStatus int) int {
	switch httpStatus {
	case http.StatusUnauthorized:
		return -32001
	case http.StatusForbidden:
		return -32002
	case http.StatusNotFound:
		return -32601
	default:
		return -32603
	}
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func extractPathToolID(path string) string {
	// Matches /v1/mcp/tools/{toolID}/call
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "tools" && i+1 < len(parts) {
			id := parts[i+1]
			// Confirm next segment is "call" if present.
			if i+2 < len(parts) && parts[i+2] == "call" {
				return id
			}
			if i+2 >= len(parts) {
				return id
			}
		}
	}
	return ""
}
