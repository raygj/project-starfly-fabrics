// Package httpgeneric provides the generic HTTP adapter for the universal tool-call layer.
//
// It secures existing REST/gRPC services exposed to agents without requiring
// them to implement a specific protocol. The token is taken from the Authorization
// header, the tool ID is derived from URL prefix mappings, and the operation
// is derived from the HTTP method and path.
//
// This adapter is the fallback when no more-specific protocol adapter matches.
package httpgeneric

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

// ToolIDMapping maps a URL path prefix to a canonical tool ID.
type ToolIDMapping struct {
	// PathPrefix is the URL prefix to match (e.g., "/api/analytics").
	PathPrefix string
	// ToolID is the canonical tool identifier for this prefix.
	ToolID string
}

// Adapter implements toolcall.Adapter for generic HTTP/REST services.
type Adapter struct {
	mappings []ToolIDMapping
}

// New creates a generic HTTP adapter with the given URL prefix → tool ID mappings.
func New(mappings ...ToolIDMapping) *Adapter {
	return &Adapter{mappings: mappings}
}

// Protocol implements toolcall.Adapter.
func (a *Adapter) Protocol() toolcall.Protocol { return toolcall.ProtocolHTTP }

// ExtractFromHTTP extracts a ToolCallRequest from any HTTP request carrying a Bearer token.
//
// Confidence levels:
//   - MatchDefinitive: Authorization header present AND path matches a configured mapping.
//   - MatchLikely: Authorization header present but no explicit mapping (fallback behavior).
//   - MatchNone: No Authorization header.
func (a *Adapter) ExtractFromHTTP(r *http.Request) (*toolcall.MatchResult, error) {
	token := extractBearer(r)
	if token == "" {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}

	toolID, confidence := a.resolveToolID(r.URL.Path)
	operation := operationFromRequest(r)

	req := &toolcall.ToolCallRequest{
		Protocol:  toolcall.ProtocolHTTP,
		ToolID:    toolID,
		Operation: operation,
		Token:     token,
		TransportMeta: &toolcall.TransportMeta{
			OriginalHeaders: r.Header.Clone(),
		},
	}

	// Detect gRPC-web by content-type.
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/grpc") {
		req.TransportMeta.Custom = map[string]interface{}{"grpc": true}
	}

	return &toolcall.MatchResult{Confidence: confidence, Request: req}, nil
}

// ExtractFromMessage is not applicable for the generic HTTP adapter.
// It always returns MatchNone.
func (a *Adapter) ExtractFromMessage(_ []byte) (*toolcall.MatchResult, error) {
	return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
}

// FormatError writes a standard HTTP error response with a JSON body.
func (a *Adapter) FormatError(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// resolveToolID finds the best matching tool ID for a URL path.
// Returns (toolID, MatchDefinitive) on a prefix match, ("", MatchLikely) on no match.
func (a *Adapter) resolveToolID(path string) (string, toolcall.MatchConfidence) {
	// Longest prefix wins.
	best := ""
	bestLen := 0
	for _, m := range a.mappings {
		if strings.HasPrefix(path, m.PathPrefix) && len(m.PathPrefix) > bestLen {
			best = m.ToolID
			bestLen = len(m.PathPrefix)
		}
	}
	if best != "" {
		return best, toolcall.MatchDefinitive
	}
	return "", toolcall.MatchLikely
}

// operationFromRequest derives a canonical operation string from the HTTP method and path.
// Examples: "GET /api/orders" → "get", "POST /api/orders/ship" → "post:ship"
func operationFromRequest(r *http.Request) string {
	method := strings.ToLower(r.Method)
	// Extract the last meaningful path segment as an operation hint.
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		return method
	}
	last := parts[len(parts)-1]
	if last == "" || last == "call" || last == "invoke" {
		return method
	}
	return method + ":" + last
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
