// Package a2a provides a skeleton A2A adapter for the universal tool-call layer.
//
// # Stability Warning
//
// A2A is an evolving protocol. This adapter targets the 2025-draft-01 spec revision.
// The Google A2A spec may ship breaking changes before standardization. If that
// happens we version the adapter (a2a/v1 vs a2a/v2) rather than silently tracking
// HEAD. Do NOT commit to A2A adapter stability in customer contracts.
//
// # What is implemented
//
//   - Agent Card parsing (JSON object with capabilities, endpoint, auth fields)
//   - Task-creation request detection via JSON-RPC method "a2a/tasks/send"
//   - Agent Card hash computation (SHA-256) stored in TransportMeta for audit
//   - MatchLikely confidence on A2A method, MatchNone for everything else
//   - FormatError: A2A task-failure JSON object
//
// # What is NOT implemented yet
//
//   - OIDC token extraction from A2A Bearer credentials (requires spec clarity)
//   - Streaming task endpoints (/stream-updates)
//   - Agent Card signature verification (spec does not yet mandate this)
//
// SpecRevision declares which A2A spec draft this adapter implements.
// Bump this constant when the spec changes and adapter behavior changes.
package a2a

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

// SpecRevision is the A2A spec draft this adapter targets.
const SpecRevision = "2025-draft-01"

// Adapter implements toolcall.Adapter for the A2A (Agent-to-Agent) protocol.
//
// This is an EXPERIMENTAL adapter. The A2A protocol is not yet stable.
type Adapter struct {
	specRevision string
}

// New creates an A2A adapter. The adapter logs its spec revision on creation.
func New(opts ...Option) *Adapter {
	a := &Adapter{specRevision: SpecRevision}
	for _, o := range opts {
		o(a)
	}
	slog.Info("a2a adapter initialized (experimental)", "spec_revision", a.specRevision)
	return a
}

// Option configures the A2A adapter.
type Option func(*Adapter)

// WithSpecRevision overrides the spec revision string for testing.
func WithSpecRevision(rev string) Option {
	return func(a *Adapter) { a.specRevision = rev }
}

// Protocol implements toolcall.Adapter.
func (a *Adapter) Protocol() toolcall.Protocol {
	return toolcall.Protocol("a2a/" + a.specRevision)
}

// a2aRequest is the JSON-RPC shape for A2A task-creation requests.
type a2aRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

// a2aTaskParams captures task-creation params we use for routing.
type a2aTaskParams struct {
	AgentCard json.RawMessage        `json:"agentCard"`
	TaskType  string                 `json:"taskType"`
	Input     map[string]interface{} `json:"input"`
}

// ExtractFromHTTP detects A2A task-creation requests.
//
// Confidence levels:
//   - MatchLikely:    POST with application/json body and method "a2a/tasks/send"
//   - MatchPossible:  POST with Content-Type "application/json" and X-A2A-Version header
//   - MatchNone:      everything else
//
// A2A does not use Bearer tokens in the conventional sense — the spec describes
// OIDC-based auth via the Agent Card's authentication field. This adapter extracts
// the Authorization header if present (for forward compatibility) and otherwise
// leaves Token empty.
func (a *Adapter) ExtractFromHTTP(r *http.Request) (*toolcall.MatchResult, error) {
	if r.Method != http.MethodPost {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}

	// Heuristic: X-A2A-Version header signals A2A without reading the body.
	if r.Header.Get("X-A2A-Version") != "" && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return &toolcall.MatchResult{
			Confidence: toolcall.MatchPossible,
			Request: &toolcall.ToolCallRequest{
				Protocol: a.Protocol(),
				Token:    extractBearer(r),
				TransportMeta: &toolcall.TransportMeta{
					OriginalHeaders: r.Header.Clone(),
					Custom:          map[string]interface{}{"a2a_version": r.Header.Get("X-A2A-Version")},
				},
			},
		}, nil
	}

	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
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

	var rpc a2aRequest
	if err := json.Unmarshal(body, &rpc); err != nil {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}
	if rpc.JSONRPC != "2.0" || !strings.HasPrefix(rpc.Method, "a2a/") {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}

	// Parse task params.
	var params a2aTaskParams
	_ = json.Unmarshal(rpc.Params, &params)

	cardHash, cardRaw := parseAgentCard(params.AgentCard)
	taskType := params.TaskType
	if taskType == "" {
		taskType = rpc.Method
	}

	req := &toolcall.ToolCallRequest{
		Protocol:    a.Protocol(),
		Operation:   taskType,
		Token:       extractBearer(r),
		RequestBody: body,
		TransportMeta: &toolcall.TransportMeta{
			OriginalHeaders: r.Header.Clone(),
			A2AAgentCard:    cardRaw,
			Custom: map[string]interface{}{
				"a2a_card_hash":    cardHash,
				"spec_revision":    a.specRevision,
				"a2a_jsonrpc_id":   rpc.ID,
				"a2a_method":       rpc.Method,
			},
		},
	}
	return &toolcall.MatchResult{Confidence: toolcall.MatchLikely, Request: req}, nil
}

// ExtractFromMessage extracts an A2A task from a raw message (e.g., SSE body).
func (a *Adapter) ExtractFromMessage(msg []byte) (*toolcall.MatchResult, error) {
	var rpc a2aRequest
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}
	if rpc.JSONRPC != "2.0" || !strings.HasPrefix(rpc.Method, "a2a/") {
		return &toolcall.MatchResult{Confidence: toolcall.MatchNone}, nil
	}

	var params a2aTaskParams
	_ = json.Unmarshal(rpc.Params, &params)
	cardHash, cardRaw := parseAgentCard(params.AgentCard)

	return &toolcall.MatchResult{
		Confidence: toolcall.MatchLikely,
		Request: &toolcall.ToolCallRequest{
			Protocol:    a.Protocol(),
			Operation:   params.TaskType,
			RequestBody: msg,
			TransportMeta: &toolcall.TransportMeta{
				A2AAgentCard: cardRaw,
				Custom: map[string]interface{}{
					"a2a_card_hash": cardHash,
					"spec_revision": a.specRevision,
				},
			},
		},
	}, nil
}

// FormatError writes an A2A task-failure response.
// A2A uses a JSON object with "error" and "status" fields.
func (a *Adapter) FormatError(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    a2aErrorCode(status),
			"message": description,
			"data": map[string]string{
				"error":          code,
				"spec_revision":  a.specRevision,
			},
		},
		"id": nil,
	})
}

// parseAgentCard deserializes and hashes the Agent Card payload.
// Returns (sha256-hex, raw-map). Both are empty/nil on malformed input.
func parseAgentCard(raw json.RawMessage) (hash string, parsed map[string]interface{}) {
	if len(raw) == 0 {
		return "", nil
	}
	sum := sha256.Sum256(raw)
	hash = hex.EncodeToString(sum[:])

	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return hash, nil
	}
	return hash, m
}

func a2aErrorCode(httpStatus int) int {
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
