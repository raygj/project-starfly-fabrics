// Package toolcall provides the protocol-agnostic abstraction layer for tool call
// identity enforcement across MCP, A2A, generic HTTP, and future protocols.
//
// Every incoming tool call — regardless of protocol — is represented as a
// ToolCallRequest, verified by the universal Verifier, and produces a
// VerifiedIdentity. Protocol-specific details live in Adapter implementations
// under adapters/. The universal middleware (middleware.go) wires it together.
//
// See ADR-0022 for the architecture decision record.
package toolcall

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// Protocol identifies the tool-calling protocol and optional version.
// Format: "name" or "name/version" (e.g., "mcp", "mcp/v2", "a2a/2026-draft-01").
type Protocol string

const (
	ProtocolMCP  Protocol = "mcp"
	ProtocolHTTP Protocol = "http"
	ProtocolA2A  Protocol = "a2a"
)

// ParseProtocol splits a Protocol value into name and version components.
//
//	"mcp"              → ("mcp", "")
//	"a2a/2026-draft-01" → ("a2a", "2026-draft-01")
func ParseProtocol(p Protocol) (name, version string) {
	s := string(p)
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}

// FormatProtocol constructs a Protocol from name and version.
// An empty version returns just the name.
func FormatProtocol(name, version string) Protocol {
	if version == "" {
		return Protocol(name)
	}
	return Protocol(name + "/" + version)
}

// MatchConfidence indicates how confident an Adapter is that a request
// belongs to its protocol. Higher beats lower in dispatch.
type MatchConfidence int

const (
	MatchNone       MatchConfidence = 0   // request is definitely not this protocol
	MatchPossible   MatchConfidence = 50  // might be this protocol
	MatchLikely     MatchConfidence = 75  // probably this protocol
	MatchDefinitive MatchConfidence = 100 // unambiguously this protocol
)

// TransportMeta carries protocol-specific transport metadata extracted by an Adapter.
type TransportMeta struct {
	// OriginalHeaders are the raw HTTP request headers.
	OriginalHeaders http.Header
	// A2AAgentCard is the parsed Agent Card for A2A requests.
	A2AAgentCard map[string]interface{}
	// MCPTransport is the MCP transport mode ("http", "sse", "stdio").
	MCPTransport string
	// Custom holds additional protocol-specific metadata.
	Custom map[string]interface{}
}

// ToolCallRequest is a protocol-agnostic representation of a tool invocation.
// It is produced by an Adapter and consumed by the Verifier.
type ToolCallRequest struct {
	// Protocol identifies the originating tool-calling protocol.
	Protocol Protocol `json:"protocol"`
	// ProtocolVersion is the specific version (may be empty).
	ProtocolVersion string `json:"protocol_version,omitempty"`
	// ToolID is the canonical identifier for the tool being called.
	ToolID string `json:"tool_id"`
	// Operation is the specific action (exec_act, HTTP method, A2A task type).
	Operation string `json:"operation,omitempty"`
	// Params are the tool call parameters extracted from the request body.
	Params map[string]interface{} `json:"params,omitempty"`
	// Token is the raw bearer token string.
	Token string `json:"-"`
	// TransportMeta carries protocol-specific metadata.
	TransportMeta *TransportMeta `json:"-"`
	// CallerIdentity is an optional pre-resolved identity hint.
	CallerIdentity string `json:"caller_identity,omitempty"`
	// RequestBody is the raw request body for inp_hash verification.
	RequestBody []byte `json:"-"`
}

// Delegation holds on-behalf-of delegation chain information from a token.
type Delegation struct {
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	Depth      int    `json:"depth"`
}

// VerifiedIdentity is the output of a successful Verifier.Verify call.
// It contains all claims validated and enriched by the verification pipeline.
type VerifiedIdentity struct {
	// Subject is the verified workload identifier (WIMSE/SPIFFE URI).
	Subject string `json:"sub"`
	// Issuer is the token issuer.
	Issuer string `json:"iss"`
	// Capabilities are the attested capabilities granted by the token.
	Capabilities []string `json:"caps,omitempty"`
	// BlastRadius is the impact scope from the token.
	BlastRadius string `json:"blast_radius,omitempty"`
	// Delegation holds on-behalf-of chain information, if present.
	Delegation *Delegation `json:"delegation,omitempty"`
	// Execution is the execution scope binding, if present.
	Execution *core.ExecutionScope `json:"execution,omitempty"`
	// Protocol is the tool-calling protocol this identity was verified through.
	Protocol Protocol `json:"protocol"`
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"exp"`
	// ToolID is the tool this identity was verified for.
	ToolID string `json:"tool_id,omitempty"`
	// Resource is the RFC 8707 resource indicator matched against the token audience.
	Resource string `json:"resource,omitempty"`
}

// MatchResult is returned by an Adapter's Extract methods.
type MatchResult struct {
	// Confidence is how certain the adapter is that this request is its protocol.
	Confidence MatchConfidence
	// Request is the extracted tool call request (nil when Confidence == MatchNone).
	Request *ToolCallRequest
}

// Verifier validates a ToolCallRequest through the full WIMSE verification pipeline
// and returns a VerifiedIdentity. It is the single enforcement engine used by all adapters.
type Verifier interface {
	Verify(ctx context.Context, req *ToolCallRequest) (*VerifiedIdentity, error)
}

// Adapter detects and extracts tool-call requests from HTTP requests or raw messages.
// Each protocol (MCP, A2A, HTTP) provides its own Adapter implementation.
type Adapter interface {
	// Protocol returns the protocol this adapter handles.
	Protocol() Protocol

	// ExtractFromHTTP detects whether an HTTP request belongs to this adapter's protocol
	// and, if so, extracts a ToolCallRequest. Returns MatchNone if not matched.
	ExtractFromHTTP(r *http.Request) (*MatchResult, error)

	// ExtractFromMessage extracts a ToolCallRequest from a raw message payload
	// (e.g., stdio frame, SSE event body).
	ExtractFromMessage(msg []byte) (*MatchResult, error)

	// FormatError writes a protocol-appropriate error response.
	FormatError(w http.ResponseWriter, code, description string, status int)
}
