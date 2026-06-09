// Package plugin provides a gRPC plugin framework for out-of-process
// AgentIdentityProvider implementations. Third-party agent platforms
// implement the AgentIdentityPlugin gRPC service; Starfly connects
// to them via PluginClient, which satisfies core.AgentIdentityProvider.
//
// These types mirror the proto messages and will be replaced by
// generated code once protoc is available (see gen.sh).
package plugin

// IssueAgentIdentityRequest is the gRPC request for identity issuance.
type IssueAgentIdentityRequest struct {
	AgentName       string            `json:"agent_name"`
	Platform        string            `json:"platform"`
	Capabilities    []string          `json:"capabilities"`
	OnBehalfOf      string            `json:"on_behalf_of,omitempty"`
	MaxBlastRadius  string            `json:"max_blast_radius,omitempty"`
	DelegationDepth int32             `json:"delegation_depth,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// IssueAgentIdentityResponse is the gRPC response for identity issuance.
type IssueAgentIdentityResponse struct {
	WorkloadID    string `json:"workload_id"`
	SpiffeID      string `json:"spiffe_id,omitempty"`
	Token         string `json:"token"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

// RevokeIdentityRequest is the gRPC request for identity revocation.
type RevokeIdentityRequest struct {
	IdentityID string `json:"identity_id"`
}

// RevokeIdentityResponse is the gRPC response for identity revocation.
type RevokeIdentityResponse struct{}
