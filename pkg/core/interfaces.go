// Package core defines the foundational interfaces and types for Starfly Fabrics.
//
// All cross-package communication flows through interfaces defined here.
// Implementations live in their respective packages (exchange, signals, identity, etc.).
// This prevents circular dependencies and enables testing with mocks.
package core

import (
	"context"
	"crypto"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// TOKEN EXCHANGE
// The heart of Starfly: accept a source credential, validate it,
// evaluate policy, and issue a WIMSE-compliant JWT for the target.
// ─────────────────────────────────────────────────────────────────────

// TokenExchanger handles RFC 8693 token exchange operations.
// This is the core identity routing capability.
type TokenExchanger interface {
	// Exchange performs a token exchange per RFC 8693 + WIMSE profiles.
	// The source token can be any supported format (K8s SA, AWS STS,
	// GCP WIF, SPIFFE SVID, AD Kerberos, etc.).
	// Returns a scoped WIMSE JWT for the requested audience/trust domain.
	Exchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error)
}

// TokenExchangeRequest represents an RFC 8693 token exchange request.
type TokenExchangeRequest struct {
	// GrantType must be "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantType string `json:"grant_type"`

	// SubjectToken is the source credential being exchanged.
	SubjectToken string `json:"subject_token"`

	// SubjectTokenType identifies the format of the subject token.
	// e.g., "urn:ietf:params:oauth:token-type:jwt",
	//       "urn:ietf:params:oauth:token-type:saml2",
	//       "urn:starfly:token-type:spiffe-svid"
	SubjectTokenType string `json:"subject_token_type"`

	// Audience is the target trust domain or service.
	// e.g., "spiffe://target.example.com" or "https://api.target.com"
	Audience string `json:"audience"`

	// Scope defines the requested permissions in the target domain.
	Scope string `json:"scope,omitempty"`

	// ActorToken is used for delegation (on-behalf-of) flows.
	// The actor is the entity requesting to act on behalf of the subject.
	ActorToken     string `json:"actor_token,omitempty"`
	ActorTokenType string `json:"actor_token_type,omitempty"`

	// RequestedTokenType specifies the desired output format.
	// Default: "urn:ietf:params:oauth:token-type:jwt" (WIMSE JWT)
	RequestedTokenType string `json:"requested_token_type,omitempty"`

	// DPoPProof is an optional DPoP proof JWT (RFC 9449).
	// When present, the exchange engine validates proof-of-possession
	// and binds the issued token via a cnf.jkt claim.
	DPoPProof string `json:"-"` // Not part of the JSON body — comes from DPoP HTTP header.

	// Attestation is the parsed X-Starfly-Attestation header from the agent.
	// When present, the exchange engine evaluates attestation claims and
	// includes assurance_level + attestation metadata in the minted JWT.
	// See ADR-0013 for the attestation architecture.
	Attestation *ServerAttestation `json:"-"` // Not part of the JSON body — comes from HTTP header.

	// ExecutionScope binds the issued token to a specific action.
	// When present, the token is execution-scoped: 30s TTL, bound to
	// THIS method + THIS target + THIS payload hash. Non-replayable.
	// This closes Gap #3 from the inflection point: authorization at execution time.
	ExecutionScope *ExecutionScope `json:"execution_scope,omitempty"`
}

// ExecutionScope binds a token to a specific action at a specific moment.
// An execution-scoped token proves not just WHO you are and that you HOLD the key,
// but that THIS action is authorized RIGHT NOW.
//
// Claim names align with draft-nennemann-wimse-ect-00 (Execution Context Tokens).
type ExecutionScope struct {
	// Method is the HTTP method being authorized (e.g., "POST", "GET").
	// Maps to the htm claim per RFC 9449.
	Method string `json:"htm"`

	// URI is the target resource being accessed (e.g., "https://api.example.com/transfer").
	// Maps to the htu claim per RFC 9449.
	URI string `json:"htu"`

	// ExecAct is the operation being performed (e.g., "query", "read", "delete").
	// Maps to the exec_act claim per draft-nennemann-wimse-ect-00.
	// Renamed from "action" to avoid collision with OAuth "act" (Actor) claim (RFC 8693).
	ExecAct string `json:"exec_act,omitempty"`

	// InputHash is the SHA-256 hash of the request body (base64url-encoded, no padding).
	// Binds the token to THIS specific payload — prevents request body tampering.
	// Maps to the inp_hash claim per draft-nennemann-wimse-ect-00.
	InputHash string `json:"inp_hash,omitempty"`

	// OutputHash is the SHA-256 hash of the response body (base64url-encoded, no padding).
	// Populated post-execution by MCP middleware callback for accountability recording.
	// Maps to the out_hash claim per draft-nennemann-wimse-ect-00.
	OutputHash string `json:"out_hash,omitempty"`

	// Target is the downstream resource URI (e.g., "postgresql://analytics.prod:5432/metrics").
	// Binds the token to a specific backend resource, preventing resource substitution.
	Target string `json:"target,omitempty"`

	// WorkflowID is an optional workflow identifier (UUID format).
	// Links execution-scoped tokens across a multi-step workflow.
	// Maps to the wid claim per draft-nennemann-wimse-ect-00.
	WorkflowID string `json:"wid,omitempty"`

	// PayloadHash is deprecated — use InputHash instead.
	// Kept for backward compatibility during migration.
	PayloadHash string `json:"payload_hash,omitempty"`

	// Nonce is a unique value for replay protection.
	// Each nonce can only be used once within the token's lifetime.
	Nonce string `json:"nonce"`
}

// ServerAttestation is the server-side representation of the X-Starfly-Attestation
// header sent by starfly-agent. It contains attestation metadata about the
// workload's environment — the platform credential itself is in subject_token.
// See ADR-0013 for the attestation architecture.
type ServerAttestation struct {
	// Platform describes the source credential used for this exchange.
	Platform ServerAttestPlatform `json:"platform"`

	// Hardware contains hardware-rooted attestation proofs (TPM, GPU, enclave).
	Hardware []*ServerAttestHardware `json:"hardware,omitempty"`

	// Workload contains metadata about the running process.
	Workload *ServerAttestWorkload `json:"workload,omitempty"`

	// AgentVersion is the starfly-agent binary version.
	AgentVersion string `json:"agent_version"`

	// Timestamp is when the attestation was assembled.
	Timestamp time.Time `json:"timestamp"`
}

// ServerAttestPlatform identifies the platform credential source.
type ServerAttestPlatform struct {
	Source   string            `json:"source"`
	CredType string           `json:"cred_type"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ServerAttestHardware is a hardware attestation proof.
type ServerAttestHardware struct {
	Type         string            `json:"type"`
	Quote        []byte            `json:"quote"`
	PCRs         map[int][]byte    `json:"pcrs,omitempty"`
	Firmware     string            `json:"firmware,omitempty"`
	Nonce        []byte            `json:"nonce"`
	Measurements map[string]string `json:"measurements,omitempty"`
}

// ServerAttestWorkload describes the workload process.
type ServerAttestWorkload struct {
	PID         int               `json:"pid"`
	BinaryHash  string            `json:"binary_hash,omitempty"`
	ImageDigest string            `json:"image_digest,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	PodName     string            `json:"pod_name,omitempty"`
	NodeName    string            `json:"node_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// AssuranceLevel computes the trust level from the attestation bundle.
// Returns "hardware" if hardware proofs are present, "software" if only
// platform credentials, or "none" if the attestation is nil.
func (a *ServerAttestation) AssuranceLevel() string {
	if a == nil {
		return "none"
	}
	if len(a.Hardware) > 0 {
		return "hardware"
	}
	return "software"
}

// TokenExchangeResponse contains the exchanged token.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`

	// WIMSEClaims contains the WIMSE-specific claims in the issued token.
	WIMSEClaims *WIMSEClaims `json:"-"`

	// DelegationDepth carries the delegation chain depth from the engine to
	// the API handler for metric recording. Not included in the HTTP response.
	DelegationDepth int `json:"-"`
}

// WIMSEClaims represents WIMSE Workload Identity Token claims.
type WIMSEClaims struct {
	// WorkloadID is a WIMSE-compliant URI identifying the workload.
	// Format: "spiffe://<trust_domain>/<path>" or "wimse://<trust_domain>/<path>"
	WorkloadID string `json:"sub"`

	// Issuer is the Starfly unit that issued this token.
	Issuer string `json:"iss"`

	// Audience is the intended recipient.
	Audience string `json:"aud"`

	// IssuedAt and Expiration define the token's validity window.
	IssuedAt   time.Time `json:"iat"`
	Expiration time.Time `json:"exp"`

	// CNF (Confirmation) contains key binding information.
	// Used for proof-of-possession tokens per WIMSE s2s protocol.
	Confirmation map[string]interface{} `json:"cnf,omitempty"`

	// TrustDomain is the issuing trust domain.
	TrustDomain string `json:"td,omitempty"`

	// Capabilities are the attested capabilities of the workload.
	Capabilities []string `json:"caps,omitempty"`

	// OnBehalfOf identifies the principal this token is acting for.
	OnBehalfOf string `json:"obo,omitempty"`

	// BlastRadius defines the maximum impact scope.
	BlastRadius string `json:"blast_radius,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────
// SHARED SIGNALS
// SSF/CAEP: receive security events, evaluate policy, propagate.
// Interfaces are split by responsibility following io.Reader/Writer:
//   - SignalTransmitter: outbound stream management + event delivery
//   - SignalReceiver: inbound event validation + routing
//   - SignalDiscovery: SSF configuration document
//   - SignalEngine: composed interface for full Starfly units
// ─────────────────────────────────────────────────────────────────────

// SignalTransmitter manages outbound SSF streams and event delivery.
// At scale, a transmitter may serve thousands of streams across hundreds
// of trust domains. Implementations MUST index streams by event type
// for O(1) matching — linear scans are not acceptable at scale.
type SignalTransmitter interface {
	// CreateStream creates a new SSF stream for a receiver.
	// Returns the stream with events_supported populated.
	// The actual events delivered are the intersection of
	// events_requested and events_supported.
	CreateStream(ctx context.Context, cfg *StreamConfig) (*Stream, error)

	// DeleteStream removes a stream and stops event delivery.
	DeleteStream(ctx context.Context, streamID string) error

	// TransmitEvent signs the event as a SET (RFC 8417) and delivers
	// to all streams where:
	//   1. The stream's events_requested includes this event type
	//   2. The stream status is "enabled"
	//
	// Delivery method is per-stream:
	//   - Internal streams: NATS publish (per ADR-0001)
	//   - External streams: HTTP push to stream endpoint
	//
	// Failed deliveries are retried with exponential backoff.
	// Permanently failed streams are marked "paused" after max retries.
	// Every transmission produces an audit event.
	TransmitEvent(ctx context.Context, event *SecurityEvent) error

	// GetStreamStatus returns the current status of a stream.
	GetStreamStatus(ctx context.Context, streamID string) (*StreamStatus, error)
}

// SignalReceiver processes inbound security events.
// A compliance aggregator or SIEM connector only needs this interface —
// it never transmits, so it should not be forced to implement transmitter methods.
type SignalReceiver interface {
	// ReceiveEvent validates an incoming SET (RFC 8417), evaluates
	// OPA policy, and routes based on event type:
	//
	// Routing table:
	//   credential-change         → RevocationIndex.Revoke() if change_type is "revoke"
	//   session-revoked           → RevocationIndex.Revoke()
	//   device-compliance-change  → evaluate compliance policy, conditionally revoke
	//   account-disabled          → RevocationIndex.Revoke() for all subject tokens
	//   token-claims-change       → revoke tokens exceeding new capability ceiling
	//   agent-credential-revoked  → RevocationIndex.Revoke() + cascade delegation chain
	//   agent-delegation-revoked  → revoke from the severed link downward
	//   agent-capability-reduced  → revoke tokens exceeding new capability ceiling
	//   agent-blast-radius-reduced → revoke tokens exceeding new blast radius
	//   agent-attestation-failed  → revoke all tokens for subject, quarantine
	//
	// Events for subjects not in this unit's trust domain are
	// forwarded via NATS to units that serve that domain.
	// Events that fail OPA policy evaluation are logged and dropped.
	// Every received event produces an audit event regardless of outcome.
	ReceiveEvent(ctx context.Context, event *SecurityEvent) error
}

// SignalDiscovery serves the SSF configuration document.
type SignalDiscovery interface {
	// Configuration returns the SSF discovery document for this unit.
	// Built from static config at startup — no runtime failure mode.
	Configuration() *SSFConfiguration
}

// SignalEngine is the composed interface for Starfly units that both
// transmit and receive security events. Most Starfly units implement this.
// Receive-only consumers (compliance aggregators, SIEM connectors)
// implement SignalReceiver alone. Transmit-only sources (notification
// gateways) implement SignalTransmitter alone.
type SignalEngine interface {
	SignalTransmitter
	SignalReceiver
	SignalDiscovery
}

// RevocationIndex tracks revoked tokens and identities.
// The exchange engine calls IsRevoked on EVERY token exchange —
// treat it accordingly.
//
// Performance contract:
//   - IsRevoked MUST be O(1) or O(log n) — this is hot path (<15ms p99 budget)
//   - Revoke MUST be safe for concurrent calls (cascade bursts of 500+ writes)
//   - Entries MUST auto-expire based on expiresAt (not dependent on Cleanup)
//   - Cleanup is advisory — removes already-expired entries to free memory
//   - All methods MUST be safe for concurrent use by multiple goroutines
type RevocationIndex interface {
	// Revoke marks a subject as revoked.
	Revoke(ctx context.Context, subjectID string, reason string, expiresAt time.Time) error

	// IsRevoked checks whether a subject is currently revoked.
	// Returns the RevocationEntry if revoked, nil if not revoked.
	// Returning the entry (not bool) enables audit trails that explain
	// WHY an exchange was denied — "session-revoked" vs "delegation-chain-revoked"
	// vs "blast-radius-exceeded".
	IsRevoked(ctx context.Context, subjectID string) (*RevocationEntry, error)

	// Cleanup removes expired revocation entries to free memory.
	// Advisory — callers should run periodically but correctness does not
	// depend on it (IsRevoked checks expiry inline).
	Cleanup(ctx context.Context) (int, error)

	// Hash returns a SHA-256 hash of the current index state.
	// Entries are sorted by SubjectID for deterministic output.
	// Used by federation sync to detect divergence without transferring
	// the full index — units compare hashes first and only sync on mismatch.
	Hash() string

	// Export serializes the revocation index to a JSON byte slice.
	// The output includes all entries and a SHA-256 integrity hash.
	// Entries are sorted by SubjectID for hash stability.
	Export() ([]byte, error)

	// Import deserializes a revocation snapshot and merges entries into the index.
	// Import is additive — it does not remove existing entries. This ensures
	// entries that arrived via NATS since the last snapshot are preserved.
	// The integrity hash is verified before loading.
	Import(data []byte) error
}

// RevocationSnapshot is the serialization format for revocation index export/import.
// Used by Export() and Import() on RevocationIndex implementations.
type RevocationSnapshot struct {
	Entries []*RevocationEntry `json:"entries"`
	Count   int                `json:"count"`
	Hash    string             `json:"hash"`
}

// RevocationEntry contains details about a revoked subject.
// Returned by IsRevoked when the subject IS revoked. Nil when not revoked.
type RevocationEntry struct {
	SubjectID string    `json:"subject_id"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	EventJTI  string    `json:"event_jti,omitempty"` // links back to the triggering SecurityEvent
}

// SecurityEvent represents an SSF Security Event Token (SET).
// This is the universal signal format per OpenID SSF 1.0.
type SecurityEvent struct {
	// Standard JWT claims
	Issuer   string `json:"iss"`
	JTI      string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Audience string `json:"aud"`

	// Subject identifier per SSF 1.0
	SubjectID *SubjectIdentifier `json:"sub_id"`

	// Events map: event URI → event-specific claims
	// CAEP: https://schemas.openid.net/secevent/caep/event-type/*
	// RISC: https://schemas.openid.net/secevent/risc/event-type/*
	Events map[string]map[string]interface{} `json:"events"`

	// Transaction ID for correlation
	TransactionID string `json:"txn,omitempty"`
}

// SubjectIdentifier identifies the subject of a security event.
type SubjectIdentifier struct {
	Format string `json:"format"`

	// Format-specific fields
	SpiffeID string `json:"spiffe_id,omitempty"` // For NHI subjects
	Email    string `json:"email,omitempty"`      // For human subjects
	URI      string `json:"uri,omitempty"`         // For WIMSE workload IDs
}

// StreamConfig defines an SSF stream configuration.
type StreamConfig struct {
	Issuer          string   `json:"iss"`
	Audience        string   `json:"aud"`
	EventsRequested []string `json:"events_requested"`
	EventsDelivered []string `json:"events_delivered,omitempty"` // actual events being delivered (subset of requested)
	DeliveryMethod  string   `json:"delivery_method"`            // "push" or "poll"
	EndpointURL     string   `json:"endpoint_url,omitempty"`
}

// Stream represents an active SSF stream.
type Stream struct {
	ID              string   `json:"stream_id"`
	Issuer          string   `json:"iss"`
	Audience        string   `json:"aud"`
	EventsSupported []string `json:"events_supported"`
	Status          string   `json:"status"` // "enabled", "paused", "disabled"
}

// StreamStatus reports the health of an SSF stream.
type StreamStatus struct {
	StreamID string `json:"stream_id"`
	Status   string `json:"status"`
	Subject  string `json:"subject,omitempty"`
}

// SSFConfiguration is the discovery document served at /.well-known/ssf-configuration.
type SSFConfiguration struct {
	Issuer                string   `json:"issuer"`
	JWKsURI               string   `json:"jwks_uri"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
	ConfigurationEndpoint string   `json:"configuration_endpoint"`
	StatusEndpoint        string   `json:"status_endpoint"`
	AddSubjectEndpoint    string   `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint string   `json:"remove_subject_endpoint,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────
// IDENTITY
// SPIFFE integration, agent identity, A2A passport, MCP identity.
// ─────────────────────────────────────────────────────────────────────

// IdentityProvider validates workload credentials and resolves identities.
type IdentityProvider interface {
	// ValidateWorkload validates a source credential and returns the
	// resolved workload identity (SPIFFE ID or WIMSE URI).
	ValidateWorkload(ctx context.Context, credential string, credType string) (*WorkloadIdentity, error)
}

// See AgentIdentityProvider below for agent identity issuance and revocation.
// Kept separate per ADR-0005 — agent identity has different semantics from
// workload credential validation.

// WorkloadIdentity represents a validated workload identity.
type WorkloadIdentity struct {
	// ID is the WIMSE-compliant workload identifier URI.
	// Format: "spiffe://<trust_domain>/<path>" or "wimse://<trust_domain>/<path>"
	ID string `json:"id"`

	// TrustDomain is the trust domain this identity belongs to.
	TrustDomain string `json:"trust_domain"`

	// Attestation contains the evidence used to validate this identity.
	Attestation *AttestationEvidence `json:"attestation"`

	// Claims are the validated claims from the source credential.
	Claims map[string]interface{} `json:"claims"`
}

// AttestationEvidence records how a workload's identity was validated.
type AttestationEvidence struct {
	Method    string    `json:"method"`    // "k8s-sa", "aws-iam", "gcp-wif", "spiffe-svid", etc.
	Timestamp time.Time `json:"timestamp"`
	NodeID    string    `json:"node_id,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
}

// Attestation method constants for agent platforms.
const (
	AttestMethodK8sSA   = "k8s-sa"
	AttestMethodMCP     = "mcp-client"
	AttestMethodA2A     = "a2a-passport"
	AttestMethodWatsonx = "watsonx-iam"
	AttestMethodCustom  = "custom-agent"
)

// Attestation method constants for source credential types.
const (
	AttestMethodSPIFFE   = "spiffe-svid"
	AttestMethodOIDC     = "oidc"
	AttestMethodKerberos = "kerberos"
	AttestMethodSAML     = "saml"
)

// AgentIdentityRequest is a request to issue identity to an AI agent.
type AgentIdentityRequest struct {
	AgentName    string            `json:"agent_name"`
	Platform     string            `json:"platform"`      // "mcp", "a2a", "watsonx", "custom"
	Capabilities []string          `json:"capabilities"`
	OnBehalfOf   string            `json:"on_behalf_of,omitempty"`
	MaxBlastRadius string          `json:"max_blast_radius,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`

	// DelegationDepth is the maximum number of delegation hops permitted.
	// Zero means the agent cannot delegate further (terminal agent).
	// Decremented on each on-behalf-of exchange.
	DelegationDepth int `json:"delegation_depth,omitempty"`
}

// AgentIdentity is a verifiable identity issued to an AI agent.
type AgentIdentity struct {
	// WIMSE workload identifier for this agent
	WorkloadID string `json:"workload_id"`

	// SPIFFE ID (if SPIFFE trust domain is configured)
	SpiffeID string `json:"spiffe_id,omitempty"`

	// Signed WIMSE JWT containing agent claims
	Token string `json:"token"`

	// Expiration
	ExpiresAt time.Time `json:"expires_at"`
}

// AgentIdentityProvider issues and revokes verifiable identities for AI agents.
// Separate from IdentityProvider: agent identity issuance has different
// semantics from workload credential validation.
type AgentIdentityProvider interface {
	IssueAgentIdentity(ctx context.Context, req *AgentIdentityRequest) (*AgentIdentity, error)
	RevokeIdentity(ctx context.Context, identityID string) error
}

// ─────────────────────────────────────────────────────────────────────
// JWKS RESOLUTION
// Cache-with-TTL and kid-miss refetch for cross-domain key resolution.
// See ADR-0003 for design rationale.
// ─────────────────────────────────────────────────────────────────────

// JWKSResolver abstracts JWKS fetch, cache, and key resolution.
// Implementations handle caching, TTL refresh, and kid-miss refetch
// so that callers simply ask for a key by issuer and kid.
type JWKSResolver interface {
	// ResolveKey returns the public key for the given issuer and key ID.
	// Cache hit → return immediately.
	// Cache miss or kid miss → fetch JWKS from issuer, update cache, return.
	ResolveKey(ctx context.Context, issuer string, kid string) (crypto.PublicKey, error)

	// Prefetch warms the cache for known trust domains. Non-blocking.
	Prefetch(ctx context.Context, issuers []string) error

	// Stats returns cache hit/miss metrics for observability.
	Stats() JWKSCacheStats
}

// JWKSCacheStats reports cache performance metrics.
type JWKSCacheStats struct {
	Hits       uint64 `json:"hits"`
	Misses     uint64 `json:"misses"`
	Fetches    uint64 `json:"fetches"`
	Errors     uint64 `json:"errors"`
	CachedKeys int    `json:"cached_keys"`
	Issuers    int    `json:"issuers"`
}

// ─────────────────────────────────────────────────────────────────────
// POLICY
// OPA-based policy evaluation for all decisions.
// ─────────────────────────────────────────────────────────────────────

// PolicyEngine evaluates authorization decisions.
type PolicyEngine interface {
	// Evaluate runs a policy query and returns the decision.
	Evaluate(ctx context.Context, input *PolicyInput) (*PolicyDecision, error)

	// LoadBundle loads or updates the OPA policy bundle.
	LoadBundle(ctx context.Context, bundlePath string) error
}

// PolicyInput contains all context needed for a policy decision.
type PolicyInput struct {
	// Action being evaluated: "exchange", "signal", "identity", "admin"
	Action string `json:"action"`

	// Subject performing the action
	Subject *WorkloadIdentity `json:"subject"`

	// Target of the action
	Target string `json:"target"`

	// Additional context (trust domain, scopes, etc.)
	Context map[string]interface{} `json:"context"`
}

// PolicyDecision is the result of a policy evaluation.
type PolicyDecision struct {
	Allowed bool                   `json:"allowed"`
	Reason  string                 `json:"reason,omitempty"`
	Claims  map[string]interface{} `json:"claims,omitempty"` // Claims to add to issued token
}

// ─────────────────────────────────────────────────────────────────────
// SYNC (Firefly Protocol)
// NATS-based signal flashing between units.
// ─────────────────────────────────────────────────────────────────────

// SyncBus handles inter-unit signal flashing.
type SyncBus interface {
	// Flash sends a signal to all other units in the fabric.
	Flash(ctx context.Context, signal *Signal) error

	// Subscribe registers a handler for incoming signals.
	Subscribe(ctx context.Context, signalType string, handler SignalHandler) error

	// Replay retrieves missed signals from JetStream.
	Replay(ctx context.Context, since time.Time) ([]*Signal, error)
}

// Signal is a flash message between Starfly units.
type Signal struct {
	Type      string                 `json:"type"`       // "identity_event", "caep_signal", "policy_update", "heartbeat"
	Source    string                 `json:"source"`     // Unit ID that originated this signal
	Timestamp time.Time             `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload"`
}

// SignalHandler processes incoming signals from other units.
type SignalHandler func(ctx context.Context, signal *Signal) error

// ─────────────────────────────────────────────────────────────────────
// LOCK
// Envelope encryption for data at rest. The lock wraps the storage
// encryption key — all persisted state passes through Lock before
// write and Unlock after read.
// ─────────────────────────────────────────────────────────────────────

// Locker provides envelope encryption for data at rest.
type Locker interface {
	Lock(data []byte) ([]byte, error)
	Unlock(data []byte) ([]byte, error)
}

// ─────────────────────────────────────────────────────────────────────
// STORE
// Versioned key-value store for local state.
// ─────────────────────────────────────────────────────────────────────

// Store provides versioned key-value storage.
type Store interface {
	Get(ctx context.Context, key string) (*StoreEntry, error)
	Put(ctx context.Context, key string, value []byte) (*StoreEntry, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// StoreEntry is a versioned key-value entry.
type StoreEntry struct {
	Key       string    `json:"key"`
	Value     []byte    `json:"value"`
	Version   uint64    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ─────────────────────────────────────────────────────────────────────
// AUDIT
// Structured audit logging for every decision.
// ─────────────────────────────────────────────────────────────────────

// Auditor records audit events.
type Auditor interface {
	// Log records an audit event.
	Log(ctx context.Context, event *AuditEvent) error
}

// AuditEvent represents an auditable action.
type AuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"`      // "exchange", "signal", "identity", "policy", "admin"
	Action    string                 `json:"action"`    // "token_issued", "event_received", "identity_created", etc.
	Subject   string                 `json:"subject"`   // Who performed the action
	Target    string                 `json:"target"`    // What was acted upon
	Decision  string                 `json:"decision"`  // "allowed", "denied"
	Reason    string                 `json:"reason,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	UnitID    string                 `json:"unit_id"`   // Which Starfly unit processed this
}
