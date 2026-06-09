package federation

import (
	"context"
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// SIGNAL GATEWAY — Cross-Cluster Revocation Propagation (Phase 13)
//
// The SignalGateway relays revocation events between federated fabrics.
// JWKS federation (types.go) handles key distribution; the signal gateway
// handles revocation propagation. Together they give each fabric the
// ability to validate AND revoke tokens issued by peers.
//
// Design principle: "Revocations propagate faster than keys rotate."
// JWKS refresh runs on 60s cadence. Revocation relay targets <2s p99.
// ─────────────────────────────────────────────────────────────────────

// SignalGateway manages cross-cluster revocation signal propagation.
// Implementations relay revocation events to peer fabrics and process
// inbound revocations from peers, keeping each cluster's RevocationIndex
// consistent with the federation.
type SignalGateway interface {
	// RelayRevocation pushes a revocation signal to all connected peers.
	// The implementation fans out to each peer concurrently. Delivery is
	// fire-and-forget: errors are logged and tracked in PeerSignalState
	// but not returned to the caller. The method always returns nil.
	RelayRevocation(ctx context.Context, signal RevocationSignal) error

	// ReceiveRevocation handles an inbound revocation signal from a peer.
	// The implementation validates the signal, checks for duplicates
	// (via EventJTI), and applies the revocation to the local index.
	ReceiveRevocation(ctx context.Context, signal RevocationSignal) error

	// SyncState performs hash-based reconciliation with a specific peer.
	// Compares revocation index hashes and exchanges missing entries.
	// Called periodically and on peer reconnect.
	SyncState(ctx context.Context, peerID string) error

	// State returns the current health of the signal gateway and all peers.
	State() GatewayState

	// Close stops background goroutines (sync loops, health checks).
	Close() error
}

// RevocationSignal is the wire format for cross-cluster revocation events.
// Carries enough context for the receiving fabric to apply the revocation
// without needing to re-validate the original SecurityEvent.
type RevocationSignal struct {
	// SubjectID is the revoked identity (SPIFFE ID or WIMSE workload URI).
	SubjectID string `json:"subject_id"`

	// Reason is the CAEP event type that triggered the revocation.
	// e.g., "session-revoked", "credential-change", "agent-credential-revoked"
	Reason string `json:"reason"`

	// RevokedAt is when the revocation was originally applied.
	RevokedAt time.Time `json:"revoked_at"`

	// ExpiresAt is when the revocation entry expires and can be cleaned up.
	ExpiresAt time.Time `json:"expires_at"`

	// EventJTI is the JTI of the originating SecurityEvent (SET).
	// Used for deduplication — a peer that already processed this JTI skips it.
	EventJTI string `json:"event_jti"`

	// SourceFabric is the fabric ID that originated the revocation.
	SourceFabric string `json:"source_fabric"`

	// TrustDomain is the trust domain of the revoked subject.
	TrustDomain string `json:"trust_domain"`

	// CertFabricID is the peer fabric identity extracted from the mTLS client
	// certificate (CN or SAN URI) by the HTTP handler layer. It is NOT part
	// of the JSON wire format — it is set server-side after TLS verification.
	// Used by InboundHandler.VerifyPeerIdentity to cross-check against SourceFabric.
	CertFabricID string `json:"-"`
}

// PeerSignalStatus represents the health of a signal relay connection to a peer.
type PeerSignalStatus string

const (
	// SignalHealthy means the peer is reachable and relaying normally.
	SignalHealthy PeerSignalStatus = "healthy"

	// SignalDegraded means the peer is reachable but experiencing errors.
	SignalDegraded PeerSignalStatus = "degraded"

	// SignalDown means the peer is unreachable for signal relay.
	SignalDown PeerSignalStatus = "down"
)

// PeerSignalState tracks the runtime state of a signal relay connection to a peer.
type PeerSignalState struct {
	// FabricID uniquely identifies the peer fabric.
	FabricID string `json:"fabric_id"`

	// Transport is the relay protocol: "https" or "nats".
	Transport string `json:"transport"`

	// LastRelayed is when the last signal was successfully relayed to this peer.
	LastRelayed time.Time `json:"last_relayed"`

	// LastReceived is when the last signal was received from this peer.
	LastReceived time.Time `json:"last_received"`

	// RelayedCount is the total number of signals successfully relayed.
	RelayedCount int64 `json:"relayed_count"`

	// ReceivedCount is the total number of signals received from this peer.
	ReceivedCount int64 `json:"received_count"`

	// ErrorCount is the total number of relay errors for this peer.
	ErrorCount int64 `json:"error_count"`

	// ConsecutiveErrors tracks consecutive relay failures for circuit breaking.
	// Reset to 0 on any successful relay. When it reaches circuitBreakerThreshold,
	// the peer status is set to SignalDown and relay attempts are skipped.
	ConsecutiveErrors int `json:"consecutive_errors"`

	// RevocationHash is the peer's last-known revocation index hash.
	// Compared during SyncState for reconciliation.
	RevocationHash string `json:"revocation_hash"`

	// Status is the current health of the signal connection.
	Status PeerSignalStatus `json:"status"`
}

// GatewayState is the aggregate state of the signal gateway.
// Used for health reporting and the soul manifest signals section.
type GatewayState struct {
	// Peers maps fabricId to peer signal state.
	Peers map[string]*PeerSignalState `json:"peers"`

	// UpdatedAt is when this state was last computed.
	UpdatedAt time.Time `json:"updated_at"`
}

// HealthyCount returns the number of peers with healthy signal connections.
func (gs *GatewayState) HealthyCount() int {
	n := 0
	for _, ps := range gs.Peers {
		if ps.Status == SignalHealthy {
			n++
		}
	}
	return n
}

// DegradedCount returns the number of peers with degraded signal connections.
func (gs *GatewayState) DegradedCount() int {
	n := 0
	for _, ps := range gs.Peers {
		if ps.Status == SignalDegraded {
			n++
		}
	}
	return n
}

// DownCount returns the number of peers with down signal connections.
func (gs *GatewayState) DownCount() int {
	n := 0
	for _, ps := range gs.Peers {
		if ps.Status == SignalDown {
			n++
		}
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────────────

// DefaultRelayTimeout is the default timeout for relaying a signal to a peer.
const DefaultRelayTimeout = 2 * time.Second

// DefaultSyncInterval is the default interval for hash reconciliation with peers.
const DefaultSyncInterval = 30 * time.Second

// SignalGatewayConfig is the top-level configuration for the signal gateway.
type SignalGatewayConfig struct {
	// Peers defines the signal relay configuration for each federated peer.
	Peers []PeerSignalConfig `yaml:"peers" json:"peers"`
}

// PeerSignalConfig defines the signal relay configuration for a single peer.
type PeerSignalConfig struct {
	// FabricID uniquely identifies the peer fabric.
	// Must match the peer's PeerConfig.FabricID from JWKS federation.
	FabricID string `yaml:"fabricId" json:"fabricId"`

	// Endpoint is the peer's signal relay URL (e.g., https://peer/v1/signals/events).
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Transport is the relay protocol. Valid values: "https", "nats".
	// Default: "https".
	Transport string `yaml:"transport,omitempty" json:"transport,omitempty"`

	// RelayTimeout is the per-peer timeout for relaying a single signal.
	// Default: 2s.
	RelayTimeout time.Duration `yaml:"relayTimeout,omitempty" json:"relayTimeout,omitempty"`

	// SyncInterval is how often hash reconciliation runs with this peer.
	// Default: 30s.
	SyncInterval time.Duration `yaml:"syncInterval,omitempty" json:"syncInterval,omitempty"`

	// MTLSSecret is the Kubernetes Secret name holding the mTLS client
	// certificate for authenticating signal relay to this peer.
	MTLSSecret string `yaml:"mtlsSecret,omitempty" json:"mtlsSecret,omitempty"`
}

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (psc *PeerSignalConfig) ApplyDefaults() {
	if psc.Transport == "" {
		psc.Transport = "https"
	}
	if psc.RelayTimeout <= 0 {
		psc.RelayTimeout = DefaultRelayTimeout
	}
	if psc.SyncInterval <= 0 {
		psc.SyncInterval = DefaultSyncInterval
	}
}

// validTransports is the set of supported relay transports.
var validTransports = map[string]bool{
	"https": true,
}

// unimplementedTransports lists transports that are recognized but not yet implemented.
var unimplementedTransports = map[string]bool{
	"nats": true,
}

// ValidateSignalGatewayConfig checks that the gateway configuration is valid.
// Returns an error describing the first invalid field found.
func ValidateSignalGatewayConfig(cfg SignalGatewayConfig) error {
	seenFabricIDs := make(map[string]int, len(cfg.Peers))
	for i, peer := range cfg.Peers {
		if peer.FabricID == "" {
			return fmt.Errorf("peers[%d]: fabricId is required", i)
		}
		if prevIdx, ok := seenFabricIDs[peer.FabricID]; ok {
			return fmt.Errorf("peers[%d]: duplicate fabricId %q (first seen at peers[%d])", i, peer.FabricID, prevIdx)
		}
		seenFabricIDs[peer.FabricID] = i
		if peer.Endpoint == "" {
			return fmt.Errorf("peers[%d] (%s): endpoint is required", i, peer.FabricID)
		}
		// Apply defaults before validating derived fields.
		peer.ApplyDefaults()
		if unimplementedTransports[peer.Transport] {
			return fmt.Errorf("peers[%d] (%s): transport %q not yet implemented", i, peer.FabricID, peer.Transport)
		}
		if !validTransports[peer.Transport] {
			return fmt.Errorf("peers[%d] (%s): invalid transport %q (must be \"https\")", i, peer.FabricID, peer.Transport)
		}
		if peer.RelayTimeout <= 0 {
			return fmt.Errorf("peers[%d] (%s): relayTimeout must be positive", i, peer.FabricID)
		}
		if peer.SyncInterval <= 0 {
			return fmt.Errorf("peers[%d] (%s): syncInterval must be positive", i, peer.FabricID)
		}
	}
	return nil
}
