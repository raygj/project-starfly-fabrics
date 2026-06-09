// Package federation implements multi-cluster JWKS federation for Starfly.
//
// Federation enables Starfly fabrics in separate clusters to validate each
// other's tokens without sharing signing keys. Each cluster publishes its
// JWKS; peer clusters prefetch and cache those keys.
//
// Design principle: "Federation through resolution, not replication."
// No signing keys cross cluster boundaries. Each fabric remains sovereign.
// The only shared artifact is a public JWKS endpoint.
//
// See ADR-0011 for architecture rationale.
package federation

import (
	"time"
)

// PeerConfig defines a federated peer fabric.
// Configured via the StarlightFabric CRD spec.federation.peers[].
type PeerConfig struct {
	// FabricID uniquely identifies the peer fabric.
	FabricID string `yaml:"fabricId" json:"fabricId"`

	// JWKSEndpoint is the HTTPS URL serving the peer's public JWKS.
	JWKSEndpoint string `yaml:"jwksEndpoint" json:"jwksEndpoint"`

	// MTLSSecret is the Kubernetes Secret name holding the mTLS client
	// certificate used to authenticate JWKS fetches from this peer.
	// Empty string means no mTLS (dev/testing only).
	MTLSSecret string `yaml:"mtlsSecret,omitempty" json:"mtlsSecret,omitempty"`

	// RefreshInterval controls how often the peer's JWKS is refetched.
	// Default: 60s. This governs key distribution cadence, NOT revocation
	// propagation (which requires <2s via NATS gateway — see Phase 13).
	RefreshInterval time.Duration `yaml:"refreshInterval" json:"refreshInterval"`

	// StalenessThreshold is the maximum acceptable age of cached keys
	// before the peer is marked unhealthy. Default: 5m.
	// Cached keys are still served beyond this threshold (graceful degradation)
	// but health probes report the peer as stale.
	StalenessThreshold time.Duration `yaml:"stalenessThreshold" json:"stalenessThreshold"`
}

// DefaultRefreshInterval is the default JWKS refetch interval per peer.
const DefaultRefreshInterval = 60 * time.Second

// DefaultStalenessThreshold is the default staleness threshold per peer.
const DefaultStalenessThreshold = 5 * time.Minute

// ApplyDefaults fills in zero-value fields with sensible defaults.
func (pc *PeerConfig) ApplyDefaults() {
	if pc.RefreshInterval <= 0 {
		pc.RefreshInterval = DefaultRefreshInterval
	}
	if pc.StalenessThreshold <= 0 {
		pc.StalenessThreshold = DefaultStalenessThreshold
	}
}

// PeerStatus is the health status of a single federated peer.
type PeerStatus string

const (
	// PeerHealthy means the peer's JWKS was fetched within the refresh interval.
	PeerHealthy PeerStatus = "healthy"

	// PeerStale means the peer's JWKS is older than the staleness threshold.
	// Cached keys are still served but the peer is flagged for attention.
	PeerStale PeerStatus = "stale"

	// PeerUnreachable means the last JWKS fetch attempt failed.
	// Cached keys (if any) are still served until the staleness threshold.
	PeerUnreachable PeerStatus = "unreachable"
)

// PeerState tracks the runtime state of a federated peer.
type PeerState struct {
	// Config is the peer's configuration.
	Config PeerConfig

	// Status is the current health status.
	Status PeerStatus

	// LastSeen is when the peer's JWKS was last successfully fetched.
	LastSeen time.Time

	// LastAttempt is when the last JWKS fetch was attempted (success or failure).
	LastAttempt time.Time

	// LastError is the error from the most recent failed fetch, or empty.
	LastError string

	// KeyCount is the number of public keys in the cached JWKS.
	KeyCount int

	// FetchCount is the total number of successful JWKS fetches since startup.
	FetchCount uint64

	// ErrorCount is the total number of failed JWKS fetches since startup.
	ErrorCount uint64
}

// IsHealthy returns true if the peer is in a healthy state.
func (ps *PeerState) IsHealthy() bool {
	return ps.Status == PeerHealthy
}

// Age returns how long since the peer's JWKS was last successfully fetched.
func (ps *PeerState) Age() time.Duration {
	if ps.LastSeen.IsZero() {
		return 0
	}
	return time.Since(ps.LastSeen)
}

// FederationState is the aggregate state of all federated peers.
// Used for soul manifest federation section and health reporting.
type FederationState struct {
	// Peers maps fabricId to peer state.
	Peers map[string]*PeerState

	// UpdatedAt is when this state was last computed.
	UpdatedAt time.Time
}

// PeerCount returns the total number of configured peers.
func (fs *FederationState) PeerCount() int {
	return len(fs.Peers)
}

// HealthyCount returns the number of peers in healthy state.
func (fs *FederationState) HealthyCount() int {
	n := 0
	for _, ps := range fs.Peers {
		if ps.IsHealthy() {
			n++
		}
	}
	return n
}

// StaleCount returns the number of peers in stale state.
func (fs *FederationState) StaleCount() int {
	n := 0
	for _, ps := range fs.Peers {
		if ps.Status == PeerStale {
			n++
		}
	}
	return n
}

// UnreachableCount returns the number of peers in unreachable state.
func (fs *FederationState) UnreachableCount() int {
	n := 0
	for _, ps := range fs.Peers {
		if ps.Status == PeerUnreachable {
			n++
		}
	}
	return n
}

// ManifestPeer is the serialized peer entry in the soul manifest.
type ManifestPeer struct {
	FabricID       string    `yaml:"fabricId" json:"fabricId"`
	LastSeen       time.Time `yaml:"lastSeen" json:"lastSeen"`
	KeyCount       int       `yaml:"keyCount" json:"keyCount"`
	RevocationHash string    `yaml:"revocationHash,omitempty" json:"revocationHash,omitempty"`
}
