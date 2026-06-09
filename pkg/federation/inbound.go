package federation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ─────────────────────────────────────────────────────────────────────
// INBOUND REVOCATION HANDLER — Phase 13, P13-004
//
// Receives revocation signals from peer fabrics, validates trust,
// applies to the local RevocationIndex, and optionally flashes
// the event to the local cluster via SyncBus.
//
// Local interfaces avoid circular imports: concrete implementations
// from core/signals satisfy these at construction time.
// ─────────────────────────────────────────────────────────────────────

// RevocationIndex is the subset of core.RevocationIndex needed by InboundHandler.
// Defined locally to avoid circular import paths; the concrete
// InMemoryRevocationIndex from pkg/signals satisfies this.
type RevocationIndex interface {
	Revoke(ctx context.Context, subjectID, reason string, expiresAt time.Time) error
}

// SyncBus is the subset of core.SyncBus needed by InboundHandler.
// Defined locally to avoid circular import paths.
type SyncBus interface {
	Flash(ctx context.Context, signal *core.Signal) error
}

// Sentinel errors for inbound operations.
var (
	ErrUntrustedPeer      = fmt.Errorf("untrusted peer")
	ErrInvalidSignal      = fmt.Errorf("invalid revocation signal")
	ErrSignalExpired      = fmt.Errorf("revocation signal expired")
	ErrMTLSRequired       = fmt.Errorf("mTLS identity required")
	ErrPeerIdentityMismatch = fmt.Errorf("peer identity mismatch")
)

// InboundHandler processes inbound revocation signals from peer fabrics.
// It validates that signals originate from trusted peers, applies the
// revocation to the local index, and optionally flashes the event to
// the local cluster for real-time propagation.
//
// When requireMTLS is true, the handler rejects signals that do not carry
// a CertFabricID (set by the HTTP handler layer after TLS verification)
// and cross-checks it against the claimed SourceFabric.
type InboundHandler struct {
	mu           sync.RWMutex
	trustedPeers map[string]PeerSignalConfig // fabricID → config
	peerStates   map[string]*PeerSignalState
	revocation   RevocationIndex // local revocation index
	syncBus      SyncBus         // optional, flash to local cluster
	requireMTLS  bool            // reject signals without mTLS identity
	logger       *slog.Logger

	// JTI dedup — bounded FIFO, mirrors Relay dedup logic.
	seen      map[string]struct{}
	seenOrder []string
	maxSeen   int
	dedupHits atomic.Int64 // counter for deduplicated signals
}

// InboundOption configures the InboundHandler.
type InboundOption func(*InboundHandler)

// WithInboundRevocation injects the revocation index for applying inbound revocations.
func WithInboundRevocation(r RevocationIndex) InboundOption {
	return func(h *InboundHandler) { h.revocation = r }
}

// WithInboundSyncBus injects the sync bus for flashing signals to the local cluster.
func WithInboundSyncBus(bus SyncBus) InboundOption {
	return func(h *InboundHandler) { h.syncBus = bus }
}

// WithInboundLogger injects a structured logger.
func WithInboundLogger(l *slog.Logger) InboundOption {
	return func(h *InboundHandler) { h.logger = l }
}

// WithInboundRequireMTLS enforces mTLS peer identity verification on all
// inbound signals. When enabled, signals without a CertFabricID are rejected,
// and the CertFabricID must match the claimed SourceFabric.
func WithInboundRequireMTLS(require bool) InboundOption {
	return func(h *InboundHandler) { h.requireMTLS = require }
}

// NewInboundHandler creates an InboundHandler with the given trusted peers and options.
// Each peer's config is indexed by FabricID for O(1) trust checks.
func NewInboundHandler(peers []PeerSignalConfig, opts ...InboundOption) *InboundHandler {
	h := &InboundHandler{
		trustedPeers: make(map[string]PeerSignalConfig, len(peers)),
		peerStates:   make(map[string]*PeerSignalState, len(peers)),
		seen:         make(map[string]struct{}, defaultMaxSeen),
		seenOrder:    make([]string, 0, defaultMaxSeen),
		maxSeen:      defaultMaxSeen,
		logger:       slog.Default(),
	}

	for _, p := range peers {
		p.ApplyDefaults()
		h.trustedPeers[p.FabricID] = p
		h.peerStates[p.FabricID] = &PeerSignalState{
			FabricID:  p.FabricID,
			Transport: p.Transport,
			Status:    SignalHealthy,
		}
	}

	for _, opt := range opts {
		opt(h)
	}

	h.logger.Info("inbound handler initialized", "trusted_peers", len(h.trustedPeers))
	return h
}

// VerifyPeerIdentity cross-checks the claimed SourceFabric against the
// fabric identity extracted from the peer's mTLS client certificate.
// The HTTP handler layer is responsible for extracting CertFabricID from
// r.TLS.PeerCertificates (CN or SAN URI) and setting it on the signal
// before calling ReceiveRevocation.
//
// Returns nil if the identities match, or an error describing the mismatch.
func (h *InboundHandler) VerifyPeerIdentity(claimed, certFabricID string) error {
	if certFabricID == "" {
		return fmt.Errorf("%w: no certificate identity provided", ErrMTLSRequired)
	}
	if claimed != certFabricID {
		return fmt.Errorf("%w: claimed %q but certificate says %q", ErrPeerIdentityMismatch, claimed, certFabricID)
	}
	return nil
}

// ReceiveRevocation handles an inbound revocation signal from a peer fabric.
// It validates trust, applies the revocation to the local index, and optionally
// flashes the event to the local cluster via SyncBus.
//
// When requireMTLS is enabled, the signal's CertFabricID must be set (by the
// HTTP handler layer) and must match SourceFabric. Without requireMTLS,
// CertFabricID is still verified if present but not required.
func (h *InboundHandler) ReceiveRevocation(ctx context.Context, signal RevocationSignal) error {
	// mTLS identity verification.
	if h.requireMTLS && signal.CertFabricID == "" {
		h.logger.Warn("mTLS identity required but not provided",
			"source_fabric", signal.SourceFabric,
		)
		return fmt.Errorf("%w: signal from %s has no mTLS identity", ErrMTLSRequired, signal.SourceFabric)
	}
	if signal.CertFabricID != "" {
		if err := h.VerifyPeerIdentity(signal.SourceFabric, signal.CertFabricID); err != nil {
			h.logger.Warn("peer identity verification failed",
				"source_fabric", signal.SourceFabric,
				"cert_fabric_id", signal.CertFabricID,
				"error", err,
			)
			return err
		}
	}

	// Trust check: is the source fabric in our trusted peers?
	if !h.IsTrustedPeer(signal.SourceFabric) {
		h.logger.Warn("revocation from untrusted peer",
			"source_fabric", signal.SourceFabric,
			"subject_id", signal.SubjectID,
		)
		return fmt.Errorf("%w: %s", ErrUntrustedPeer, signal.SourceFabric)
	}

	// Validate: SubjectID must be non-empty.
	if signal.SubjectID == "" {
		return fmt.Errorf("%w: empty subject_id", ErrInvalidSignal)
	}

	// Default max TTL: if ExpiresAt is zero, apply a 24h default to prevent
	// permanent revocations from signals that omit an expiry.
	if signal.ExpiresAt.IsZero() {
		signal.ExpiresAt = time.Now().Add(24 * time.Hour)
		h.logger.Warn("revocation signal has zero ExpiresAt, applying default 24h TTL",
			"subject_id", signal.SubjectID,
			"source_fabric", signal.SourceFabric,
			"default_expires_at", signal.ExpiresAt,
		)
	}

	// Validate: ExpiresAt must be in the future.
	if signal.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("%w: expires_at is in the past", ErrSignalExpired)
	}

	// JTI dedup — skip if we've already processed this event.
	// Empty JTIs are not tracked (cannot meaningfully deduplicate).
	if signal.EventJTI != "" {
		h.mu.Lock()
		if _, ok := h.seen[signal.EventJTI]; ok {
			h.mu.Unlock()
			h.dedupHits.Add(1)
			h.logger.Debug("inbound revocation skipped duplicate JTI",
				"jti", signal.EventJTI,
				"source_fabric", signal.SourceFabric,
			)
			return nil
		}
		h.seen[signal.EventJTI] = struct{}{}
		h.seenOrder = append(h.seenOrder, signal.EventJTI)
		if len(h.seen) > h.maxSeen {
			h.evictOldestLocked()
		}
		h.mu.Unlock()
	}

	// Apply revocation to local index.
	if h.revocation != nil {
		reason := fmt.Sprintf("federated:%s from:%s", signal.Reason, signal.SourceFabric)
		if err := h.revocation.Revoke(ctx, signal.SubjectID, reason, signal.ExpiresAt); err != nil {
			h.logger.Error("revocation failed",
				"error", err,
				"subject_id", signal.SubjectID,
				"source_fabric", signal.SourceFabric,
			)
			return fmt.Errorf("applying revocation: %w", err)
		}
	}

	// Flash to local cluster if sync bus is configured.
	if h.syncBus != nil {
		sig := &core.Signal{
			Type:      "federation.revocation",
			Source:    signal.SourceFabric,
			Timestamp: time.Now().UTC(),
			Payload: map[string]interface{}{
				"subject_id":    signal.SubjectID,
				"reason":        signal.Reason,
				"source_fabric": signal.SourceFabric,
				"event_jti":     signal.EventJTI,
			},
		}
		if err := h.syncBus.Flash(ctx, sig); err != nil {
			h.logger.Error("sync bus flash failed for federated revocation",
				"error", err,
				"subject_id", signal.SubjectID,
				"source_fabric", signal.SourceFabric,
			)
			// Non-fatal: revocation was already applied locally.
		}
	}

	// Update peer state.
	h.mu.Lock()
	if state, ok := h.peerStates[signal.SourceFabric]; ok {
		state.ReceivedCount++
		state.LastReceived = time.Now().UTC()
	}
	h.mu.Unlock()

	h.logger.Info("federated revocation applied",
		"subject_id", signal.SubjectID,
		"reason", signal.Reason,
		"source_fabric", signal.SourceFabric,
		"event_jti", signal.EventJTI,
	)

	return nil
}

// IsTrustedPeer checks if a fabricID is in the trusted peers map.
// Thread-safe.
func (h *InboundHandler) IsTrustedPeer(fabricID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.trustedPeers[fabricID]
	return ok
}

// DedupHits returns the number of inbound signals deduplicated by JTI.
func (h *InboundHandler) DedupHits() int64 {
	return h.dedupHits.Load()
}

// evictOldestLocked removes the oldest 10% of seen JTIs.
// MUST be called while h.mu is held.
func (h *InboundHandler) evictOldestLocked() {
	evictCount := h.maxSeen / 10
	if evictCount == 0 {
		evictCount = 1
	}
	if evictCount > len(h.seenOrder) {
		evictCount = len(h.seenOrder)
	}

	for _, jti := range h.seenOrder[:evictCount] {
		delete(h.seen, jti)
	}
	// Copy remaining entries to a new slice so the old backing array can be GC'd.
	remaining := make([]string, len(h.seenOrder)-evictCount)
	copy(remaining, h.seenOrder[evictCount:])
	h.seenOrder = remaining
}

// State returns a copy of the current peer signal states.
func (h *InboundHandler) State() map[string]*PeerSignalState {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make(map[string]*PeerSignalState, len(h.peerStates))
	for k, v := range h.peerStates {
		cp := *v
		out[k] = &cp
	}
	return out
}
