package federation

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	stdsync "github.com/starfly-fabrics/starfly/pkg/sync"
)

// ─────────────────────────────────────────────────────────────────────
// COMPOSITE GATEWAY — Unified SignalGateway Implementation (H-3 Fix)
//
// SignalGateway defines five methods but no single struct implements all
// of them: Relay handles outbound, InboundHandler handles inbound, and
// Syncer handles reconciliation. CompositeGateway composes all three
// into a single value that satisfies the interface.
//
// This is also the integration point for H-4: the sync bus bridge that
// subscribes to local revocation signals and auto-relays them to peers.
// ─────────────────────────────────────────────────────────────────────

// Compile-time assertion: CompositeGateway satisfies SignalGateway.
var _ SignalGateway = (*CompositeGateway)(nil)

// CompositeGateway composes Relay, InboundHandler, and Syncer into a
// unified SignalGateway implementation. Each method delegates to the
// appropriate component.
type CompositeGateway struct {
	relay   *Relay
	inbound *InboundHandler
	syncer  *Syncer
	logger  *slog.Logger

	// syncBusSub tracks whether SubscribeToSyncBus has been called,
	// to prevent double-subscription.
	syncBusSubscribed bool
}

// NewCompositeGateway creates a CompositeGateway from its constituent parts.
// All three components must be non-nil.
func NewCompositeGateway(relay *Relay, inbound *InboundHandler, syncer *Syncer) *CompositeGateway {
	logger := slog.Default()
	if relay != nil && relay.logger != nil {
		logger = relay.logger
	}

	logger.Info("composite gateway initialized",
		"has_relay", relay != nil,
		"has_inbound", inbound != nil,
		"has_syncer", syncer != nil,
	)

	return &CompositeGateway{
		relay:   relay,
		inbound: inbound,
		syncer:  syncer,
		logger:  logger,
	}
}

// RelayRevocation delegates to Relay to push a revocation signal to all
// connected peers.
func (cg *CompositeGateway) RelayRevocation(ctx context.Context, signal RevocationSignal) error {
	if cg.relay == nil {
		return fmt.Errorf("composite gateway: relay component is nil")
	}
	return cg.relay.RelayRevocation(ctx, signal)
}

// ReceiveRevocation delegates to InboundHandler to process an inbound
// revocation signal from a peer.
func (cg *CompositeGateway) ReceiveRevocation(ctx context.Context, signal RevocationSignal) error {
	if cg.inbound == nil {
		return fmt.Errorf("composite gateway: inbound component is nil")
	}
	return cg.inbound.ReceiveRevocation(ctx, signal)
}

// SyncState delegates to Syncer to perform hash-based reconciliation
// with the specified peer. It calls the syncer's internal syncWithPeer
// method by looking up the peer config.
func (cg *CompositeGateway) SyncState(ctx context.Context, peerID string) error {
	if cg.syncer == nil {
		return fmt.Errorf("composite gateway: syncer component is nil")
	}

	// Find the peer config for the requested peerID.
	cg.syncer.mu.RLock()
	var peerCfg *PeerSignalConfig
	for i := range cg.syncer.peers {
		if cg.syncer.peers[i].FabricID == peerID {
			p := cg.syncer.peers[i]
			peerCfg = &p
			break
		}
	}
	cg.syncer.mu.RUnlock()

	if peerCfg == nil {
		return fmt.Errorf("composite gateway: unknown peer %q for sync", peerID)
	}

	return cg.syncer.syncWithPeer(ctx, *peerCfg)
}

// State merges state from all three components into a unified GatewayState.
// Relay peer states are the base; inbound and syncer states are overlaid
// so the caller gets a complete view of each peer's relay, receive, and
// sync health in one snapshot.
func (cg *CompositeGateway) State() GatewayState {
	merged := GatewayState{
		Peers:     make(map[string]*PeerSignalState),
		UpdatedAt: time.Now().UTC(),
	}

	// Start with relay state (has relay counts, last relayed, status).
	if cg.relay != nil {
		relayState := cg.relay.State()
		for id, ps := range relayState.Peers {
			cp := *ps
			merged.Peers[id] = &cp
		}
	}

	// Overlay inbound state (has received counts, last received).
	if cg.inbound != nil {
		inboundStates := cg.inbound.State()
		for id, is := range inboundStates {
			if existing, ok := merged.Peers[id]; ok {
				existing.ReceivedCount = is.ReceivedCount
				existing.LastReceived = is.LastReceived
			} else {
				merged.Peers[id] = is
			}
		}
	}

	// Overlay syncer state metadata (hash info) via RevocationHash.
	if cg.syncer != nil {
		syncStates := cg.syncer.State()
		for id, ss := range syncStates {
			if existing, ok := merged.Peers[id]; ok {
				existing.RevocationHash = ss.PeerHash
			}
			// Syncer tracks peers that may not be in relay/inbound —
			// but those are SyncPeerState, not PeerSignalState, so we
			// only enrich existing entries.
			_ = ss
		}
	}

	return merged
}

// Close stops all three components. Errors from individual components
// are collected but do not prevent other components from closing.
func (cg *CompositeGateway) Close() error {
	var errs []error

	if cg.relay != nil {
		if err := cg.relay.Close(); err != nil {
			errs = append(errs, fmt.Errorf("relay close: %w", err))
		}
	}

	// InboundHandler has no Close method — it is stateless per-request.

	if cg.syncer != nil {
		if err := cg.syncer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("syncer close: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("composite gateway close: %v", errs)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// SYNC BUS BRIDGE — H-4 Fix
//
// SubscribeToSyncBus wires the local sync bus to the relay so that
// local revocation events automatically propagate to federated peers.
// Without this bridge, RelayRevocation must be called explicitly —
// meaning local revocations would never reach peers in production.
// ─────────────────────────────────────────────────────────────────────

// revocationSignalTypes are the sync bus signal types that should
// trigger outbound relay to federated peers.
var revocationSignalTypes = []string{
	stdsync.SignalIdentityRevoked,
	stdsync.SignalCAEPSessionRevoked,
}

// SubscribeToSyncBus subscribes to revocation-related signals on the
// local sync bus and automatically relays them to federated peers.
// This bridges the gap where local revocations were not propagating
// to peers because RelayRevocation required explicit invocation.
//
// The sourceFabric parameter identifies this fabric in outbound signals.
func (cg *CompositeGateway) SubscribeToSyncBus(ctx context.Context, bus core.SyncBus, sourceFabric string) error {
	if cg.relay == nil {
		return fmt.Errorf("composite gateway: cannot subscribe to sync bus without relay")
	}
	if bus == nil {
		return fmt.Errorf("composite gateway: sync bus is nil")
	}
	if cg.syncBusSubscribed {
		return fmt.Errorf("composite gateway: already subscribed to sync bus")
	}

	for _, sigType := range revocationSignalTypes {
		st := sigType // capture for closure
		handler := cg.buildSyncBusHandler(st, sourceFabric)
		if err := bus.Subscribe(ctx, st, handler); err != nil {
			return fmt.Errorf("subscribing to %s on sync bus: %w", st, err)
		}
		cg.logger.Info("sync bus bridge subscribed",
			"signal_type", st,
			"source_fabric", sourceFabric,
		)
	}

	cg.syncBusSubscribed = true
	return nil
}

// buildSyncBusHandler returns a SignalHandler that converts a local
// sync bus signal into a RevocationSignal and relays it to peers.
func (cg *CompositeGateway) buildSyncBusHandler(signalType, sourceFabric string) core.SignalHandler {
	return func(ctx context.Context, signal *core.Signal) error {
		// Extract subject_id from the signal payload.
		subjectID, _ := signal.Payload["subject_id"].(string)
		if subjectID == "" {
			cg.logger.Debug("sync bus signal missing subject_id, skipping relay",
				"signal_type", signalType,
				"source", signal.Source,
			)
			return nil
		}

		// Extract optional fields from payload.
		reason, _ := signal.Payload["reason"].(string)
		if reason == "" {
			reason = signalType
		}
		eventJTI, _ := signal.Payload["event_jti"].(string)
		trustDomain, _ := signal.Payload["trust_domain"].(string)

		revSig := RevocationSignal{
			SubjectID:    subjectID,
			Reason:       reason,
			RevokedAt:    signal.Timestamp,
			ExpiresAt:    signal.Timestamp.Add(1 * time.Hour), // default 1h TTL
			EventJTI:     eventJTI,
			SourceFabric: sourceFabric,
			TrustDomain:  trustDomain,
		}

		if err := cg.relay.RelayRevocation(ctx, revSig); err != nil {
			cg.logger.Error("sync bus bridge relay failed",
				"signal_type", signalType,
				"subject_id", subjectID,
				"error", err,
			)
			return err
		}

		cg.logger.Info("sync bus bridge relayed revocation",
			"signal_type", signalType,
			"subject_id", subjectID,
			"source_fabric", sourceFabric,
		)
		return nil
	}
}
