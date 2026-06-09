package federation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	globalmetrics "github.com/starfly-fabrics/starfly/pkg/metrics"
)

// ─────────────────────────────────────────────────────────────────────
// RELAY — Outbound Revocation Signal Propagation (Phase 13, P13-003)
//
// The Relay implements the outbound half of the SignalGateway. It fans
// out RevocationSignal events to all configured peer fabrics over HTTPS.
// Delivery is fire-and-forget: errors are logged and tracked in
// PeerSignalState but do not block delivery to other peers.
//
// Deduplication uses a bounded JTI set (FIFO eviction) so the same
// revocation event relayed via multiple paths is sent at most once.
// ─────────────────────────────────────────────────────────────────────

const defaultMaxSeen = 10_000

// circuitBreakerThreshold is the number of consecutive relay failures
// before a peer is marked SignalDown and relay attempts are skipped.
const circuitBreakerThreshold = 5

// Relay fans out revocation signals to federated peer fabrics.
type Relay struct {
	mu          sync.RWMutex
	peers       []PeerSignalConfig
	peerStates  map[string]*PeerSignalState
	seen        map[string]struct{} // JTI dedup, bounded FIFO
	seenOrder   []string            // FIFO eviction order
	maxSeen     int                 // default 10000
	client      *http.Client        // default client (no mTLS, dev mode)
	peerClients map[string]*http.Client // per-peer mTLS clients, keyed by FabricID
	unitID      string
	logger      *slog.Logger
	met         *globalmetrics.Metrics
}

// RelayOption configures a Relay.
type RelayOption func(*Relay)

// WithRelayHTTPClient sets the HTTP client used for relay requests.
func WithRelayHTTPClient(c *http.Client) RelayOption {
	return func(r *Relay) { r.client = c }
}

// WithRelayUnitID sets the unit ID used for relay logging context.
func WithRelayUnitID(id string) RelayOption {
	return func(r *Relay) { r.unitID = id }
}

// WithRelayLogger sets the logger for relay operations.
func WithRelayLogger(l *slog.Logger) RelayOption {
	return func(r *Relay) { r.logger = l }
}

// WithRelayMetrics injects a Metrics instance for recording federation relay counters.
func WithRelayMetrics(m *globalmetrics.Metrics) RelayOption {
	return func(r *Relay) { r.met = m }
}

// NewRelay creates a Relay from the given gateway configuration.
// Each peer's defaults are applied before use. If a peer has MTLSSecret
// configured, a per-peer HTTP client with mTLS is built and cached.
// Peers without MTLSSecret fall back to the default (non-mTLS) client.
func NewRelay(cfg SignalGatewayConfig, opts ...RelayOption) *Relay {
	r := &Relay{
		peers:       make([]PeerSignalConfig, len(cfg.Peers)),
		peerStates:  make(map[string]*PeerSignalState, len(cfg.Peers)),
		peerClients: make(map[string]*http.Client, len(cfg.Peers)),
		seen:        make(map[string]struct{}, defaultMaxSeen),
		seenOrder:   make([]string, 0, defaultMaxSeen),
		maxSeen:     defaultMaxSeen,
		client:      core.NewDefaultHTTPClient(),
		logger:      slog.Default(),
	}

	copy(r.peers, cfg.Peers)
	for i := range r.peers {
		r.peers[i].ApplyDefaults()
		r.peerStates[r.peers[i].FabricID] = &PeerSignalState{
			FabricID:  r.peers[i].FabricID,
			Transport: r.peers[i].Transport,
			Status:    SignalHealthy,
		}
	}

	for _, opt := range opts {
		opt(r)
	}

	// Build per-peer mTLS clients for peers with MTLSSecret configured.
	for _, p := range r.peers {
		if p.MTLSSecret != "" {
			c, err := buildPeerTLSClient(p.MTLSSecret, p.RelayTimeout)
			if err != nil {
				r.logger.Error("failed to build mTLS client for peer, falling back to default",
					"fabric_id", p.FabricID,
					"mtls_secret", p.MTLSSecret,
					"error", err,
				)
				continue
			}
			r.peerClients[p.FabricID] = c
			r.logger.Info("mTLS client configured for peer",
				"fabric_id", p.FabricID,
			)
		}
	}

	r.logger.Info("revocation relay initialized",
		"peer_count", len(r.peers),
		"mtls_peers", len(r.peerClients),
		"unit_id", r.unitID,
	)

	return r
}

// buildPeerTLSClient creates an *http.Client configured with mTLS using
// the PEM cert+key file at the given path. The file must contain both
// the client certificate and private key in PEM format (concatenated).
func buildPeerTLSClient(certKeyPath string, timeout time.Duration) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certKeyPath, certKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading mTLS cert/key from %s: %w", certKeyPath, err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}

// clientForPeer returns the per-peer mTLS client if configured,
// otherwise the default HTTP client.
func (r *Relay) clientForPeer(fabricID string) *http.Client {
	if c, ok := r.peerClients[fabricID]; ok {
		return c
	}
	return r.client
}

// RelayRevocation pushes a revocation signal to all connected peers.
// Delivery is fire-and-forget — errors are logged and tracked in peer
// state but not returned to the caller. Duplicate JTIs are silently
// skipped (idempotent).
func (r *Relay) RelayRevocation(ctx context.Context, signal RevocationSignal) error {
	r.mu.Lock()

	// JTI dedup — already relayed this event.
	// Skip dedup for empty JTIs: they cannot be deduplicated and inserting ""
	// into the seen map would block all future signals with missing JTIs.
	if signal.EventJTI != "" {
		if _, ok := r.seen[signal.EventJTI]; ok {
			r.mu.Unlock()
			r.logger.Debug("relay skipped duplicate JTI", "jti", signal.EventJTI)
			return nil
		}

		// Record JTI and evict oldest if over capacity.
		r.seen[signal.EventJTI] = struct{}{}
		r.seenOrder = append(r.seenOrder, signal.EventJTI)
		if len(r.seen) > r.maxSeen {
			r.evictOldestLocked()
		}
	}

	// Snapshot peers for fan-out outside the lock.
	peers := make([]PeerSignalConfig, len(r.peers))
	copy(peers, r.peers)
	r.mu.Unlock()

	// Fan out to each peer concurrently.
	var wg sync.WaitGroup
	for _, peer := range peers {
		// Circuit breaker: skip peers marked SignalDown.
		r.mu.RLock()
		ps := r.peerStates[peer.FabricID]
		isDown := ps != nil && ps.Status == SignalDown
		r.mu.RUnlock()
		if isDown {
			r.logger.Debug("relay skipped for down peer (circuit breaker open)",
				"fabric_id", peer.FabricID,
				"jti", signal.EventJTI,
			)
			continue
		}

		wg.Add(1)
		go func(p PeerSignalConfig) {
			defer wg.Done()

			timeout := p.RelayTimeout
			if timeout <= 0 {
				timeout = DefaultRelayTimeout
			}
			peerCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			err := r.relayToPeer(peerCtx, p, signal)

			r.mu.Lock()
			ps := r.peerStates[p.FabricID]
			if err != nil {
				ps.ErrorCount++
				ps.ConsecutiveErrors++
				if ps.ConsecutiveErrors >= circuitBreakerThreshold {
					ps.Status = SignalDown
				} else {
					ps.Status = SignalDegraded
				}
				r.logger.Warn("relay to peer failed",
					"fabric_id", p.FabricID,
					"jti", signal.EventJTI,
					"consecutive_errors", ps.ConsecutiveErrors,
					"error", err,
				)
			} else {
				ps.LastRelayed = time.Now().UTC()
				ps.RelayedCount++
				ps.ConsecutiveErrors = 0
				ps.Status = SignalHealthy
			}
			r.mu.Unlock()
		}(peer)
	}
	wg.Wait()

	return nil
}

// relayToPeer sends a single RevocationSignal to one peer via HTTP POST.
// Uses the per-peer mTLS client when configured, otherwise the default client.
func (r *Relay) relayToPeer(ctx context.Context, peer PeerSignalConfig, signal RevocationSignal) error {
	start := time.Now()

	body, err := json.Marshal(signal)
	if err != nil {
		return fmt.Errorf("marshaling revocation signal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peer.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating relay request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use per-peer mTLS client if available; mTLS provides authentication
	// at the transport layer — no application-level source headers needed.
	client := r.clientForPeer(peer.FabricID)

	resp, err := client.Do(req)
	if err != nil {
		if r.met != nil {
			r.met.FederationRelayTotal.WithLabelValues(peer.FabricID, "error").Inc()
			r.met.FederationRelayDuration.WithLabelValues(peer.FabricID).Observe(time.Since(start).Seconds())
		}
		return fmt.Errorf("relay POST to %s: %w", peer.Endpoint, err)
	}
	defer func() {
		// Drain body to enable HTTP connection reuse.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if r.met != nil {
			r.met.FederationRelayTotal.WithLabelValues(peer.FabricID, "error").Inc()
			r.met.FederationRelayDuration.WithLabelValues(peer.FabricID).Observe(time.Since(start).Seconds())
		}
		return fmt.Errorf("relay POST to %s returned HTTP %d", peer.Endpoint, resp.StatusCode)
	}

	if r.met != nil {
		r.met.FederationRelayTotal.WithLabelValues(peer.FabricID, "ok").Inc()
		r.met.FederationRelayDuration.WithLabelValues(peer.FabricID).Observe(time.Since(start).Seconds())
	}

	return nil
}

// State returns a snapshot of the current gateway state.
func (r *Relay) State() GatewayState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make(map[string]*PeerSignalState, len(r.peerStates))
	for id, ps := range r.peerStates {
		cp := *ps
		peers[id] = &cp
	}

	return GatewayState{
		Peers:     peers,
		UpdatedAt: time.Now().UTC(),
	}
}

// Close is a no-op — the relay is stateless per-request with no
// background goroutines. Provided to satisfy the SignalGateway interface.
func (r *Relay) Close() error {
	return nil
}

// evictOldestLocked removes the oldest 10% of seen JTIs.
// MUST be called while r.mu is held.
func (r *Relay) evictOldestLocked() {
	evictCount := r.maxSeen / 10
	if evictCount == 0 {
		evictCount = 1
	}
	if evictCount > len(r.seenOrder) {
		evictCount = len(r.seenOrder)
	}

	for _, jti := range r.seenOrder[:evictCount] {
		delete(r.seen, jti)
	}
	// Copy remaining entries to a new slice so the old backing array can be GC'd.
	remaining := make([]string, len(r.seenOrder)-evictCount)
	copy(remaining, r.seenOrder[evictCount:])
	r.seenOrder = remaining
}
