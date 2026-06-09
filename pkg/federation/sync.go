package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/metrics"
)

// ─────────────────────────────────────────────────────────────────────
// SYNCER — Hash-Based Revocation Reconciliation (Phase 13, P13-005)
//
// The Syncer periodically compares local revocation index hashes with
// peer fabrics. When hashes diverge it fetches the peer's full export
// and merges it into the local index. This closes the consistency gap
// that fire-and-forget relay cannot guarantee (network partitions,
// restarts, dropped signals).
//
// Design:
//   - One background goroutine per peer (same pattern as resolver.go).
//   - Compare hashes first (cheap GET). Only fetch full export on mismatch.
//   - SyncPeerState tracks per-peer reconciliation metrics.
// ─────────────────────────────────────────────────────────────────────

// RevocationSyncer is the subset of revocation index needed for sync.
// Defined locally to avoid circular import paths; the concrete
// InMemoryRevocationIndex from pkg/signals satisfies this.
type RevocationSyncer interface {
	Hash() string
	Export() ([]byte, error)
	Import(data []byte) error
	Cleanup(ctx context.Context) (int, error)
}

// Syncer performs periodic hash-based revocation reconciliation with
// federated peer fabrics. It detects divergence cheaply via hash
// comparison and triggers a full export/import only when needed.
type Syncer struct {
	mu         sync.RWMutex
	peers      []PeerSignalConfig
	peerStates map[string]*SyncPeerState
	revocation RevocationSyncer
	client     *http.Client
	stopCh     chan struct{}
	wg         sync.WaitGroup
	logger     *slog.Logger
	met        *metrics.Metrics
	started    bool
	closeOnce  sync.Once
}

// SyncPeerState tracks reconciliation metrics for a single peer.
type SyncPeerState struct {
	FabricID      string    `json:"fabric_id"`
	LastSync      time.Time `json:"last_sync"`
	LastMismatch  time.Time `json:"last_mismatch"`
	SyncCount     int64     `json:"sync_count"`
	MismatchCount int64     `json:"mismatch_count"`
	FullSyncCount int64     `json:"full_sync_count"`
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error,omitempty"`
	PeerHash      string    `json:"peer_hash"`
	LocalHash     string    `json:"local_hash"`
}

// SyncerOption configures a Syncer.
type SyncerOption func(*Syncer)

// WithSyncerHTTPClient sets the HTTP client used for sync requests.
func WithSyncerHTTPClient(c *http.Client) SyncerOption {
	return func(s *Syncer) { s.client = c }
}

// WithSyncerLogger sets the logger for sync operations.
func WithSyncerLogger(l *slog.Logger) SyncerOption {
	return func(s *Syncer) { s.logger = l }
}

// WithSyncerMetrics injects a Metrics instance for recording federation sync counters.
func WithSyncerMetrics(m *metrics.Metrics) SyncerOption {
	return func(s *Syncer) { s.met = m }
}

// NewSyncer creates a Syncer from the given gateway configuration.
// Each peer's defaults are applied before use.
func NewSyncer(cfg SignalGatewayConfig, revocation RevocationSyncer, opts ...SyncerOption) *Syncer {
	s := &Syncer{
		peers:      make([]PeerSignalConfig, len(cfg.Peers)),
		peerStates: make(map[string]*SyncPeerState, len(cfg.Peers)),
		revocation: revocation,
		client:     core.NewDefaultHTTPClient(),
		stopCh:     make(chan struct{}),
		logger:     slog.Default(),
	}

	copy(s.peers, cfg.Peers)
	for i := range s.peers {
		s.peers[i].ApplyDefaults()
		s.peerStates[s.peers[i].FabricID] = &SyncPeerState{
			FabricID: s.peers[i].FabricID,
		}
	}

	for _, opt := range opts {
		opt(s)
	}

	s.logger.Info("revocation syncer initialized",
		"peer_count", len(s.peers),
	)

	return s
}

// Start launches a background goroutine for each peer that periodically
// compares revocation index hashes and reconciles on mismatch.
// Returns an error if the syncer has already been started.
func (s *Syncer) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("syncer already started")
	}
	s.started = true
	s.mu.Unlock()

	for _, p := range s.peers {
		s.wg.Add(1)
		go s.syncLoop(p)
	}
	return nil
}

// syncLoop runs the background reconciliation for a single peer.
func (s *Syncer) syncLoop(peer PeerSignalConfig) {
	defer s.wg.Done()

	// Initial sync.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := s.syncWithPeer(ctx, peer); err != nil {
		s.logger.Warn("sync initial reconciliation failed",
			"fabric_id", peer.FabricID, "error", err)
	}
	cancel()

	ticker := time.NewTicker(peer.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.syncWithPeer(ctx, peer); err != nil {
				s.logger.Warn("sync reconciliation failed",
					"fabric_id", peer.FabricID, "error", err)
			}
			cancel()
		}
	}
}

// syncWithPeer performs a single hash-compare-and-reconcile cycle with a peer.
func (s *Syncer) syncWithPeer(ctx context.Context, peer PeerSignalConfig) error {
	baseURL := peerBaseURL(peer.Endpoint)

	// Purge expired entries before computing hash so both sides
	// compare over the same active set (H-1 fix).
	if _, err := s.revocation.Cleanup(ctx); err != nil {
		s.logger.Warn("sync pre-hash cleanup failed",
			"fabric_id", peer.FabricID, "error", err)
	}

	// Compute local hash.
	localHash := s.revocation.Hash()

	// Fetch peer hash.
	hashURL := baseURL + "/v1/federation/revocation-hash"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hashURL, nil)
	if err != nil {
		s.recordError(peer.FabricID, fmt.Sprintf("creating hash request: %v", err))
		return fmt.Errorf("creating hash request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.recordError(peer.FabricID, fmt.Sprintf("fetching peer hash: %v", err))
		return fmt.Errorf("fetching peer hash from %s: %w", hashURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		s.recordError(peer.FabricID, fmt.Sprintf("hash endpoint returned HTTP %d", resp.StatusCode))
		return fmt.Errorf("hash endpoint %s returned HTTP %d", hashURL, resp.StatusCode)
	}

	var hashResp struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hashResp); err != nil {
		s.recordError(peer.FabricID, fmt.Sprintf("decoding hash response: %v", err))
		return fmt.Errorf("decoding hash response: %w", err)
	}

	// Update state: successful hash check.
	now := time.Now().UTC()
	s.mu.Lock()
	state := s.peerStates[peer.FabricID]
	state.SyncCount++
	state.LastSync = now
	state.LocalHash = localHash
	state.PeerHash = hashResp.Hash
	state.LastError = ""
	s.mu.Unlock()

	if s.met != nil {
		s.met.FederationSyncTotal.WithLabelValues(peer.FabricID, "ok").Inc()
		s.met.FederationRevocationLag.WithLabelValues(peer.FabricID).Set(time.Since(now).Seconds())
	}

	// If hashes match, we're consistent — nothing to do.
	if localHash == hashResp.Hash {
		s.logger.Debug("sync hashes match",
			"fabric_id", peer.FabricID,
			"hash", localHash,
		)
		return nil
	}

	// Hashes diverge — fetch full export and merge.
	s.logger.Info("sync hash mismatch, triggering full reconciliation",
		"fabric_id", peer.FabricID,
		"local_hash", localHash,
		"peer_hash", hashResp.Hash,
	)

	s.mu.Lock()
	state.MismatchCount++
	state.LastMismatch = now
	s.mu.Unlock()

	if s.met != nil {
		s.met.FederationSyncMismatchesTotal.WithLabelValues(peer.FabricID).Inc()
	}

	exportURL := baseURL + "/v1/federation/revocation-export"
	exportReq, err := http.NewRequestWithContext(ctx, http.MethodGet, exportURL, nil)
	if err != nil {
		s.recordError(peer.FabricID, fmt.Sprintf("creating export request: %v", err))
		return fmt.Errorf("creating export request: %w", err)
	}

	exportResp, err := s.client.Do(exportReq)
	if err != nil {
		s.recordError(peer.FabricID, fmt.Sprintf("fetching peer export: %v", err))
		return fmt.Errorf("fetching peer export from %s: %w", exportURL, err)
	}
	defer func() { _ = exportResp.Body.Close() }()

	if exportResp.StatusCode != http.StatusOK {
		s.recordError(peer.FabricID, fmt.Sprintf("export endpoint returned HTTP %d", exportResp.StatusCode))
		return fmt.Errorf("export endpoint %s returned HTTP %d", exportURL, exportResp.StatusCode)
	}

	// Cap import size to prevent OOM from oversized peer responses (H-2 fix).
	const maxExportSize = 10 << 20 // 10 MiB
	body, err := io.ReadAll(io.LimitReader(exportResp.Body, maxExportSize+1))
	if err != nil {
		s.recordError(peer.FabricID, fmt.Sprintf("reading export body: %v", err))
		return fmt.Errorf("reading export body: %w", err)
	}
	if int64(len(body)) > maxExportSize {
		s.recordError(peer.FabricID, "export response exceeds 10 MiB limit")
		return fmt.Errorf("export response from %s exceeds 10 MiB size limit", exportURL)
	}

	if err := s.revocation.Import(body); err != nil {
		s.recordError(peer.FabricID, fmt.Sprintf("importing revocation data: %v", err))
		return fmt.Errorf("importing revocation data: %w", err)
	}

	s.mu.Lock()
	state.FullSyncCount++
	state.LocalHash = s.revocation.Hash()
	s.mu.Unlock()

	s.logger.Info("sync full reconciliation complete",
		"fabric_id", peer.FabricID,
	)

	return nil
}

// recordError increments the error count and stores the error message.
func (s *Syncer) recordError(fabricID string, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state, ok := s.peerStates[fabricID]; ok {
		state.ErrorCount++
		state.LastError = errMsg
		if s.met != nil && !state.LastSync.IsZero() {
			s.met.FederationRevocationLag.WithLabelValues(fabricID).Set(time.Since(state.LastSync).Seconds())
		}
	}
	if s.met != nil {
		s.met.FederationSyncTotal.WithLabelValues(fabricID, "error").Inc()
	}
}

// State returns a deep copy of per-peer sync states.
func (s *Syncer) State() map[string]*SyncPeerState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]*SyncPeerState, len(s.peerStates))
	for k, v := range s.peerStates {
		cp := *v
		out[k] = &cp
	}
	return out
}

// Close stops all background sync goroutines and waits for them to exit.
// Safe to call multiple times — subsequent calls are no-ops.
func (s *Syncer) Close() error {
	s.closeOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
	return nil
}

// peerBaseURL extracts the scheme+host from a peer endpoint URL,
// stripping any path. For example:
//
//	"https://starfly-eu.example.com/v1/signals/events" → "https://starfly-eu.example.com"
//	"https://starfly-eu.example.com" → "https://starfly-eu.example.com"
func peerBaseURL(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	return u.Scheme + "://" + u.Host
}
