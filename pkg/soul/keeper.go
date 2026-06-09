package soul

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/metrics"
)

// RevocationExporter is the interface the Keeper uses to snapshot the revocation index.
// This avoids importing pkg/signals directly.
type RevocationExporter interface {
	Export() ([]byte, error)
	Hash() string
	Len() int
}

// KeeperConfig configures the Soul Keeper.
type KeeperConfig struct {
	FabricID string
	Anchor   Anchor
	RevIndex RevocationExporter
	Bus      core.SyncBus // optional — nil if NATS not available
	Interval time.Duration
	UnitID   string
	Metrics  *metrics.Metrics // optional — nil disables metric updates
	// OnSnapshot is called after each successful snapshot (e.g. to broadcast SSE events).
	OnSnapshot func(fabricID string, seq uint64)
}

// Keeper periodically snapshots the fabric's soul state to an external anchor.
type Keeper struct {
	fabricID   string
	anchor     Anchor
	revIndex   RevocationExporter
	bus        core.SyncBus
	interval   time.Duration
	unitID     string
	sequence   atomic.Uint64
	met        *metrics.Metrics
	onSnapshot func(fabricID string, seq uint64)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// signingKeys and trustDomains are set via SetIdentity.
	mu           sync.RWMutex
	signingKeys  []SigningKeyRef
	trustDomains []TrustDomainSpec
	auditState   AuditState
}

// NewKeeper creates a new Soul Keeper. Call Start to begin periodic snapshots.
func NewKeeper(cfg KeeperConfig) (*Keeper, error) {
	if cfg.FabricID == "" {
		return nil, fmt.Errorf("fabricID is required")
	}
	if cfg.Anchor == nil {
		return nil, fmt.Errorf("anchor is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.UnitID == "" {
		cfg.UnitID = "unknown"
	}

	k := &Keeper{
		fabricID:   cfg.FabricID,
		anchor:     cfg.Anchor,
		revIndex:   cfg.RevIndex,
		bus:        cfg.Bus,
		interval:   cfg.Interval,
		unitID:     cfg.UnitID,
		met:        cfg.Metrics,
		onSnapshot: cfg.OnSnapshot,
	}
	return k, nil
}

// SetIdentity updates the configured identity state (signing keys, trust domains).
func (k *Keeper) SetIdentity(keys []SigningKeyRef, domains []TrustDomainSpec) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.signingKeys = keys
	k.trustDomains = domains
	if k.met != nil {
		k.met.FabricTrustDomainsTotal.Set(float64(len(domains)))
	}
}

// TrustDomains returns a copy of configured trust domains.
func (k *Keeper) TrustDomains() []TrustDomainSpec {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]TrustDomainSpec, len(k.trustDomains))
	copy(out, k.trustDomains)
	return out
}

// SigningKeys returns a copy of configured signing keys.
func (k *Keeper) SigningKeys() []SigningKeyRef {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]SigningKeyRef, len(k.signingKeys))
	copy(out, k.signingKeys)
	return out
}

// SetAuditState updates the audit buffer state.
func (k *Keeper) SetAuditState(state AuditState) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.auditState = state
}

// Sequence returns the current snapshot sequence number.
func (k *Keeper) Sequence() uint64 {
	return k.sequence.Load()
}

// Start begins periodic snapshots in a background goroutine.
func (k *Keeper) Start(ctx context.Context) {
	k.ctx, k.cancel = context.WithCancel(ctx)

	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		k.run()
	}()

	slog.Info("soul keeper started",
		"fabric_id", k.fabricID,
		"interval", k.interval,
		"unit_id", k.unitID,
	)
}

// Stop performs a final snapshot and shuts down the keeper.
func (k *Keeper) Stop() error {
	if k.cancel != nil {
		k.cancel()
	}
	k.wg.Wait()

	// Final snapshot on shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := k.Snapshot(ctx); err != nil {
		slog.Error("final soul snapshot failed", "error", err)
		return err
	}
	slog.Info("soul keeper stopped", "fabric_id", k.fabricID, "final_sequence", k.sequence.Load())
	return nil
}

// run is the background loop that snapshots on interval.
func (k *Keeper) run() {
	ticker := time.NewTicker(k.interval)
	defer ticker.Stop()

	for {
		select {
		case <-k.ctx.Done():
			return
		case <-ticker.C:
			if err := k.Snapshot(k.ctx); err != nil {
				slog.Error("soul snapshot failed", "error", err, "fabric_id", k.fabricID)
				if k.met != nil {
					k.met.SoulAnchorReachable.Set(0)
				}
			}
		}
	}
}

// Snapshot performs an immediate soul snapshot to the anchor.
// Safe to call from outside the keeper (e.g., on significant events).
func (k *Keeper) Snapshot(ctx context.Context) error {
	start := time.Now()
	seq := k.sequence.Add(1)

	// Check for split-brain before writing.
	existing, err := k.anchor.ReadManifest(ctx, k.fabricID)
	if err == nil && existing != nil {
		if existing.Metadata.Sequence >= seq {
			slog.Warn("SPLIT-BRAIN DETECTED: anchor has higher sequence than local",
				"anchor_sequence", existing.Metadata.Sequence,
				"local_sequence", seq,
				"fabric_id", k.fabricID,
			)
		}
	}

	// Build the manifest.
	k.mu.RLock()
	manifest := NewManifest(k.fabricID, seq)
	manifest.Identity.SigningKeys = k.signingKeys
	manifest.TrustDomains = k.trustDomains
	manifest.Audit = k.auditState
	k.mu.RUnlock()

	// Snapshot revocation index.
	if k.revIndex != nil {
		manifest.Revocations = RevocationSnapshot{
			Count:      k.revIndex.Len(),
			Hash:       k.revIndex.Hash(),
			ExportedAt: time.Now().UTC(),
		}

		revData, err := k.revIndex.Export()
		if err != nil {
			return fmt.Errorf("exporting revocation index: %w", err)
		}
		if err := k.anchor.WriteRevocationSnapshot(ctx, k.fabricID, revData); err != nil {
			return fmt.Errorf("writing revocation snapshot: %w", err)
		}
	}

	// Write manifest.
	if err := k.anchor.WriteManifest(ctx, manifest); err != nil {
		return fmt.Errorf("writing soul manifest: %w", err)
	}

	slog.Info("soul snapshot written",
		"fabric_id", k.fabricID,
		"sequence", seq,
		"revocation_count", manifest.Revocations.Count,
	)

	// Update Prometheus gauges.
	if k.met != nil {
		k.met.SoulManifestSequence.Set(float64(seq))
		k.met.SoulAnchorReachable.Set(1)
		k.met.SoulAnchorAgeSeconds.Set(0) // just written — age is 0
		k.mu.RLock()
		k.met.FabricTrustDomainsTotal.Set(float64(len(k.trustDomains)))
		k.mu.RUnlock()
	}

	// Notify SSE broadcaster.
	if k.onSnapshot != nil {
		k.onSnapshot(k.fabricID, seq)
	}

	// Flash signal on NATS (if available).
	if k.bus != nil {
		sig := &core.Signal{
			Type: "fabric.soul",
			Payload: map[string]interface{}{
				"fabric_id":        k.fabricID,
				"sequence":         seq,
				"revocation_count": manifest.Revocations.Count,
			},
		}
		if err := k.bus.Flash(ctx, sig); err != nil {
			slog.Warn("failed to flash soul snapshot signal", "error", err)
			// Non-fatal — snapshot was already written.
		}
	}

	if k.met != nil {
		k.met.SoulSnapshotDurationSeconds.Observe(time.Since(start).Seconds())
	}

	return nil
}
