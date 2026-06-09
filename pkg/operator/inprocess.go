package operator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
	"github.com/starfly-fabrics/starfly/pkg/identity"
	"github.com/starfly-fabrics/starfly/pkg/signals"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// InProcessConnection implements FabricConnection by bridging directly to
// the running fabric's components. No network calls — the operator controller
// and the fabric share the same process.
type InProcessConnection struct {
	fabricID    string
	keeper      *soul.Keeper
	keyring     *exchange.Keyring
	transmitter *signals.Transmitter
	revIndex    *signals.InMemoryRevocationIndex
	registry    *identity.Registry
	trustDomains []core.TrustDomain // boot-time config (immutable)

	mu           sync.RWMutex
	desiredSpec  *soul.SoulManifest
}

// InProcessOption configures the InProcessConnection.
type InProcessOption func(*InProcessConnection)

// WithKeeper sets the soul keeper for manifest reads.
func WithKeeper(k *soul.Keeper) InProcessOption {
	return func(c *InProcessConnection) { c.keeper = k }
}

// WithKeyring sets the signing key manager.
func WithKeyring(kr *exchange.Keyring) InProcessOption {
	return func(c *InProcessConnection) { c.keyring = kr }
}

// WithTransmitter sets the SSF transmitter for stream management.
func WithTransmitter(tx *signals.Transmitter) InProcessOption {
	return func(c *InProcessConnection) { c.transmitter = tx }
}

// WithRevocationIndex sets the revocation index.
func WithRevocationIndex(ri *signals.InMemoryRevocationIndex) InProcessOption {
	return func(c *InProcessConnection) { c.revIndex = ri }
}

// WithRegistry sets the identity provider registry.
func WithRegistry(r *identity.Registry) InProcessOption {
	return func(c *InProcessConnection) { c.registry = r }
}

// WithTrustDomains sets the boot-time trust domain configuration.
func WithTrustDomains(tds []core.TrustDomain) InProcessOption {
	return func(c *InProcessConnection) { c.trustDomains = tds }
}

// NewInProcessConnection creates a FabricConnection that operates against
// in-process components. All parameters are optional — missing components
// produce partial manifests and no-op apply for unsupported action types.
func NewInProcessConnection(fabricID string, opts ...InProcessOption) *InProcessConnection {
	c := &InProcessConnection{fabricID: fabricID}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SetDesiredSpec stores the CRD desired manifest for action application.
func (c *InProcessConnection) SetDesiredSpec(spec *soul.SoulManifest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.desiredSpec = spec
}

// CurrentManifest assembles a soul manifest from the live runtime state.
func (c *InProcessConnection) CurrentManifest(_ context.Context) (*soul.SoulManifest, error) {
	seq := uint64(0)
	if c.keeper != nil {
		seq = c.keeper.Sequence()
	}

	manifest := soul.NewManifest(c.fabricID, seq)

	// Signing keys from keyring or keeper.
	if c.keyring != nil {
		activeKid := c.keyring.ActiveKid()
		manifest.Identity.SigningKeys = []soul.SigningKeyRef{
			{KID: activeKid, Status: "active", Algorithm: "RS256"},
		}
	} else if c.keeper != nil {
		manifest.Identity.SigningKeys = c.keeper.SigningKeys()
	}

	// Trust domains from keeper (runtime) falling back to boot config.
	if c.keeper != nil {
		domains := c.keeper.TrustDomains()
		if len(domains) > 0 {
			manifest.TrustDomains = domains
		}
	}
	if len(manifest.TrustDomains) == 0 {
		for _, td := range c.trustDomains {
			manifest.TrustDomains = append(manifest.TrustDomains, soul.TrustDomainSpec{
				Name:    td.Name,
				Issuer:  td.Issuer,
				JWKSURL: td.JWKSURL,
				Enabled: td.Enabled,
			})
		}
	}

	// SSF streams from transmitter.
	if c.transmitter != nil {
		for _, info := range c.transmitter.ListStreams() {
			manifest.SSFStreams = append(manifest.SSFStreams, soul.SSFStreamSpec{
				StreamID:        info.StreamID,
				Transmitter:     info.EndpointURL,
				EventsRequested: info.EventsRequested,
			})
		}
	}

	// Revocation snapshot.
	if c.revIndex != nil {
		manifest.Revocations = soul.RevocationSnapshot{
			Count:      c.revIndex.Len(),
			Hash:       c.revIndex.Hash(),
			ExportedAt: time.Now().UTC(),
		}
	}

	return manifest, nil
}

// ApplyAction executes a single convergence action against the live fabric.
// The action's Target field carries the entity identifier (kid, trust domain name,
// stream ID, etc.) as set by soul.Converge().
func (c *InProcessConnection) ApplyAction(ctx context.Context, action soul.ConvergenceAction) error {
	switch action.Type {
	case soul.ActionRotateSigningKey:
		if c.keyring == nil {
			return fmt.Errorf("keyring not configured")
		}
		if action.Target == "" {
			return fmt.Errorf("rotate_signing_key: missing target kid")
		}
		return c.keyring.ActivateKey(action.Target)

	case soul.ActionAddTrustDomain, soul.ActionUpdateTrustDomain:
		return c.applyTrustDomainChange(action)

	case soul.ActionRemoveTrustDomain:
		return c.removeTrustDomain(action.Target)

	case soul.ActionAddSSFStream:
		if c.transmitter == nil {
			return fmt.Errorf("transmitter not configured")
		}
		// Target is the audience/stream identifier from the convergence diff.
		_, err := c.transmitter.CreateStream(ctx, &core.StreamConfig{
			Audience: action.Target,
		})
		return err

	case soul.ActionRemoveSSFStream:
		if c.transmitter == nil {
			return fmt.Errorf("transmitter not configured")
		}
		if action.Target == "" {
			return fmt.Errorf("remove_ssf_stream: missing target stream_id")
		}
		return c.transmitter.DeleteStream(ctx, action.Target)

	case soul.ActionImportRevocations:
		// Import requires external data — log and skip in-process.
		slog.Info("inprocess: import_revocations acknowledged", "target", action.Target)
		return nil

	case soul.ActionResetRevocations:
		slog.Info("inprocess: reset_revocations acknowledged", "target", action.Target)
		return nil

	default:
		slog.Warn("inprocess: unknown action type", "type", action.Type)
		return nil
	}
}

// ApplyPlan delegates to ExecutePlan which handles ordering and error semantics.
func (c *InProcessConnection) ApplyPlan(ctx context.Context, plan *soul.ConvergencePlan) (*ApplyResult, error) {
	return ExecutePlan(ctx, c, plan)
}

// Health returns the current health of the in-process fabric.
func (c *InProcessConnection) Health(_ context.Context) (*HealthStatus, error) {
	h := &HealthStatus{Healthy: true}

	if c.keyring != nil {
		h.SigningKeysActive = c.keyring.Len()
	}

	h.TrustDomainsActive = len(c.currentTrustDomains())

	if c.transmitter != nil {
		h.SSFStreamsActive = c.transmitter.StreamCount()
	}

	if c.keeper != nil {
		h.SoulSequence = c.keeper.Sequence()
	}

	return h, nil
}

func (c *InProcessConnection) applyTrustDomainChange(action soul.ConvergenceAction) error {
	spec := c.lookupDesiredDomain(action.Target)
	if spec == nil {
		return fmt.Errorf("trust domain %q not found in desired spec", action.Target)
	}
	domains := c.currentTrustDomains()
	updated := false
	for i, d := range domains {
		if d.Name == action.Target {
			domains[i] = *spec
			updated = true
			break
		}
	}
	if !updated {
		domains = append(domains, *spec)
	}
	c.persistTrustDomains(domains)
	slog.Info("inprocess: trust domain applied", "type", action.Type, "target", action.Target)
	return nil
}

func (c *InProcessConnection) removeTrustDomain(name string) error {
	domains := c.currentTrustDomains()
	out := domains[:0]
	found := false
	for _, d := range domains {
		if d.Name == name {
			found = true
			continue
		}
		out = append(out, d)
	}
	if !found {
		return fmt.Errorf("trust domain %q not found", name)
	}
	c.persistTrustDomains(out)
	slog.Info("inprocess: trust domain removed", "target", name)
	return nil
}

func (c *InProcessConnection) lookupDesiredDomain(name string) *soul.TrustDomainSpec {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.desiredSpec == nil {
		return nil
	}
	for _, d := range c.desiredSpec.TrustDomains {
		if d.Name == name {
			copy := d
			return &copy
		}
	}
	return nil
}

func (c *InProcessConnection) currentTrustDomains() []soul.TrustDomainSpec {
	if c.keeper != nil {
		if domains := c.keeper.TrustDomains(); len(domains) > 0 {
			return domains
		}
	}
	out := make([]soul.TrustDomainSpec, 0, len(c.trustDomains))
	for _, td := range c.trustDomains {
		out = append(out, soul.TrustDomainSpec{
			Name:    td.Name,
			Issuer:  td.Issuer,
			JWKSURL: td.JWKSURL,
			Enabled: td.Enabled,
		})
	}
	return out
}

func (c *InProcessConnection) persistTrustDomains(domains []soul.TrustDomainSpec) {
	if c.keeper != nil {
		c.keeper.SetIdentity(c.keeper.SigningKeys(), domains)
	}
}
