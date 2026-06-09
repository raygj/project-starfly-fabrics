package soul

import (
	"context"
	"fmt"
	"log/slog"
)

// ActionType describes a convergence action.
type ActionType string

const (
	ActionAddTrustDomain    ActionType = "add_trust_domain"
	ActionRemoveTrustDomain ActionType = "remove_trust_domain"
	ActionUpdateTrustDomain ActionType = "update_trust_domain"
	ActionRotateSigningKey  ActionType = "rotate_signing_key"
	ActionImportRevocations ActionType = "import_revocations"
	ActionResetRevocations  ActionType = "reset_revocations"
	ActionAddSSFStream      ActionType = "add_ssf_stream"
	ActionRemoveSSFStream   ActionType = "remove_ssf_stream"
	ActionAddPeer           ActionType = "add_peer"
	ActionRemovePeer        ActionType = "remove_peer"
)

// ConvergenceAction is a single step in a convergence plan.
type ConvergenceAction struct {
	Type        ActionType `json:"type"`
	Description string     `json:"description"`
	Target      string     `json:"target,omitempty"` // e.g. trust domain name, key KID
}

// ConvergencePlan is the set of actions needed to converge from current to spec.
type ConvergencePlan struct {
	Actions []ConvergenceAction
}

// IsEmpty returns true if no convergence actions are needed.
func (p *ConvergencePlan) IsEmpty() bool {
	return len(p.Actions) == 0
}

// ConvergenceOption configures convergence behavior.
type ConvergenceOption func(*convergenceConfig)

type convergenceConfig struct {
	importRevocations bool
}

// WithImportRevocations controls whether revocations from the snapshot
// are carried forward (true) or reset (false) during upgrade.
func WithImportRevocations(v bool) ConvergenceOption {
	return func(c *convergenceConfig) { c.importRevocations = v }
}

// Converge compares current state (snapshot from anchor) against desired state
// (spec from git/Helm) and produces a plan of actions to converge.
//
// The merge rule: configured state (spec) always wins over earned state (current).
func Converge(current *SoulManifest, spec *SoulManifest, opts ...ConvergenceOption) (*ConvergencePlan, error) {
	cfg := &convergenceConfig{importRevocations: true} // default: carry forward
	for _, opt := range opts {
		opt(cfg)
	}

	plan := &ConvergencePlan{}

	// Trust domain convergence.
	convergeTrustDomains(current, spec, plan)

	// Signing key convergence.
	convergeSigningKeys(current, spec, plan)

	// SSF stream convergence.
	convergeSSFStreams(current, spec, plan)

	// Federation peer convergence.
	convergeFederationPeers(current, spec, plan)

	// Revocation handling.
	if cfg.importRevocations {
		if current != nil && current.Revocations.Count > 0 {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionImportRevocations,
				Description: fmt.Sprintf("import %d revocations from snapshot", current.Revocations.Count),
			})
		}
	} else {
		plan.Actions = append(plan.Actions, ConvergenceAction{
			Type:        ActionResetRevocations,
			Description: "reset revocation index (clean start)",
		})
	}

	return plan, nil
}

func convergeTrustDomains(current, spec *SoulManifest, plan *ConvergencePlan) {
	currentDomains := make(map[string]TrustDomainSpec)
	if current != nil {
		for _, d := range current.TrustDomains {
			currentDomains[d.Name] = d
		}
	}

	specDomains := make(map[string]TrustDomainSpec)
	if spec != nil {
		for _, d := range spec.TrustDomains {
			specDomains[d.Name] = d
		}
	}

	// Add or update domains in spec.
	for name, specDomain := range specDomains {
		curDomain, exists := currentDomains[name]
		if !exists {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionAddTrustDomain,
				Description: fmt.Sprintf("add trust domain %q", name),
				Target:      name,
			})
		} else if domainChanged(curDomain, specDomain) {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionUpdateTrustDomain,
				Description: fmt.Sprintf("update trust domain %q", name),
				Target:      name,
			})
		}
	}

	// Remove domains not in spec.
	for name := range currentDomains {
		if _, inSpec := specDomains[name]; !inSpec {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionRemoveTrustDomain,
				Description: fmt.Sprintf("remove trust domain %q", name),
				Target:      name,
			})
		}
	}
}

func domainChanged(a, b TrustDomainSpec) bool {
	return a.Enabled != b.Enabled || a.Issuer != b.Issuer || a.JWKSURL != b.JWKSURL || a.Type != b.Type
}

func convergeSigningKeys(current, spec *SoulManifest, plan *ConvergencePlan) {
	currentKeys := make(map[string]SigningKeyRef)
	if current != nil {
		for _, k := range current.Identity.SigningKeys {
			currentKeys[k.KID] = k
		}
	}

	specKeys := make(map[string]SigningKeyRef)
	if spec != nil {
		for _, k := range spec.Identity.SigningKeys {
			specKeys[k.KID] = k
		}
	}

	// Check for new or changed keys in spec.
	for kid, specKey := range specKeys {
		curKey, exists := currentKeys[kid]
		if !exists || curKey.KMSKeyID != specKey.KMSKeyID || curKey.Status != specKey.Status {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionRotateSigningKey,
				Description: fmt.Sprintf("rotate signing key %q (status: %s)", kid, specKey.Status),
				Target:      kid,
			})
		}
	}
}

func convergeSSFStreams(current, spec *SoulManifest, plan *ConvergencePlan) {
	currentStreams := make(map[string]SSFStreamSpec)
	if current != nil {
		for _, s := range current.SSFStreams {
			currentStreams[s.StreamID] = s
		}
	}

	specStreams := make(map[string]SSFStreamSpec)
	if spec != nil {
		for _, s := range spec.SSFStreams {
			specStreams[s.StreamID] = s
		}
	}

	for id := range specStreams {
		if _, exists := currentStreams[id]; !exists {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionAddSSFStream,
				Description: fmt.Sprintf("add SSF stream %q", id),
				Target:      id,
			})
		}
	}

	for id := range currentStreams {
		if _, inSpec := specStreams[id]; !inSpec {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionRemoveSSFStream,
				Description: fmt.Sprintf("remove SSF stream %q", id),
				Target:      id,
			})
		}
	}
}

func convergeFederationPeers(current, spec *SoulManifest, plan *ConvergencePlan) {
	currentPeers := make(map[string]FederationPeer)
	if current != nil {
		for _, p := range current.Federation.Peers {
			currentPeers[p.FabricID] = p
		}
	}

	specPeers := make(map[string]FederationPeer)
	if spec != nil {
		for _, p := range spec.Federation.Peers {
			specPeers[p.FabricID] = p
		}
	}

	for id := range specPeers {
		if _, exists := currentPeers[id]; !exists {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionAddPeer,
				Description: fmt.Sprintf("add federation peer %q", id),
				Target:      id,
			})
		}
	}

	for id := range currentPeers {
		if _, inSpec := specPeers[id]; !inSpec {
			plan.Actions = append(plan.Actions, ConvergenceAction{
				Type:        ActionRemovePeer,
				Description: fmt.Sprintf("remove federation peer %q", id),
				Target:      id,
			})
		}
	}
}

// LogPlan logs the convergence plan at info level.
func LogPlan(plan *ConvergencePlan) {
	if plan.IsEmpty() {
		slog.Info("convergence plan: no actions needed")
		return
	}
	slog.Info("convergence plan", "action_count", len(plan.Actions))
	for i, a := range plan.Actions {
		slog.Info("convergence action",
			"index", i,
			"type", a.Type,
			"description", a.Description,
			"target", a.Target,
		)
	}
}

// Apply executes a convergence plan. Currently logs actions — actual
// execution hooks will be wired when the corresponding subsystems
// (key manager, registry, SSF streams) expose mutation interfaces.
func Apply(_ context.Context, plan *ConvergencePlan) error {
	if plan.IsEmpty() {
		return nil
	}
	LogPlan(plan)
	// Actual execution will be wired in Phase 8 integration.
	// For now, the plan is produced and logged — callers inspect it.
	return nil
}
