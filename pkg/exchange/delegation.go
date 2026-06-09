package exchange

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ErrDelegationDenied is returned when a delegation chain rule is violated.
var ErrDelegationDenied = fmt.Errorf("delegation denied")

// delegationContext holds the parsed delegation state from the actor token.
type delegationContext struct {
	// ParentSubject is the workload ID of the delegating agent.
	ParentSubject string

	// Depth is the remaining delegation depth from the parent token.
	// Zero means the parent cannot delegate further.
	Depth int

	// Caps are the parent's capabilities (what the child can request from).
	Caps []string

	// BlastRadius is the parent's blast radius constraint.
	BlastRadius string

	// OBOChain is the existing on-behalf-of chain from the parent.
	OBOChain []interface{}
}

// parseDelegationContext extracts delegation claims from a verified actor token.
func parseDelegationContext(actor jwt.Token) (*delegationContext, error) {
	sub, ok := actor.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("%w: actor token missing subject", ErrDelegationDenied)
	}

	dc := &delegationContext{
		ParentSubject: sub,
		Depth:         -1, // -1 means no depth claim (unrestricted)
	}

	// Extract delegation_depth.
	var depth float64
	if err := actor.Get("delegation_depth", &depth); err == nil {
		dc.Depth = int(depth)
	}

	// Extract caps.
	var caps []interface{}
	if err := actor.Get("caps", &caps); err == nil {
		for _, c := range caps {
			if s, ok := c.(string); ok {
				dc.Caps = append(dc.Caps, s)
			}
		}
	}

	// Extract blast_radius.
	var br string
	if err := actor.Get("blast_radius", &br); err == nil {
		dc.BlastRadius = br
	}

	// Extract existing obo chain.
	var obo []interface{}
	if err := actor.Get("obo", &obo); err == nil {
		dc.OBOChain = obo
	}

	return dc, nil
}

// validateDelegation enforces the four delegation chain rules:
//  1. Depth: parent must have depth > 0 (or unrestricted)
//  2. Caps subset: requested caps must be a subset of parent caps
//  3. Blast radius: requested radius must be equal or narrower than parent
//  4. Chain visibility: obo chain is extended (handled in caller)
func validateDelegation(dc *delegationContext, requestedCaps []string, requestedBlastRadius string) error {
	// Rule 1: Depth check.
	if dc.Depth == 0 {
		return fmt.Errorf("%w: delegation depth exhausted (parent has depth=0)", ErrDelegationDenied)
	}

	// Rule 2: Capability narrowing — requested caps must be subset of parent caps.
	if len(dc.Caps) > 0 && len(requestedCaps) > 0 {
		parentSet := make(map[string]bool, len(dc.Caps))
		for _, c := range dc.Caps {
			parentSet[c] = true
		}
		for _, c := range requestedCaps {
			if !parentSet[c] {
				return fmt.Errorf("%w: capability %q not in parent's set %v", ErrDelegationDenied, c, dc.Caps)
			}
		}
	}

	// Rule 3: Blast radius must not expand.
	if dc.BlastRadius != "" && requestedBlastRadius != "" {
		if !isBlastRadiusNarrowerOrEqual(requestedBlastRadius, dc.BlastRadius) {
			return fmt.Errorf("%w: blast radius %q exceeds parent's %q", ErrDelegationDenied, requestedBlastRadius, dc.BlastRadius)
		}
	}

	return nil
}

// blastRadiusLevels defines the hierarchy from narrowest to broadest.
// A child's blast radius must be at the same level or narrower (lower index).
var blastRadiusLevels = map[string]int{
	"function":    0,
	"service":     1,
	"namespace":   2,
	"cluster":     3,
	"workspace":   3, // alias for cluster-level
	"trust_domain": 4,
	"fabric":      5,
}

// isBlastRadiusNarrowerOrEqual returns true if child is at the same level
// or narrower than parent. If either value contains a colon (e.g., "namespace:trading"),
// the prefix before the colon is used for level comparison.
func isBlastRadiusNarrowerOrEqual(child, parent string) bool {
	childLevel, childOK := parseBlastRadiusLevel(child)
	parentLevel, parentOK := parseBlastRadiusLevel(parent)

	if !childOK || !parentOK {
		// Unknown levels: exact match only.
		return child == parent
	}

	return childLevel <= parentLevel
}

// parseBlastRadiusLevel extracts the level from a blast radius string.
// Supports both "namespace" and "namespace:trading" formats.
func parseBlastRadiusLevel(br string) (int, bool) {
	// Check for prefix:qualifier format.
	for i, ch := range br {
		if ch == ':' {
			level, ok := blastRadiusLevels[br[:i]]
			return level, ok
		}
	}
	level, ok := blastRadiusLevels[br]
	return level, ok
}

// buildOBOChain constructs the new obo chain by appending the parent's subject.
func buildOBOChain(dc *delegationContext) []interface{} {
	chain := make([]interface{}, 0, len(dc.OBOChain)+1)
	chain = append(chain, dc.OBOChain...)
	chain = append(chain, dc.ParentSubject)
	return chain
}
