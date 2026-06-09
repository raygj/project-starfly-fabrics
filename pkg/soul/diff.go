package soul

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DiffType classifies how an entity changed between two manifests.
type DiffType string

const (
	DiffAdded   DiffType = "added"
	DiffRemoved DiffType = "removed"
	DiffChanged DiffType = "changed"
)

// DiffEntry describes a single change between two soul manifests.
type DiffEntry struct {
	Type     DiffType `json:"type"`
	Category string   `json:"category"` // "trust_domain", "signing_key", "ssf_stream", "revocation", "audit", "metadata"
	Name     string   `json:"name"`     // entity identifier
	Detail   string   `json:"detail"`   // human-readable change description
}

// SoulDiff captures the full set of changes between two manifest versions.
type SoulDiff struct {
	FromSequence uint64      `json:"from_sequence"`
	ToSequence   uint64      `json:"to_sequence"`
	Changes      []DiffEntry `json:"changes"`
}

// Diff compares two soul manifests and returns the changes.
// Either manifest may be nil (representing empty/nonexistent state).
func Diff(from, to *SoulManifest) *SoulDiff {
	d := &SoulDiff{}

	if from != nil {
		d.FromSequence = from.Metadata.Sequence
	}
	if to != nil {
		d.ToSequence = to.Metadata.Sequence
	}

	// Handle nil cases.
	if from == nil && to == nil {
		return d
	}

	if from == nil {
		from = &SoulManifest{}
	}
	if to == nil {
		to = &SoulManifest{}
	}

	// Metadata: warn if FabricID differs (and both are non-empty).
	if from.Metadata.FabricID != "" && to.Metadata.FabricID != "" &&
		from.Metadata.FabricID != to.Metadata.FabricID {
		d.Changes = append(d.Changes, DiffEntry{
			Type:     DiffChanged,
			Category: "metadata",
			Name:     "fabricId",
			Detail:   fmt.Sprintf("WARNING: fabricId changed: %s -> %s", from.Metadata.FabricID, to.Metadata.FabricID),
		})
	}

	// Trust domains: compare by Name.
	diffTrustDomains(from.TrustDomains, to.TrustDomains, d)

	// Signing keys: compare by KID.
	diffSigningKeys(from.Identity.SigningKeys, to.Identity.SigningKeys, d)

	// SSF streams: compare by StreamID.
	diffSSFStreams(from.SSFStreams, to.SSFStreams, d)

	// Federation peers: compare by FabricID.
	diffFederationPeers(from.Federation.Peers, to.Federation.Peers, d)

	// Revocations: compare Count.
	diffRevocations(from.Revocations, to.Revocations, d)

	// Audit: compare LastFlushedSequence.
	diffAudit(from.Audit, to.Audit, d)

	return d
}

func diffTrustDomains(from, to []TrustDomainSpec, d *SoulDiff) {
	fromMap := make(map[string]TrustDomainSpec, len(from))
	for _, td := range from {
		fromMap[td.Name] = td
	}
	toMap := make(map[string]TrustDomainSpec, len(to))
	for _, td := range to {
		toMap[td.Name] = td
	}

	// Added and changed.
	for _, td := range to {
		old, exists := fromMap[td.Name]
		if !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffAdded,
				Category: "trust_domain",
				Name:     td.Name,
				Detail:   fmt.Sprintf("type: %s, issuer: %s", td.Type, td.Issuer),
			})
			continue
		}
		// Check for changes.
		var changes []string
		if old.Issuer != td.Issuer {
			changes = append(changes, fmt.Sprintf("issuer: %s -> %s", old.Issuer, td.Issuer))
		}
		if old.Type != td.Type {
			changes = append(changes, fmt.Sprintf("type: %s -> %s", old.Type, td.Type))
		}
		if old.Enabled != td.Enabled {
			changes = append(changes, fmt.Sprintf("enabled: %v -> %v", old.Enabled, td.Enabled))
		}
		if old.JWKSURL != td.JWKSURL {
			changes = append(changes, fmt.Sprintf("jwksUrl: %s -> %s", old.JWKSURL, td.JWKSURL))
		}
		if len(changes) > 0 {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffChanged,
				Category: "trust_domain",
				Name:     td.Name,
				Detail:   strings.Join(changes, ", "),
			})
		}
	}

	// Removed.
	for _, td := range from {
		if _, exists := toMap[td.Name]; !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffRemoved,
				Category: "trust_domain",
				Name:     td.Name,
				Detail:   fmt.Sprintf("type: %s, issuer: %s", td.Type, td.Issuer),
			})
		}
	}
}

func diffSigningKeys(from, to []SigningKeyRef, d *SoulDiff) {
	fromMap := make(map[string]SigningKeyRef, len(from))
	for _, k := range from {
		fromMap[k.KID] = k
	}
	toMap := make(map[string]SigningKeyRef, len(to))
	for _, k := range to {
		toMap[k.KID] = k
	}

	// Added and changed.
	for _, k := range to {
		old, exists := fromMap[k.KID]
		if !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffAdded,
				Category: "signing_key",
				Name:     k.KID,
				Detail:   fmt.Sprintf("algorithm: %s, status: %s", k.Algorithm, k.Status),
			})
			continue
		}
		var changes []string
		if old.Status != k.Status {
			changes = append(changes, fmt.Sprintf("status: %s -> %s", old.Status, k.Status))
		}
		if old.KMSKeyID != k.KMSKeyID {
			changes = append(changes, fmt.Sprintf("kmsKeyId: %s -> %s", old.KMSKeyID, k.KMSKeyID))
		}
		if old.Algorithm != k.Algorithm {
			changes = append(changes, fmt.Sprintf("algorithm: %s -> %s", old.Algorithm, k.Algorithm))
		}
		if len(changes) > 0 {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffChanged,
				Category: "signing_key",
				Name:     k.KID,
				Detail:   strings.Join(changes, ", "),
			})
		}
	}

	// Removed.
	for _, k := range from {
		if _, exists := toMap[k.KID]; !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffRemoved,
				Category: "signing_key",
				Name:     k.KID,
				Detail:   fmt.Sprintf("algorithm: %s, status: %s", k.Algorithm, k.Status),
			})
		}
	}
}

func diffSSFStreams(from, to []SSFStreamSpec, d *SoulDiff) {
	fromMap := make(map[string]SSFStreamSpec, len(from))
	for _, s := range from {
		fromMap[s.StreamID] = s
	}
	toMap := make(map[string]SSFStreamSpec, len(to))
	for _, s := range to {
		toMap[s.StreamID] = s
	}

	// Added.
	for _, s := range to {
		if _, exists := fromMap[s.StreamID]; !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffAdded,
				Category: "ssf_stream",
				Name:     s.StreamID,
				Detail:   fmt.Sprintf("transmitter: %s", s.Transmitter),
			})
		}
	}

	// Removed.
	for _, s := range from {
		if _, exists := toMap[s.StreamID]; !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffRemoved,
				Category: "ssf_stream",
				Name:     s.StreamID,
				Detail:   fmt.Sprintf("transmitter: %s", s.Transmitter),
			})
		}
	}
}

func diffFederationPeers(from, to []FederationPeer, d *SoulDiff) {
	fromMap := make(map[string]FederationPeer, len(from))
	for _, p := range from {
		fromMap[p.FabricID] = p
	}
	toMap := make(map[string]FederationPeer, len(to))
	for _, p := range to {
		toMap[p.FabricID] = p
	}

	for _, p := range to {
		old, exists := fromMap[p.FabricID]
		if !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffAdded,
				Category: "federation_peer",
				Name:     p.FabricID,
				Detail:   fmt.Sprintf("keyCount: %d", p.KeyCount),
			})
			continue
		}
		var changes []string
		if old.KeyCount != p.KeyCount {
			changes = append(changes, fmt.Sprintf("keyCount: %d -> %d", old.KeyCount, p.KeyCount))
		}
		if old.RevocationHash != p.RevocationHash {
			changes = append(changes, "revocationHash changed")
		}
		if len(changes) > 0 {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffChanged,
				Category: "federation_peer",
				Name:     p.FabricID,
				Detail:   strings.Join(changes, ", "),
			})
		}
	}

	for _, p := range from {
		if _, exists := toMap[p.FabricID]; !exists {
			d.Changes = append(d.Changes, DiffEntry{
				Type:     DiffRemoved,
				Category: "federation_peer",
				Name:     p.FabricID,
				Detail:   fmt.Sprintf("keyCount: %d", p.KeyCount),
			})
		}
	}
}

func diffRevocations(from, to RevocationSnapshot, d *SoulDiff) {
	if from.Count != to.Count {
		delta := to.Count - from.Count
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		d.Changes = append(d.Changes, DiffEntry{
			Type:     DiffChanged,
			Category: "revocation",
			Name:     "count",
			Detail:   fmt.Sprintf("count %d -> %d (%s%d)", from.Count, to.Count, sign, delta),
		})
	}
}

func diffAudit(from, to AuditState, d *SoulDiff) {
	if from.LastFlushedSequence != to.LastFlushedSequence {
		delta := int64(to.LastFlushedSequence) - int64(from.LastFlushedSequence)
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		d.Changes = append(d.Changes, DiffEntry{
			Type:     DiffChanged,
			Category: "audit",
			Name:     "sequence",
			Detail:   fmt.Sprintf("sequence %d -> %d (%s%d)", from.LastFlushedSequence, to.LastFlushedSequence, sign, delta),
		})
	}
}

// IsEmpty returns true if there are no changes.
func (d *SoulDiff) IsEmpty() bool {
	return len(d.Changes) == 0
}

// Format returns a human-readable changelog string.
func (d *SoulDiff) Format() string {
	if d.IsEmpty() {
		return "No changes."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Changes: seq %d -> seq %d\n", d.FromSequence, d.ToSequence)

	for _, c := range d.Changes {
		var prefix string
		switch c.Type {
		case DiffAdded:
			prefix = "+"
		case DiffRemoved:
			prefix = "-"
		case DiffChanged:
			prefix = "~"
		}
		if c.Detail != "" {
			fmt.Fprintf(&b, "  %s %s: %s (%s)\n", prefix, c.Category, c.Name, c.Detail)
		} else {
			fmt.Fprintf(&b, "  %s %s: %s\n", prefix, c.Category, c.Name)
		}
	}

	return b.String()
}

// FormatJSON returns the diff as indented JSON.
func (d *SoulDiff) FormatJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
