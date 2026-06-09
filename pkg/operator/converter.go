package operator

import (
	"time"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

// SpecToManifest converts a StarlightFabricSpec into a SoulManifest.
// The fabricID comes from the CR's metadata.name. The sequence is set to 0
// (the controller compares against the current manifest's sequence, not the spec's).
func SpecToManifest(fabricID string, spec *v1alpha1.StarlightFabricSpec) *soul.SoulManifest {
	m := &soul.SoulManifest{
		APIVersion: soul.APIVersionV1,
		Kind:       soul.KindManifest,
		Metadata: soul.Metadata{
			FabricID:    fabricID,
			GeneratedAt: time.Now().UTC(),
			Sequence:    0, // spec doesn't declare sequence; convergence ignores it
		},
	}

	// Convert trust domains.
	for _, td := range spec.TrustDomains {
		m.TrustDomains = append(m.TrustDomains, soul.TrustDomainSpec{
			Name:    td.Name,
			Type:    td.Type,
			Issuer:  td.Issuer,
			JWKSURL: td.JWKSURI,
			Enabled: td.Enabled,
		})
	}

	// Convert signing keys.
	for _, sk := range spec.SigningKeys {
		status := sk.Status
		if status == "" {
			status = "active"
		}
		m.Identity.SigningKeys = append(m.Identity.SigningKeys, soul.SigningKeyRef{
			KID:       sk.KID,
			Algorithm: sk.Algorithm,
			KMSKeyID:  sk.KMSKeyID,
			Status:    status,
		})
	}

	// Convert SSF streams.
	for _, ss := range spec.SSFStreams {
		events := make([]string, len(ss.EventsRequested))
		copy(events, ss.EventsRequested)
		m.SSFStreams = append(m.SSFStreams, soul.SSFStreamSpec{
			StreamID:        ss.StreamID,
			Transmitter:     ss.Transmitter,
			EventsRequested: events,
		})
	}

	// Convert federation peers.
	if spec.Federation != nil {
		for _, fp := range spec.Federation.Peers {
			m.Federation.Peers = append(m.Federation.Peers, soul.FederationPeer{
				FabricID: fp.FabricID,
			})
		}
	}

	return m
}

// ManifestToStatus extracts status fields from a SoulManifest.
func ManifestToStatus(m *soul.SoulManifest) v1alpha1.StarlightFabricStatus {
	status := v1alpha1.StarlightFabricStatus{
		SoulSequence: int64(m.Metadata.Sequence),
	}

	// Count active trust domains.
	for _, td := range m.TrustDomains {
		if td.Enabled {
			status.TrustDomainsActive++
		}
	}

	// Count active signing keys.
	for _, sk := range m.Identity.SigningKeys {
		if sk.Status == "active" {
			status.SigningKeysActive++
		}
	}

	// Count SSF streams.
	status.SSFStreamsActive = len(m.SSFStreams)

	// Count federation peers.
	status.FederationPeersTotal = len(m.Federation.Peers)

	return status
}
