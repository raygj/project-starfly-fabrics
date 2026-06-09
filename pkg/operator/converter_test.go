package operator

import (
	"testing"

	v1alpha1 "github.com/starfly-fabrics/starfly/pkg/operator/api/v1alpha1"
	"github.com/starfly-fabrics/starfly/pkg/soul"
)

func TestSpecToManifest_TrustDomains(t *testing.T) {
	spec := &v1alpha1.StarlightFabricSpec{
		TrustDomains: []v1alpha1.TrustDomainSpec{
			{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
			{Name: "k8s.internal", Type: "spiffe", Issuer: "spiffe://k8s.internal", Enabled: true},
			{Name: "legacy.disabled", Type: "oidc", Enabled: false},
		},
	}

	m := SpecToManifest("test-fabric", spec)

	if m.APIVersion != soul.APIVersionV1 {
		t.Errorf("APIVersion = %q, want %q", m.APIVersion, soul.APIVersionV1)
	}
	if m.Kind != soul.KindManifest {
		t.Errorf("Kind = %q, want %q", m.Kind, soul.KindManifest)
	}
	if m.Metadata.FabricID != "test-fabric" {
		t.Errorf("FabricID = %q, want %q", m.Metadata.FabricID, "test-fabric")
	}
	if len(m.TrustDomains) != 3 {
		t.Fatalf("TrustDomains count = %d, want 3", len(m.TrustDomains))
	}
	if m.TrustDomains[0].Name != "payments.prod" {
		t.Errorf("TrustDomains[0].Name = %q, want %q", m.TrustDomains[0].Name, "payments.prod")
	}
	if m.TrustDomains[0].JWKSURL != "" {
		t.Errorf("TrustDomains[0].JWKSURL = %q, want empty", m.TrustDomains[0].JWKSURL)
	}
	if m.TrustDomains[2].Enabled {
		t.Errorf("TrustDomains[2].Enabled = true, want false")
	}
}

func TestSpecToManifest_SigningKeys(t *testing.T) {
	spec := &v1alpha1.StarlightFabricSpec{
		SigningKeys: []v1alpha1.SigningKeySpec{
			{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:aws:kms:us-east-1:111:key/abc", Status: "active"},
			{KID: "key-002", Algorithm: "RS256", KMSKeyID: "arn:aws:kms:us-east-1:111:key/def"},
		},
	}

	m := SpecToManifest("test-fabric", spec)

	if len(m.Identity.SigningKeys) != 2 {
		t.Fatalf("SigningKeys count = %d, want 2", len(m.Identity.SigningKeys))
	}
	if m.Identity.SigningKeys[0].KID != "key-001" {
		t.Errorf("SigningKeys[0].KID = %q, want %q", m.Identity.SigningKeys[0].KID, "key-001")
	}
	// Empty status defaults to "active".
	if m.Identity.SigningKeys[1].Status != "active" {
		t.Errorf("SigningKeys[1].Status = %q, want %q", m.Identity.SigningKeys[1].Status, "active")
	}
}

func TestSpecToManifest_SSFStreams(t *testing.T) {
	spec := &v1alpha1.StarlightFabricSpec{
		SSFStreams: []v1alpha1.SSFStreamSpec{
			{StreamID: "stream-001", Transmitter: "https://ssf.example.com", EventsRequested: []string{"credential-revoked", "session-revoked"}},
		},
	}

	m := SpecToManifest("test-fabric", spec)

	if len(m.SSFStreams) != 1 {
		t.Fatalf("SSFStreams count = %d, want 1", len(m.SSFStreams))
	}
	if m.SSFStreams[0].StreamID != "stream-001" {
		t.Errorf("SSFStreams[0].StreamID = %q, want %q", m.SSFStreams[0].StreamID, "stream-001")
	}
	if len(m.SSFStreams[0].EventsRequested) != 2 {
		t.Errorf("EventsRequested count = %d, want 2", len(m.SSFStreams[0].EventsRequested))
	}
}

func TestSpecToManifest_Empty(t *testing.T) {
	spec := &v1alpha1.StarlightFabricSpec{}
	m := SpecToManifest("empty-fabric", spec)

	if m.Metadata.FabricID != "empty-fabric" {
		t.Errorf("FabricID = %q, want %q", m.Metadata.FabricID, "empty-fabric")
	}
	if len(m.TrustDomains) != 0 {
		t.Errorf("TrustDomains should be empty, got %d", len(m.TrustDomains))
	}
	if len(m.Identity.SigningKeys) != 0 {
		t.Errorf("SigningKeys should be empty, got %d", len(m.Identity.SigningKeys))
	}
}

func TestSpecToManifest_JWKSURI(t *testing.T) {
	spec := &v1alpha1.StarlightFabricSpec{
		TrustDomains: []v1alpha1.TrustDomainSpec{
			{Name: "ext", Type: "oidc", JWKSURI: "https://ext.example.com/.well-known/jwks.json", Enabled: true},
		},
	}

	m := SpecToManifest("test-fabric", spec)

	if m.TrustDomains[0].JWKSURL != "https://ext.example.com/.well-known/jwks.json" {
		t.Errorf("JWKSURL = %q, want JWKS URI mapped", m.TrustDomains[0].JWKSURL)
	}
}

func TestManifestToStatus(t *testing.T) {
	m := &soul.SoulManifest{
		Metadata: soul.Metadata{
			FabricID: "test-fabric",
			Sequence: 47,
		},
		TrustDomains: []soul.TrustDomainSpec{
			{Name: "a", Enabled: true},
			{Name: "b", Enabled: true},
			{Name: "c", Enabled: false},
		},
		Identity: soul.Identity{
			SigningKeys: []soul.SigningKeyRef{
				{KID: "key-001", Status: "active"},
				{KID: "key-002", Status: "rotated"},
				{KID: "key-003", Status: "active"},
			},
		},
		SSFStreams: []soul.SSFStreamSpec{
			{StreamID: "s1"},
			{StreamID: "s2"},
		},
	}

	status := ManifestToStatus(m)

	if status.SoulSequence != 47 {
		t.Errorf("SoulSequence = %d, want 47", status.SoulSequence)
	}
	if status.TrustDomainsActive != 2 {
		t.Errorf("TrustDomainsActive = %d, want 2", status.TrustDomainsActive)
	}
	if status.SigningKeysActive != 2 {
		t.Errorf("SigningKeysActive = %d, want 2", status.SigningKeysActive)
	}
	if status.SSFStreamsActive != 2 {
		t.Errorf("SSFStreamsActive = %d, want 2", status.SSFStreamsActive)
	}
}

func TestManifestToStatus_Empty(t *testing.T) {
	m := &soul.SoulManifest{
		Metadata: soul.Metadata{FabricID: "empty", Sequence: 1},
	}

	status := ManifestToStatus(m)

	if status.TrustDomainsActive != 0 {
		t.Errorf("TrustDomainsActive = %d, want 0", status.TrustDomainsActive)
	}
	if status.SigningKeysActive != 0 {
		t.Errorf("SigningKeysActive = %d, want 0", status.SigningKeysActive)
	}
}

func TestSpecToManifest_EventsRequestedCopied(t *testing.T) {
	events := []string{"credential-revoked"}
	spec := &v1alpha1.StarlightFabricSpec{
		SSFStreams: []v1alpha1.SSFStreamSpec{
			{StreamID: "s1", Transmitter: "https://x.com", EventsRequested: events},
		},
	}

	m := SpecToManifest("test", spec)

	// Mutate the original slice — manifest should be unaffected.
	events[0] = "MUTATED"
	if m.SSFStreams[0].EventsRequested[0] == "MUTATED" {
		t.Error("EventsRequested was not deep copied")
	}
}

func TestSpecToManifest_ConvergenceCompatible(t *testing.T) {
	// Verify the converted manifest is compatible with soul.Converge().
	spec := &v1alpha1.StarlightFabricSpec{
		TrustDomains: []v1alpha1.TrustDomainSpec{
			{Name: "new-domain", Type: "oidc", Issuer: "https://new.example.com", Enabled: true},
		},
		SigningKeys: []v1alpha1.SigningKeySpec{
			{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
		},
	}

	desired := SpecToManifest("test", spec)

	// Current state has no trust domains.
	current := soul.NewManifest("test", 1)
	current.Identity.SigningKeys = []soul.SigningKeyRef{
		{KID: "key-001", Algorithm: "ES256", KMSKeyID: "arn:key", Status: "active"},
	}

	plan, err := soul.Converge(current, desired)
	if err != nil {
		t.Fatalf("Converge() error: %v", err)
	}

	// Should have at least one action: add the trust domain.
	found := false
	for _, a := range plan.Actions {
		if a.Type == soul.ActionAddTrustDomain && a.Target == "new-domain" {
			found = true
		}
	}
	if !found {
		t.Error("Converge() did not produce ActionAddTrustDomain for 'new-domain'")
	}
}
