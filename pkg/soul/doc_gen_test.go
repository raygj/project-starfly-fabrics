package soul

import (
	"strings"
	"testing"
	"time"
)

func docTestManifest() *SoulManifest {
	return &SoulManifest{
		APIVersion: APIVersionV1,
		Kind:       KindManifest,
		Metadata: Metadata{
			FabricID:    "test-fabric-001",
			GeneratedAt: time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC),
			Sequence:    42,
		},
		Identity: Identity{
			SigningKeys: []SigningKeyRef{
				{KMSKeyID: "arn:aws:kms:us-east-1:123:key/abc", Algorithm: "ES256", KID: "key-1", Status: "active"},
				{KMSKeyID: "arn:aws:kms:us-east-1:123:key/def", Algorithm: "RS256", KID: "key-2", Status: "rotated"},
			},
		},
		TrustDomains: []TrustDomainSpec{
			{Name: "corp.example.com", Type: "oidc", Issuer: "https://idp.example.com", Enabled: true},
			{Name: "staging.internal", Type: "spiffe", Issuer: "spiffe://staging.internal", Enabled: false},
		},
		Revocations: RevocationSnapshot{
			Count:      15,
			Hash:       "sha256:abcdef1234567890",
			ExportedAt: time.Date(2026, 3, 7, 11, 0, 0, 0, time.UTC),
		},
		SSFStreams: []SSFStreamSpec{
			{StreamID: "stream-001", Transmitter: "https://ssf.example.com", EventsRequested: []string{"credential-revoked", "session-revoked"}},
		},
		Audit: AuditState{
			LastFlushedSequence: 100,
		},
	}
}

func TestGenerateTopology_IncludesAllDomains(t *testing.T) {
	m := docTestManifest()
	out := GenerateTopology(m)

	// Check header.
	if !strings.Contains(out, "# Fabric Topology") {
		t.Error("missing topology header")
	}

	// Metadata.
	if !strings.Contains(out, "test-fabric-001") {
		t.Error("missing fabric ID")
	}
	if !strings.Contains(out, "42") {
		t.Error("missing sequence")
	}

	// Trust domains.
	if !strings.Contains(out, "corp.example.com") {
		t.Error("missing trust domain corp.example.com")
	}
	if !strings.Contains(out, "staging.internal") {
		t.Error("missing trust domain staging.internal")
	}
	if !strings.Contains(out, "oidc") {
		t.Error("missing type oidc")
	}
	if !strings.Contains(out, "spiffe") {
		t.Error("missing type spiffe")
	}

	// Signing keys.
	if !strings.Contains(out, "key-1") {
		t.Error("missing signing key key-1")
	}
	if !strings.Contains(out, "key-2") {
		t.Error("missing signing key key-2")
	}
	if !strings.Contains(out, "ES256") {
		t.Error("missing algorithm ES256")
	}
	if !strings.Contains(out, "RS256") {
		t.Error("missing algorithm RS256")
	}

	// SSF streams.
	if !strings.Contains(out, "stream-001") {
		t.Error("missing SSF stream")
	}
	if !strings.Contains(out, "credential-revoked") {
		t.Error("missing event type")
	}

	// Revocations.
	if !strings.Contains(out, "15") {
		t.Error("missing revocation count")
	}
	if !strings.Contains(out, "sha256:abcdef1234567890") {
		t.Error("missing revocation hash")
	}
}

func TestGenerateRunbook_IncludesRecovery(t *testing.T) {
	m := docTestManifest()
	out := GenerateRunbook(m)

	if !strings.Contains(out, "# Operational Runbook") {
		t.Error("missing runbook header")
	}
	if !strings.Contains(out, "## Recovery") {
		t.Error("missing recovery section")
	}
	if !strings.Contains(out, "restore from FSAnchor and reimport revocation index") {
		t.Error("missing recovery instructions")
	}
	if !strings.Contains(out, "test-fabric-001") {
		t.Error("missing fabric ID in runbook")
	}
}

func TestGenerateRunbook_ListsTrustDomains(t *testing.T) {
	m := docTestManifest()
	out := GenerateRunbook(m)

	if !strings.Contains(out, "corp.example.com") {
		t.Error("missing trust domain in runbook")
	}
	if !strings.Contains(out, "ENABLED") {
		t.Error("missing ENABLED status")
	}
	if !strings.Contains(out, "DISABLED") {
		t.Error("missing DISABLED status")
	}
}

func TestGenerateRunbook_KeyRotation(t *testing.T) {
	m := docTestManifest()
	out := GenerateRunbook(m)

	if !strings.Contains(out, "### Active Keys") {
		t.Error("missing active keys section")
	}
	if !strings.Contains(out, "### Rotated / Revoked Keys") {
		t.Error("missing rotated keys section")
	}
	if !strings.Contains(out, "key-1") {
		t.Error("missing active key key-1")
	}
	if !strings.Contains(out, "key-2") {
		t.Error("missing rotated key key-2")
	}
}

func TestGenerateChangelog_UsesDiff(t *testing.T) {
	from := docTestManifest()
	to := docTestManifest()
	to.Metadata.Sequence = 43
	to.TrustDomains = append(to.TrustDomains, TrustDomainSpec{
		Name: "new-domain.io", Type: "aws-sts", Issuer: "arn:aws:iam::123", Enabled: true,
	})

	diff := Diff(from, to)
	out := GenerateChangelog(diff)

	if !strings.Contains(out, "# Changelog") {
		t.Error("missing changelog header")
	}
	if !strings.Contains(out, "42 -> 43") {
		t.Error("missing sequence range")
	}
	if !strings.Contains(out, "new-domain.io") {
		t.Error("missing added domain in changelog")
	}
}

func TestGenerateChangelog_EmptyDiff(t *testing.T) {
	diff := &SoulDiff{}
	out := GenerateChangelog(diff)

	if !strings.Contains(out, "# Changelog") {
		t.Error("missing changelog header")
	}
	if !strings.Contains(out, "No changes.") {
		t.Error("missing 'No changes.' for empty diff")
	}
}

func TestGenerateTopology_NilManifest(t *testing.T) {
	out := GenerateTopology(nil)
	if !strings.Contains(out, "No manifest data available") {
		t.Error("nil manifest should produce 'no data' message")
	}
}

func TestGenerateRunbook_NilManifest(t *testing.T) {
	out := GenerateRunbook(nil)
	if !strings.Contains(out, "No manifest data available") {
		t.Error("nil manifest should produce 'no data' message")
	}
}

func TestGenerateChangelog_NilDiff(t *testing.T) {
	out := GenerateChangelog(nil)
	if !strings.Contains(out, "No diff data available") {
		t.Error("nil diff should produce 'no data' message")
	}
}

func TestGenerateTopology_MinimalManifest(t *testing.T) {
	m := &SoulManifest{
		Metadata: Metadata{FabricID: "minimal"},
	}
	out := GenerateTopology(m)

	if !strings.Contains(out, "minimal") {
		t.Error("missing fabric ID")
	}
	if !strings.Contains(out, "No trust domains configured") {
		t.Error("missing empty trust domains message")
	}
	if !strings.Contains(out, "No signing keys configured") {
		t.Error("missing empty signing keys message")
	}
	if !strings.Contains(out, "No SSF streams configured") {
		t.Error("missing empty SSF streams message")
	}
}

func TestGenerateRunbook_MinimalManifest(t *testing.T) {
	m := &SoulManifest{
		Metadata: Metadata{FabricID: "minimal"},
	}
	out := GenerateRunbook(m)

	if !strings.Contains(out, "## Recovery") {
		t.Error("recovery section must always be present")
	}
	if !strings.Contains(out, "No trust domains configured") {
		t.Error("missing empty trust domains message")
	}
	if !strings.Contains(out, "No signing keys configured") {
		t.Error("missing empty signing keys message")
	}
}
