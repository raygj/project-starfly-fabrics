package soul

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseManifest() *SoulManifest {
	m := NewManifest("fabric-001", 44)
	m.TrustDomains = []TrustDomainSpec{
		{Name: "payments.prod", Type: "oidc", Issuer: "https://pay.example.com", Enabled: true},
	}
	m.Identity.SigningKeys = []SigningKeyRef{
		{KID: "key-001", KMSKeyID: "arn:aws:kms:us-east-1:111:key/abc", Algorithm: "ES256", Status: "active"},
	}
	m.SSFStreams = []SSFStreamSpec{
		{StreamID: "stream-001", Transmitter: "https://ssf.example.com", EventsRequested: []string{"token-revocation"}},
	}
	m.Revocations = RevocationSnapshot{Count: 144, Hash: "sha256:abc123"}
	m.Audit = AuditState{LastFlushedSequence: 284000}
	return m
}

func cloneManifest(m *SoulManifest) *SoulManifest {
	cp := *m
	cp.TrustDomains = make([]TrustDomainSpec, len(m.TrustDomains))
	copy(cp.TrustDomains, m.TrustDomains)
	cp.Identity.SigningKeys = make([]SigningKeyRef, len(m.Identity.SigningKeys))
	copy(cp.Identity.SigningKeys, m.Identity.SigningKeys)
	cp.SSFStreams = make([]SSFStreamSpec, len(m.SSFStreams))
	copy(cp.SSFStreams, m.SSFStreams)
	return &cp
}

func TestDiff_Identical(t *testing.T) {
	m := baseManifest()
	d := Diff(m, m)
	if !d.IsEmpty() {
		t.Fatalf("expected empty diff for identical manifests, got %d changes", len(d.Changes))
	}
}

func TestDiff_AddTrustDomain(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Metadata.Sequence = 47
	to.TrustDomains = append(to.TrustDomains, TrustDomainSpec{
		Name: "analytics.int", Type: "spiffe", Issuer: "https://analytics.example.com", Enabled: true,
	})

	d := Diff(from, to)
	found := findEntry(d, DiffAdded, "trust_domain", "analytics.int")
	if found == nil {
		t.Fatal("expected added trust_domain entry for analytics.int")
	}
}

func TestDiff_RemoveTrustDomain(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.TrustDomains = nil

	d := Diff(from, to)
	found := findEntry(d, DiffRemoved, "trust_domain", "payments.prod")
	if found == nil {
		t.Fatal("expected removed trust_domain entry for payments.prod")
	}
}

func TestDiff_ChangeTrustDomain_Issuer(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.TrustDomains[0].Issuer = "https://new-pay.example.com"

	d := Diff(from, to)
	found := findEntry(d, DiffChanged, "trust_domain", "payments.prod")
	if found == nil {
		t.Fatal("expected changed trust_domain entry for payments.prod")
	}
	if !strings.Contains(found.Detail, "issuer") {
		t.Fatalf("expected detail to mention issuer, got: %s", found.Detail)
	}
}

func TestDiff_ChangeTrustDomain_Enabled(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.TrustDomains[0].Enabled = false

	d := Diff(from, to)
	found := findEntry(d, DiffChanged, "trust_domain", "payments.prod")
	if found == nil {
		t.Fatal("expected changed trust_domain entry for payments.prod")
	}
	if !strings.Contains(found.Detail, "enabled") {
		t.Fatalf("expected detail to mention enabled, got: %s", found.Detail)
	}
}

func TestDiff_AddSigningKey(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Identity.SigningKeys = append(to.Identity.SigningKeys, SigningKeyRef{
		KID: "key-002", KMSKeyID: "arn:aws:kms:us-east-1:111:key/def", Algorithm: "RS256", Status: "active",
	})

	d := Diff(from, to)
	found := findEntry(d, DiffAdded, "signing_key", "key-002")
	if found == nil {
		t.Fatal("expected added signing_key entry for key-002")
	}
}

func TestDiff_RemoveSigningKey(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Identity.SigningKeys = nil

	d := Diff(from, to)
	found := findEntry(d, DiffRemoved, "signing_key", "key-001")
	if found == nil {
		t.Fatal("expected removed signing_key entry for key-001")
	}
}

func TestDiff_ChangeSigningKey_Status(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Identity.SigningKeys[0].Status = "rotated"

	d := Diff(from, to)
	found := findEntry(d, DiffChanged, "signing_key", "key-001")
	if found == nil {
		t.Fatal("expected changed signing_key entry for key-001")
	}
	if !strings.Contains(found.Detail, "active -> rotated") {
		t.Fatalf("expected detail to show status transition, got: %s", found.Detail)
	}
}

func TestDiff_AddSSFStream(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.SSFStreams = append(to.SSFStreams, SSFStreamSpec{
		StreamID: "stream-002", Transmitter: "https://new.example.com",
	})

	d := Diff(from, to)
	found := findEntry(d, DiffAdded, "ssf_stream", "stream-002")
	if found == nil {
		t.Fatal("expected added ssf_stream entry for stream-002")
	}
	if !strings.Contains(found.Detail, "https://new.example.com") {
		t.Fatalf("expected detail to contain transmitter URL, got: %s", found.Detail)
	}
}

func TestDiff_RemoveSSFStream(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.SSFStreams = nil

	d := Diff(from, to)
	found := findEntry(d, DiffRemoved, "ssf_stream", "stream-001")
	if found == nil {
		t.Fatal("expected removed ssf_stream entry for stream-001")
	}
}

func TestDiff_RevocationCountChange(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Revocations.Count = 147

	d := Diff(from, to)
	found := findEntry(d, DiffChanged, "revocation", "count")
	if found == nil {
		t.Fatal("expected changed revocation entry")
	}
	if !strings.Contains(found.Detail, "+3") {
		t.Fatalf("expected detail to contain +3 delta, got: %s", found.Detail)
	}
}

func TestDiff_AuditSequenceChange(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Audit.LastFlushedSequence = 284719

	d := Diff(from, to)
	found := findEntry(d, DiffChanged, "audit", "sequence")
	if found == nil {
		t.Fatal("expected changed audit entry")
	}
	if !strings.Contains(found.Detail, "+719") {
		t.Fatalf("expected detail to contain +719 delta, got: %s", found.Detail)
	}
}

func TestDiff_FabricIDMismatch(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Metadata.FabricID = "fabric-999"

	d := Diff(from, to)
	found := findEntry(d, DiffChanged, "metadata", "fabricId")
	if found == nil {
		t.Fatal("expected metadata warning entry for fabricId mismatch")
	}
	if !strings.Contains(found.Detail, "WARNING") {
		t.Fatalf("expected WARNING in detail, got: %s", found.Detail)
	}
}

func TestDiff_NilFrom(t *testing.T) {
	to := baseManifest()
	d := Diff(nil, to)

	if d.FromSequence != 0 {
		t.Fatalf("expected FromSequence 0, got %d", d.FromSequence)
	}
	if d.ToSequence != to.Metadata.Sequence {
		t.Fatalf("expected ToSequence %d, got %d", to.Metadata.Sequence, d.ToSequence)
	}

	// Everything in to should be "added".
	td := findEntry(d, DiffAdded, "trust_domain", "payments.prod")
	if td == nil {
		t.Fatal("expected added trust_domain")
	}
	sk := findEntry(d, DiffAdded, "signing_key", "key-001")
	if sk == nil {
		t.Fatal("expected added signing_key")
	}
	ss := findEntry(d, DiffAdded, "ssf_stream", "stream-001")
	if ss == nil {
		t.Fatal("expected added ssf_stream")
	}
}

func TestDiff_NilTo(t *testing.T) {
	from := baseManifest()
	d := Diff(from, nil)

	if d.ToSequence != 0 {
		t.Fatalf("expected ToSequence 0, got %d", d.ToSequence)
	}

	// Everything in from should be "removed".
	td := findEntry(d, DiffRemoved, "trust_domain", "payments.prod")
	if td == nil {
		t.Fatal("expected removed trust_domain")
	}
	sk := findEntry(d, DiffRemoved, "signing_key", "key-001")
	if sk == nil {
		t.Fatal("expected removed signing_key")
	}
	ss := findEntry(d, DiffRemoved, "ssf_stream", "stream-001")
	if ss == nil {
		t.Fatal("expected removed ssf_stream")
	}
}

func TestDiff_BothNil(t *testing.T) {
	d := Diff(nil, nil)
	if !d.IsEmpty() {
		t.Fatalf("expected empty diff for nil/nil, got %d changes", len(d.Changes))
	}
}

func TestDiff_IsEmpty(t *testing.T) {
	m := baseManifest()
	d := Diff(m, m)
	if !d.IsEmpty() {
		t.Fatal("expected IsEmpty to return true for identical manifests")
	}

	to := cloneManifest(m)
	to.Revocations.Count = 999
	d2 := Diff(m, to)
	if d2.IsEmpty() {
		t.Fatal("expected IsEmpty to return false for differing manifests")
	}
}

func TestDiff_Format(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Metadata.Sequence = 47

	// Add a trust domain.
	to.TrustDomains = append(to.TrustDomains, TrustDomainSpec{
		Name: "analytics.int", Type: "spiffe", Issuer: "https://analytics.example.com", Enabled: true,
	})
	// Change a signing key status.
	to.Identity.SigningKeys[0].Status = "rotated"
	// Remove SSF stream.
	to.SSFStreams = nil
	// Change revocation count.
	to.Revocations.Count = 147
	// Change audit sequence.
	to.Audit.LastFlushedSequence = 284719

	d := Diff(from, to)
	out := d.Format()

	// Verify header.
	if !strings.Contains(out, "seq 44 -> seq 47") {
		t.Fatalf("expected sequence header, got:\n%s", out)
	}
	// Verify prefix characters.
	if !strings.Contains(out, "+ trust_domain: analytics.int") {
		t.Fatalf("expected + prefix for added trust_domain, got:\n%s", out)
	}
	if !strings.Contains(out, "~ signing_key: key-001") {
		t.Fatalf("expected ~ prefix for changed signing_key, got:\n%s", out)
	}
	if !strings.Contains(out, "- ssf_stream: stream-001") {
		t.Fatalf("expected - prefix for removed ssf_stream, got:\n%s", out)
	}
	if !strings.Contains(out, "~ revocation: count") {
		t.Fatalf("expected ~ prefix for changed revocation, got:\n%s", out)
	}
	if !strings.Contains(out, "~ audit: sequence") {
		t.Fatalf("expected ~ prefix for changed audit, got:\n%s", out)
	}
}

func TestDiff_FormatJSON(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Revocations.Count = 150

	d := Diff(from, to)
	data, err := d.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}

	// Verify it's valid JSON.
	var parsed SoulDiff
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("FormatJSON produced invalid JSON: %v", err)
	}
	if len(parsed.Changes) != 1 {
		t.Fatalf("expected 1 change in parsed JSON, got %d", len(parsed.Changes))
	}
	if parsed.Changes[0].Category != "revocation" {
		t.Fatalf("expected revocation category, got %s", parsed.Changes[0].Category)
	}
}

// findEntry searches for a DiffEntry matching the given criteria.
func TestDiff_AddFederationPeer(t *testing.T) {
	from := baseManifest()
	to := cloneManifest(from)
	to.Federation.Peers = []FederationPeer{
		{FabricID: "beta.fabric", KeyCount: 3},
	}

	d := Diff(from, to)
	e := findEntry(d, DiffAdded, "federation_peer", "beta.fabric")
	if e == nil {
		t.Fatalf("expected DiffAdded for federation_peer beta.fabric: %s", d.Format())
	}
	if !strings.Contains(e.Detail, "keyCount: 3") {
		t.Errorf("expected detail to contain keyCount, got %q", e.Detail)
	}
}

func TestDiff_RemoveFederationPeer(t *testing.T) {
	from := baseManifest()
	from.Federation.Peers = []FederationPeer{
		{FabricID: "alpha.fabric", KeyCount: 2},
	}
	to := cloneManifest(from)
	to.Federation.Peers = nil

	d := Diff(from, to)
	e := findEntry(d, DiffRemoved, "federation_peer", "alpha.fabric")
	if e == nil {
		t.Fatalf("expected DiffRemoved for federation_peer alpha.fabric: %s", d.Format())
	}
}

func TestDiff_ChangeFederationPeer_KeyCount(t *testing.T) {
	from := baseManifest()
	from.Federation.Peers = []FederationPeer{
		{FabricID: "beta.fabric", KeyCount: 2, RevocationHash: "sha256:old"},
	}
	to := cloneManifest(from)
	to.Federation.Peers = []FederationPeer{
		{FabricID: "beta.fabric", KeyCount: 4, RevocationHash: "sha256:new"},
	}

	d := Diff(from, to)
	e := findEntry(d, DiffChanged, "federation_peer", "beta.fabric")
	if e == nil {
		t.Fatalf("expected DiffChanged for federation_peer beta.fabric: %s", d.Format())
	}
	if !strings.Contains(e.Detail, "keyCount") {
		t.Errorf("expected detail to contain keyCount change, got %q", e.Detail)
	}
}

func TestDiff_FederationPeer_NoOp(t *testing.T) {
	from := baseManifest()
	peers := []FederationPeer{
		{FabricID: "alpha.fabric", KeyCount: 2, RevocationHash: "sha256:abc"},
	}
	from.Federation.Peers = peers
	to := cloneManifest(from)
	to.Federation.Peers = peers

	d := Diff(from, to)
	for _, e := range d.Changes {
		if e.Category == "federation_peer" {
			t.Fatalf("expected no federation_peer changes on identical peers, got: %+v", e)
		}
	}
}

func findEntry(d *SoulDiff, dt DiffType, category, name string) *DiffEntry {
	for i := range d.Changes {
		if d.Changes[i].Type == dt && d.Changes[i].Category == category && d.Changes[i].Name == name {
			return &d.Changes[i]
		}
	}
	return nil
}
