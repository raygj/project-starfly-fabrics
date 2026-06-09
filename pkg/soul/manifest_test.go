package soul

import (
	"testing"
	"time"
)

func validManifest() *SoulManifest {
	m := NewManifest("fabric-prod-us-east-1", 42)
	m.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:aws:kms:us-east-1:123:key/abc", Algorithm: "RS256", KID: "starfly-prod-1", Status: "active"},
	}
	m.TrustDomains = []TrustDomainSpec{
		{Name: "prod.acme.com", Issuer: "https://oidc.eks.example.com", JWKSURL: "https://oidc.eks.example.com/.well-known/jwks.json", Enabled: true},
		{Name: "123456789012", Type: "aws-sts", Enabled: true},
	}
	m.Revocations = RevocationSnapshot{
		Count:      1847,
		Hash:       "sha256:a1b2c3d4e5",
		ExportedAt: time.Now().UTC(),
	}
	m.Audit = AuditState{
		LastFlushedSequence: 98231,
		ExternalSink:        "s3://acme-audit/starfly/",
	}
	return m
}

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	m := validManifest()

	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.APIVersion != APIVersionV1 {
		t.Errorf("APIVersion = %q, want %q", got.APIVersion, APIVersionV1)
	}
	if got.Kind != KindManifest {
		t.Errorf("Kind = %q, want %q", got.Kind, KindManifest)
	}
	if got.Metadata.FabricID != "fabric-prod-us-east-1" {
		t.Errorf("FabricID = %q, want %q", got.Metadata.FabricID, "fabric-prod-us-east-1")
	}
	if got.Metadata.Sequence != 42 {
		t.Errorf("Sequence = %d, want 42", got.Metadata.Sequence)
	}
	if len(got.Identity.SigningKeys) != 1 {
		t.Fatalf("SigningKeys count = %d, want 1", len(got.Identity.SigningKeys))
	}
	if got.Identity.SigningKeys[0].KID != "starfly-prod-1" {
		t.Errorf("KID = %q, want %q", got.Identity.SigningKeys[0].KID, "starfly-prod-1")
	}
	if len(got.TrustDomains) != 2 {
		t.Fatalf("TrustDomains count = %d, want 2", len(got.TrustDomains))
	}
	if got.Revocations.Count != 1847 {
		t.Errorf("Revocations.Count = %d, want 1847", got.Revocations.Count)
	}
	if got.Revocations.Hash != "sha256:a1b2c3d4e5" {
		t.Errorf("Revocations.Hash = %q", got.Revocations.Hash)
	}
	if got.Audit.LastFlushedSequence != 98231 {
		t.Errorf("Audit.LastFlushedSequence = %d, want 98231", got.Audit.LastFlushedSequence)
	}
}

func TestValidate_Valid(t *testing.T) {
	m := validManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingFabricID(t *testing.T) {
	m := validManifest()
	m.Metadata.FabricID = ""
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for missing fabricId")
	}
}

func TestValidate_MissingSigningKeys(t *testing.T) {
	m := validManifest()
	m.Identity.SigningKeys = nil
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for missing signing keys")
	}
}

func TestValidate_MissingKID(t *testing.T) {
	m := validManifest()
	m.Identity.SigningKeys[0].KID = ""
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for missing kid")
	}
}

func TestValidate_MissingStatus(t *testing.T) {
	m := validManifest()
	m.Identity.SigningKeys[0].Status = ""
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for missing status")
	}
}

func TestValidate_ZeroSequence(t *testing.T) {
	m := validManifest()
	m.Metadata.Sequence = 0
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for zero sequence")
	}
}

func TestValidate_WrongAPIVersion(t *testing.T) {
	m := validManifest()
	m.APIVersion = "starfly.io/v99"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for wrong apiVersion")
	}
}

func TestValidate_WrongKind(t *testing.T) {
	m := validManifest()
	m.Kind = "NotAManifest"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for wrong kind")
	}
}

func TestUnmarshal_UnknownFields(t *testing.T) {
	// Forward compatibility: unknown fields should not cause an error.
	data := []byte(`
apiVersion: starfly.io/v1
kind: SoulManifest
metadata:
  fabricId: test-fabric
  sequence: 1
  generatedAt: 2026-03-07T14:30:00Z
identity:
  signingKeys:
    - kid: key-1
      status: active
futureField: "should not break"
nestedFuture:
  deep: true
`)
	m, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal with unknown fields: %v", err)
	}
	if m.Metadata.FabricID != "test-fabric" {
		t.Errorf("FabricID = %q, want %q", m.Metadata.FabricID, "test-fabric")
	}
}

func TestNewManifest_Defaults(t *testing.T) {
	m := NewManifest("my-fabric", 1)
	if m.APIVersion != APIVersionV1 {
		t.Errorf("APIVersion = %q, want %q", m.APIVersion, APIVersionV1)
	}
	if m.Kind != KindManifest {
		t.Errorf("Kind = %q, want %q", m.Kind, KindManifest)
	}
	if m.Metadata.FabricID != "my-fabric" {
		t.Errorf("FabricID = %q", m.Metadata.FabricID)
	}
	if m.Metadata.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", m.Metadata.Sequence)
	}
	if m.Metadata.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should not be zero")
	}
}

func TestMarshal_MultipleSigningKeys(t *testing.T) {
	m := NewManifest("multi-key-fabric", 5)
	m.Identity.SigningKeys = []SigningKeyRef{
		{KMSKeyID: "arn:key/1", Algorithm: "RS256", KID: "key-1", Status: "active"},
		{KMSKeyID: "arn:key/0", Algorithm: "RS256", KID: "key-0", Status: "rotated"},
	}

	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Identity.SigningKeys) != 2 {
		t.Fatalf("SigningKeys count = %d, want 2", len(got.Identity.SigningKeys))
	}
	if got.Identity.SigningKeys[0].Status != "active" {
		t.Errorf("key 0 status = %q, want active", got.Identity.SigningKeys[0].Status)
	}
	if got.Identity.SigningKeys[1].Status != "rotated" {
		t.Errorf("key 1 status = %q, want rotated", got.Identity.SigningKeys[1].Status)
	}
}

func TestMarshal_EmptySSFStreams(t *testing.T) {
	m := validManifest()
	m.SSFStreams = nil

	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.SSFStreams) != 0 {
		t.Errorf("SSFStreams should be empty, got %d", len(got.SSFStreams))
	}
}
