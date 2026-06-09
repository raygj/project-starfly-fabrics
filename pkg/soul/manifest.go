package soul

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	APIVersionV1 = "starfly.io/v1"
	KindManifest = "SoulManifest"
)

// SoulManifest is the minimal state required to reconstruct a Starfly fabric.
type SoulManifest struct {
	APIVersion   string             `yaml:"apiVersion"`
	Kind         string             `yaml:"kind"`
	Metadata     Metadata           `yaml:"metadata"`
	Identity     Identity           `yaml:"identity"`
	TrustDomains []TrustDomainSpec  `yaml:"trustDomains"`
	Revocations  RevocationSnapshot `yaml:"revocations"`
	SSFStreams   []SSFStreamSpec    `yaml:"ssfStreams,omitempty"`
	Federation   FederationManifest `yaml:"federation,omitempty"`
	Audit        AuditState         `yaml:"audit"`
}

// Metadata identifies the fabric and the manifest version.
type Metadata struct {
	FabricID    string    `yaml:"fabricId"`
	GeneratedAt time.Time `yaml:"generatedAt"`
	Sequence    uint64    `yaml:"sequence"`
}

// Identity holds the fabric's signing key references.
type Identity struct {
	SigningKeys []SigningKeyRef `yaml:"signingKeys"`
}

// SigningKeyRef references a KMS-managed signing key.
type SigningKeyRef struct {
	KMSKeyID  string `yaml:"kmsKeyId"`
	Algorithm string `yaml:"algorithm"`
	KID       string `yaml:"kid"`
	Status    string `yaml:"status"` // "active", "rotated", "revoked"
}

// TrustDomainSpec captures a trust domain configuration.
type TrustDomainSpec struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type,omitempty"` // e.g. "aws-sts", "oidc", "spiffe"
	Issuer  string `yaml:"issuer,omitempty"`
	JWKSURL string `yaml:"jwksUrl,omitempty"`
	Enabled bool   `yaml:"enabled"`
}

// RevocationSnapshot holds metadata about the exported revocation index.
type RevocationSnapshot struct {
	Count      int       `yaml:"count"`
	Hash       string    `yaml:"hash"` // "sha256:..." integrity check
	ExportedAt time.Time `yaml:"exportedAt"`
}

// SSFStreamSpec captures an SSF stream registration.
type SSFStreamSpec struct {
	StreamID        string   `yaml:"streamId"`
	Transmitter     string   `yaml:"transmitter"`
	EventsRequested []string `yaml:"eventsRequested"`
}

// FederationManifest records the state of federated peers.
// Added in Phase 12 for multi-cluster JWKS federation.
type FederationManifest struct {
	Peers []FederationPeer `yaml:"peers,omitempty"`
}

// FederationPeer is a snapshot of a federated peer's state in the manifest.
type FederationPeer struct {
	FabricID       string    `yaml:"fabricId"`
	LastSeen       time.Time `yaml:"lastSeen,omitempty"`
	KeyCount       int       `yaml:"keyCount,omitempty"`
	RevocationHash string    `yaml:"revocationHash,omitempty"`
}

// AuditState captures the audit buffer position.
type AuditState struct {
	LastFlushedSequence uint64 `yaml:"lastFlushedSequence"`
	ExternalSink        string `yaml:"externalSink,omitempty"`
}

// NewManifest creates a new SoulManifest with the required fields set.
func NewManifest(fabricID string, seq uint64) *SoulManifest {
	return &SoulManifest{
		APIVersion: APIVersionV1,
		Kind:       KindManifest,
		Metadata: Metadata{
			FabricID:    fabricID,
			GeneratedAt: time.Now().UTC(),
			Sequence:    seq,
		},
	}
}

// Marshal serializes the manifest to YAML.
func (m *SoulManifest) Marshal() ([]byte, error) {
	return yaml.Marshal(m)
}

// Unmarshal deserializes a YAML document into a SoulManifest.
func Unmarshal(data []byte) (*SoulManifest, error) {
	var m SoulManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling soul manifest: %w", err)
	}
	return &m, nil
}

// Validate checks that required fields are present and consistent.
func (m *SoulManifest) Validate() error {
	if m.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if m.APIVersion != APIVersionV1 {
		return fmt.Errorf("unsupported apiVersion: %s (expected %s)", m.APIVersion, APIVersionV1)
	}
	if m.Kind != KindManifest {
		return fmt.Errorf("unexpected kind: %s (expected %s)", m.Kind, KindManifest)
	}
	if m.Metadata.FabricID == "" {
		return fmt.Errorf("metadata.fabricId is required")
	}
	if m.Metadata.Sequence == 0 {
		return fmt.Errorf("metadata.sequence must be > 0")
	}
	if len(m.Identity.SigningKeys) == 0 {
		return fmt.Errorf("at least one signing key reference is required")
	}
	// Validate each signing key ref.
	for i, k := range m.Identity.SigningKeys {
		if k.KID == "" {
			return fmt.Errorf("identity.signingKeys[%d].kid is required", i)
		}
		if k.Status == "" {
			return fmt.Errorf("identity.signingKeys[%d].status is required", i)
		}
	}
	return nil
}
