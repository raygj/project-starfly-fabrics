// Package v1alpha1 defines the StarlightFabric CRD types for the Starfly operator.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// GroupName is the API group for Starfly CRDs.
	GroupName = "starfly.io"
	// Version is the API version.
	Version = "v1alpha1"

	// PhaseConverged indicates the fabric state matches the spec.
	PhaseConverged = "Converged"
	// PhaseConverging indicates the fabric is applying changes.
	PhaseConverging = "Converging"
	// PhaseDegraded indicates the fabric is running but not fully healthy.
	PhaseDegraded = "Degraded"

	// Condition types.
	ConditionReady     = "Ready"
	ConditionConverged = "Converged"
	ConditionDegraded  = "Degraded"
	ConditionAnchored  = "Anchored"
)

// StarlightFabric is the root CRD for a Starfly fabric instance.
// It declares the desired state of trust domains, signing keys, and SSF streams.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sf,scope=Namespaced
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Soul Seq",type=integer,JSONPath=`.status.soulSequence`
// +kubebuilder:printcolumn:name="Trust Domains",type=integer,JSONPath=`.status.trustDomainsActive`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type StarlightFabric struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StarlightFabricSpec   `json:"spec,omitempty"`
	Status StarlightFabricStatus `json:"status,omitempty"`
}

// StarlightFabricSpec defines the desired fabric state.
type StarlightFabricSpec struct {
	// TrustDomains configures the identity providers the fabric trusts.
	// +optional
	TrustDomains []TrustDomainSpec `json:"trustDomains,omitempty"`

	// SigningKeys configures the KMS-backed signing keys for token issuance.
	// +optional
	SigningKeys []SigningKeySpec `json:"signingKeys,omitempty"`

	// SSFStreams configures Shared Signals Framework stream subscriptions.
	// +optional
	SSFStreams []SSFStreamSpec `json:"ssfStreams,omitempty"`

	// Anchor configures the external soul manifest anchor (backup destination).
	// +optional
	Anchor *AnchorSpec `json:"anchor,omitempty"`

	// Policy configures the OPA policy engine.
	// +optional
	Policy *PolicySpec `json:"policy,omitempty"`

	// Federation configures multi-cluster JWKS federation peers.
	// +optional
	Federation *FederationSpec `json:"federation,omitempty"`
}

// FederationSpec configures multi-cluster JWKS federation.
type FederationSpec struct {
	// Peers lists the federated peer fabrics.
	// +optional
	Peers []FederationPeerSpec `json:"peers,omitempty"`
}

// FederationPeerSpec configures a single federated peer.
type FederationPeerSpec struct {
	// FabricID uniquely identifies the peer fabric.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	FabricID string `json:"fabricId"`

	// JWKSEndpoint is the HTTPS URL serving the peer's public JWKS.
	// +kubebuilder:validation:Required
	JWKSEndpoint string `json:"jwksEndpoint"`

	// MTLSSecret is the Kubernetes Secret name holding the mTLS client cert.
	// +optional
	MTLSSecret string `json:"mtlsSecret,omitempty"`

	// RefreshInterval controls how often the peer's JWKS is refetched (e.g., "60s").
	// +optional
	// +kubebuilder:default="60s"
	RefreshInterval string `json:"refreshInterval,omitempty"`

	// StalenessThreshold is the max age before marking the peer unhealthy (e.g., "5m").
	// +optional
	// +kubebuilder:default="5m"
	StalenessThreshold string `json:"stalenessThreshold,omitempty"`
}

// TrustDomainSpec configures a single trust domain.
type TrustDomainSpec struct {
	// Name is the unique identifier for this trust domain.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Type is the identity provider type (oidc, spiffe, aws-sts, kerberos, saml).
	// +kubebuilder:validation:Enum=oidc;spiffe;aws-sts;kerberos;saml
	Type string `json:"type"`

	// Issuer is the token issuer URL or SPIFFE trust domain.
	// +optional
	Issuer string `json:"issuer,omitempty"`

	// JWKSURI is the JWKS endpoint for key resolution.
	// +optional
	JWKSURI string `json:"jwksUri,omitempty"`

	// Enabled controls whether this trust domain is active.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`
}

// SigningKeySpec configures a KMS-backed signing key.
type SigningKeySpec struct {
	// KID is the key identifier (unique within the fabric).
	// +kubebuilder:validation:Required
	KID string `json:"kid"`

	// Algorithm is the signing algorithm (ES256, RS256, EdDSA).
	// +kubebuilder:validation:Enum=ES256;RS256;EdDSA
	Algorithm string `json:"algorithm"`

	// KMSKeyID is the cloud KMS key reference (e.g., ARN, resource name).
	// +kubebuilder:validation:Required
	KMSKeyID string `json:"kmsKeyId"`

	// RotationPolicy is the key rotation interval (e.g., "90d", "30d").
	// +optional
	RotationPolicy string `json:"rotationPolicy,omitempty"`

	// Status is the current key status.
	// +kubebuilder:validation:Enum=active;rotated;revoked
	// +kubebuilder:default=active
	Status string `json:"status,omitempty"`
}

// SSFStreamSpec configures an SSF stream subscription.
type SSFStreamSpec struct {
	// StreamID is the unique identifier for this stream.
	// +kubebuilder:validation:Required
	StreamID string `json:"streamId"`

	// Transmitter is the SSF transmitter endpoint URL.
	// +kubebuilder:validation:Required
	Transmitter string `json:"transmitter"`

	// EventsRequested lists the CAEP/SSF event types to subscribe to.
	// +optional
	EventsRequested []string `json:"eventsRequested,omitempty"`
}

// AnchorSpec configures the external soul manifest anchor.
type AnchorSpec struct {
	// Type is the anchor backend type (s3, filesystem, gcs).
	// +kubebuilder:validation:Enum=s3;filesystem;gcs
	Type string `json:"type"`

	// Bucket is the storage bucket name (for s3/gcs).
	// +optional
	Bucket string `json:"bucket,omitempty"`

	// Prefix is the key prefix within the bucket.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// Path is the filesystem path (for filesystem anchor).
	// +optional
	Path string `json:"path,omitempty"`
}

// PolicySpec configures the OPA policy engine.
type PolicySpec struct {
	// BundlePath is the path to the OPA policy bundle.
	// +optional
	BundlePath string `json:"bundlePath,omitempty"`
}

// StarlightFabricStatus defines the observed fabric state.
type StarlightFabricStatus struct {
	// Phase is the current fabric lifecycle phase.
	// +optional
	Phase string `json:"phase,omitempty"`

	// SoulSequence is the current soul manifest sequence number.
	// +optional
	SoulSequence int64 `json:"soulSequence,omitempty"`

	// TrustDomainsActive is the number of active trust domains.
	// +optional
	TrustDomainsActive int `json:"trustDomainsActive,omitempty"`

	// SigningKeysActive is the number of active signing keys.
	// +optional
	SigningKeysActive int `json:"signingKeysActive,omitempty"`

	// SSFStreamsActive is the number of active SSF streams.
	// +optional
	SSFStreamsActive int `json:"ssfStreamsActive,omitempty"`

	// LastConvergence is the timestamp of the last successful convergence.
	// +optional
	LastConvergence *metav1.Time `json:"lastConvergence,omitempty"`

	// LastConvergenceDuration is how long the last convergence took (e.g., "12ms").
	// +optional
	LastConvergenceDuration string `json:"lastConvergenceDuration,omitempty"`

	// FederationPeersHealthy is the number of healthy federation peers.
	// +optional
	FederationPeersHealthy int `json:"federationPeersHealthy,omitempty"`

	// FederationPeersTotal is the total number of configured federation peers.
	// +optional
	FederationPeersTotal int `json:"federationPeersTotal,omitempty"`

	// Conditions represent the latest observations of the fabric's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// StarlightFabricList contains a list of StarlightFabric resources.
//
// +kubebuilder:object:root=true
type StarlightFabricList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []StarlightFabric `json:"items"`
}
