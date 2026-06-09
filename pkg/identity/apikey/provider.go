package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/apikey"
	credType   = "api-key"
)

var _ core.IdentityProvider = (*Provider)(nil)

// KeyIdentity maps a hashed API key to a pre-configured workload identity.
type KeyIdentity struct {
	WorkloadID  string
	TrustDomain string
	Claims      map[string]string
	ExpiresAt   time.Time // zero value = no expiry
}

// Provider validates static API keys against a local hash registry.
type Provider struct {
	keys    map[string]*KeyIdentity // SHA-256 hash hex -> identity
	devMode bool
}

// Option configures a Provider.
type Option func(*Provider)

// WithKeys configures the provider with a pre-built hash-to-identity map.
// Keys in the map MUST be hex-encoded SHA-256 hashes of the raw API keys.
func WithKeys(keys map[string]*KeyIdentity) Option {
	return func(p *Provider) { p.keys = keys }
}

// WithDevMode enables development mode where any non-empty key is accepted.
func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

// NewProvider creates an API key validation provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		keys: make(map[string]*KeyIdentity),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// ValidateWorkload validates a raw API key against the hash registry.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "identity.apikey.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if credential == "" {
		err := fmt.Errorf("empty API key")
		telemetry.SpanError(span, err)
		return nil, err
	}

	hash := sha256.Sum256([]byte(credential))
	hashHex := hex.EncodeToString(hash[:])
	prefix := hashHex[:8]

	span.SetAttributes(attribute.String("apikey.hash_prefix", prefix))

	claims := map[string]interface{}{
		"key_prefix":     prefix,
		"migration_path": "true",
	}

	if p.devMode {
		wimseURI := fmt.Sprintf("wimse://dev.local/apikey/%s", prefix)
		return &core.WorkloadIdentity{
			ID:          wimseURI,
			TrustDomain: "dev.local",
			Attestation: &core.AttestationEvidence{
				Method:    credType,
				Timestamp: time.Now().UTC(),
			},
			Claims: claims,
		}, nil
	}

	entry, ok := p.keys[hashHex]
	if !ok {
		err := fmt.Errorf("unknown API key")
		telemetry.SpanError(span, err)
		return nil, err
	}

	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		err := fmt.Errorf("API key expired")
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Merge pre-configured claims from the registry entry.
	for k, v := range entry.Claims {
		claims[k] = v
	}

	return &core.WorkloadIdentity{
		ID:          entry.WorkloadID,
		TrustDomain: entry.TrustDomain,
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: claims,
	}, nil
}
