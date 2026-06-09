package gcp

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName    = "github.com/starfly-fabrics/starfly/pkg/identity/gcp"
	credType      = "gcp-wif"
	googleIssuer  = "https://accounts.google.com"
	googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
)

var _ core.IdentityProvider = (*Provider)(nil)

// Provider validates GCP OIDC tokens (service account identity tokens and
// Workload Identity Federation tokens) and returns WorkloadIdentity.
type Provider struct {
	trustDomains    map[string]core.TrustDomain // keyed by project ID
	allowedProjects map[string]bool
	jwksResolver    core.JWKSResolver
	devMode         bool
}

// Option configures a Provider.
type Option func(*Provider)

// WithTrustDomains maps GCP project IDs to trust domains.
func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled && d.Name != "" {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

// WithAllowedProjects restricts which GCP projects are accepted.
func WithAllowedProjects(projects []string) Option {
	return func(p *Provider) {
		for _, proj := range projects {
			p.allowedProjects[proj] = true
		}
	}
}

// WithJWKSResolver injects a shared JWKS resolver for signature verification.
func WithJWKSResolver(r core.JWKSResolver) Option {
	return func(p *Provider) { p.jwksResolver = r }
}

// WithDevMode enables development mode (skips signature verification).
func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

// NewProvider creates a GCP identity provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains:    make(map[string]core.TrustDomain),
		allowedProjects: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// ValidateWorkload validates a GCP OIDC token and returns a WorkloadIdentity.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.gcp.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	insecureToken, err := jwt.ParseInsecure([]byte(credential))
	if err != nil {
		err = fmt.Errorf("malformed GCP token: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	issuer, _ := insecureToken.Issuer()
	if issuer != googleIssuer {
		err = fmt.Errorf("GCP token issuer %q is not %s", issuer, googleIssuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	sub, _ := insecureToken.Subject()
	if sub == "" {
		err = fmt.Errorf("GCP token missing sub claim")
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Extract email from standard claim.
	var email string
	var emailVal interface{}
	if getErr := insecureToken.Get("email", &emailVal); getErr == nil && emailVal != nil {
		if s, ok := emailVal.(string); ok {
			email = s
		}
	}

	// Extract GCP-specific claims from the nested google claim.
	var projectID, zone, instanceID string
	var googleClaim interface{}
	if getErr := insecureToken.Get("google", &googleClaim); getErr == nil && googleClaim != nil {
		if gMap, ok := googleClaim.(map[string]interface{}); ok {
			if ce, ok := gMap["compute_engine"].(map[string]interface{}); ok {
				if v, ok := ce["project_id"].(string); ok {
					projectID = v
				}
				if v, ok := ce["zone"].(string); ok {
					zone = v
				}
				if v, ok := ce["instance_id"].(string); ok {
					instanceID = v
				}
			}
		}
	}

	// Fall back to flat project_id claim.
	if projectID == "" {
		var pidVal interface{}
		if getErr := insecureToken.Get("project_id", &pidVal); getErr == nil && pidVal != nil {
			if s, ok := pidVal.(string); ok {
				projectID = s
			}
		}
	}

	// Determine the identity principal: prefer email, fall back to sub.
	principal := sub
	if email != "" {
		principal = email
	}

	span.SetAttributes(
		attribute.String("gcp.issuer", issuer),
		attribute.String("gcp.subject", sub),
		attribute.String("gcp.principal", principal),
	)

	claims := map[string]interface{}{
		"sub": sub,
	}
	if email != "" {
		claims["email"] = email
	}
	if projectID != "" {
		claims["project_id"] = projectID
	}
	if zone != "" {
		claims["zone"] = zone
	}
	if instanceID != "" {
		claims["instance_id"] = instanceID
	}

	if p.devMode {
		claims["dev_mode"] = true
		wimseURI := fmt.Sprintf("wimse://dev.local/gcp/%s", principal)
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

	// Production mode: verify signature against Google JWKS.
	if p.jwksResolver != nil {
		if err := p.verifyWithResolver(ctx, credential, googleJWKSURL, span); err != nil {
			return nil, err
		}
	} else {
		keyset, fetchErr := jwk.Fetch(ctx, googleJWKSURL)
		if fetchErr != nil {
			err = fmt.Errorf("fetching Google JWKS: %w", fetchErr)
			telemetry.SpanError(span, err)
			return nil, err
		}
		_, err = jwt.Parse([]byte(credential),
			jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithValidate(true),
		)
		if err != nil {
			err = fmt.Errorf("GCP token validation failed: %w", err)
			telemetry.SpanError(span, err)
			return nil, err
		}
	}

	// Map project ID to trust domain.
	td, ok := p.trustDomains[projectID]
	if !ok {
		err = fmt.Errorf("unknown GCP project: %s", projectID)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Enforce allowed projects if configured.
	if len(p.allowedProjects) > 0 && !p.allowedProjects[projectID] {
		err = fmt.Errorf("GCP project %s not in allowed projects", projectID)
		telemetry.SpanError(span, err)
		return nil, err
	}

	wimseURI := fmt.Sprintf("wimse://%s/gcp/%s", td.Name, principal)

	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: td.Name,
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: claims,
	}, nil
}

// verifyWithResolver extracts kid from the JWS header, resolves the public
// key via the shared JWKSResolver, and verifies the JWT signature.
func (p *Provider) verifyWithResolver(ctx context.Context, credential, jwksURL string, span trace.Span) error {
	msg, err := jws.Parse([]byte(credential))
	if err != nil {
		err = fmt.Errorf("GCP: parsing JWS: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		err = fmt.Errorf("GCP: no signatures")
		telemetry.SpanError(span, err)
		return err
	}
	kid, _ := sigs[0].ProtectedHeaders().KeyID()
	alg, _ := sigs[0].ProtectedHeaders().Algorithm()

	pubKey, err := p.jwksResolver.ResolveKey(ctx, jwksURL, kid)
	if err != nil {
		err = fmt.Errorf("resolving key for GCP token: %w", err)
		telemetry.SpanError(span, err)
		return err
	}

	jwkKey, err := jwk.Import(pubKey)
	if err != nil {
		err = fmt.Errorf("importing resolved key: %w", err)
		telemetry.SpanError(span, err)
		return err
	}

	_, err = jwt.Parse([]byte(credential), jwt.WithKey(alg, jwkKey), jwt.WithValidate(true))
	if err != nil {
		err = fmt.Errorf("GCP token validation failed: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	return nil
}
