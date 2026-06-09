package azure

import (
	"context"
	"fmt"
	"strings"
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
	tracerName        = "github.com/starfly-fabrics/starfly/pkg/identity/azure"
	credType          = "azure-mi"
	azureIssuerPrefix = "https://login.microsoftonline.com/"
	azureSTSPrefix    = "https://sts.windows.net/"
)

var _ core.IdentityProvider = (*Provider)(nil)

// Provider validates Azure AD tokens (managed identities, service principals,
// workload identity federation) and returns WorkloadIdentity.
type Provider struct {
	trustDomains   map[string]core.TrustDomain // keyed by tenant ID
	allowedTenants map[string]bool
	jwksResolver   core.JWKSResolver
	devMode        bool
}

// Option configures a Provider.
type Option func(*Provider)

// WithTrustDomains maps Azure tenant IDs to trust domains.
func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled && d.Name != "" {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

// WithAllowedTenants restricts which Azure AD tenants are accepted.
func WithAllowedTenants(tenants []string) Option {
	return func(p *Provider) {
		for _, tid := range tenants {
			p.allowedTenants[tid] = true
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

// NewProvider creates an Azure identity provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains:   make(map[string]core.TrustDomain),
		allowedTenants: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// ValidateWorkload validates an Azure AD token and returns a WorkloadIdentity.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.azure.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	insecureToken, err := jwt.ParseInsecure([]byte(credential))
	if err != nil {
		err = fmt.Errorf("malformed Azure token: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	issuer, _ := insecureToken.Issuer()
	if !strings.HasPrefix(issuer, azureIssuerPrefix) && !strings.HasPrefix(issuer, azureSTSPrefix) {
		err = fmt.Errorf("azure token issuer %q does not match Azure AD prefixes", issuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	sub, _ := insecureToken.Subject()
	if sub == "" {
		err = fmt.Errorf("azure token missing sub claim")
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Extract tenant ID from issuer URL path.
	tenantID, err := extractTenantID(issuer)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Extract Azure-specific claims.
	var oid, appID, name string
	var roles interface{}

	extractStringClaim(insecureToken, "oid", &oid)
	extractStringClaim(insecureToken, "appid", &appID)
	if appID == "" {
		extractStringClaim(insecureToken, "azp", &appID)
	}
	extractStringClaim(insecureToken, "name", &name)

	var rolesVal interface{}
	if getErr := insecureToken.Get("roles", &rolesVal); getErr == nil && rolesVal != nil {
		roles = rolesVal
	}

	// Also try tid claim (some tokens include it directly).
	var tidClaim string
	extractStringClaim(insecureToken, "tid", &tidClaim)
	if tidClaim != "" && tenantID == "" {
		tenantID = tidClaim
	}

	// Determine the identity principal: prefer oid, fall back to sub.
	principal := sub
	if oid != "" {
		principal = oid
	}

	span.SetAttributes(
		attribute.String("azure.issuer", issuer),
		attribute.String("azure.subject", sub),
		attribute.String("azure.tenant_id", tenantID),
		attribute.String("azure.principal", principal),
	)

	claims := map[string]interface{}{
		"tenant_id": tenantID,
		"sub":       sub,
	}
	if oid != "" {
		claims["object_id"] = oid
	}
	if appID != "" {
		claims["app_id"] = appID
	}
	if name != "" {
		claims["name"] = name
	}
	if roles != nil {
		claims["roles"] = roles
	}

	if p.devMode {
		claims["dev_mode"] = true
		wimseURI := fmt.Sprintf("wimse://dev.local/azure/%s", principal)
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

	// Production mode: verify signature against Azure AD JWKS.
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)

	if p.jwksResolver != nil {
		if err := p.verifyWithResolver(ctx, credential, jwksURL, span); err != nil {
			return nil, err
		}
	} else {
		keyset, fetchErr := jwk.Fetch(ctx, jwksURL)
		if fetchErr != nil {
			err = fmt.Errorf("fetching Azure AD JWKS for tenant %s: %w", tenantID, fetchErr)
			telemetry.SpanError(span, err)
			return nil, err
		}
		_, err = jwt.Parse([]byte(credential),
			jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithValidate(true),
		)
		if err != nil {
			err = fmt.Errorf("azure token validation failed: %w", err)
			telemetry.SpanError(span, err)
			return nil, err
		}
	}

	// Map tenant ID to trust domain.
	td, ok := p.trustDomains[tenantID]
	if !ok {
		err = fmt.Errorf("unknown Azure tenant: %s", tenantID)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Enforce allowed tenants if configured.
	if len(p.allowedTenants) > 0 && !p.allowedTenants[tenantID] {
		err = fmt.Errorf("azure tenant %s not in allowed tenants", tenantID)
		telemetry.SpanError(span, err)
		return nil, err
	}

	wimseURI := fmt.Sprintf("wimse://%s/azure/%s", td.Name, principal)

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

// extractTenantID extracts the tenant ID from an Azure AD issuer URL.
// Supports both v1 (https://sts.windows.net/{tenant}/) and
// v2 (https://login.microsoftonline.com/{tenant}/v2.0) formats.
func extractTenantID(issuer string) (string, error) {
	var path string
	if strings.HasPrefix(issuer, azureIssuerPrefix) {
		path = strings.TrimPrefix(issuer, azureIssuerPrefix)
	} else if strings.HasPrefix(issuer, azureSTSPrefix) {
		path = strings.TrimPrefix(issuer, azureSTSPrefix)
	} else {
		return "", fmt.Errorf("cannot extract tenant from issuer: %s", issuer)
	}

	// Remove trailing slashes and /v2.0 suffix.
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, "/v2.0")
	path = strings.TrimSuffix(path, "/")

	// The tenant ID is the first path segment.
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("cannot extract tenant from issuer: %s", issuer)
	}

	return parts[0], nil
}

// verifyWithResolver extracts kid from the JWS header, resolves the public
// key via the shared JWKSResolver, and verifies the JWT signature.
func (p *Provider) verifyWithResolver(ctx context.Context, credential, jwksURL string, span trace.Span) error {
	msg, err := jws.Parse([]byte(credential))
	if err != nil {
		err = fmt.Errorf("azure: parsing JWS: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		err = fmt.Errorf("azure: no signatures")
		telemetry.SpanError(span, err)
		return err
	}
	kid, _ := sigs[0].ProtectedHeaders().KeyID()
	alg, _ := sigs[0].ProtectedHeaders().Algorithm()

	pubKey, err := p.jwksResolver.ResolveKey(ctx, jwksURL, kid)
	if err != nil {
		err = fmt.Errorf("resolving key for Azure token: %w", err)
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
		err = fmt.Errorf("azure token validation failed: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	return nil
}

// extractStringClaim extracts a string claim from a JWT token into the target pointer.
func extractStringClaim(tok jwt.Token, key string, target *string) {
	var v interface{}
	if err := tok.Get(key, &v); err == nil && v != nil {
		if s, ok := v.(string); ok {
			*target = s
		}
	}
}
