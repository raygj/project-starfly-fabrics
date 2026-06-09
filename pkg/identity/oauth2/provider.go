package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/oauth2"
	credType   = "oauth2"
)

var _ core.IdentityProvider = (*Provider)(nil)

// ClientCredentials for introspection endpoint authentication.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

// IntrospectionResponse per RFC 7662.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// Provider validates OAuth 2.0 access tokens (JWT or opaque) and returns
// WorkloadIdentity. JWT tokens are verified locally via JWKS; opaque tokens
// are validated via RFC 7662 token introspection.
type Provider struct {
	trustDomains       map[string]core.TrustDomain // issuer -> trust domain
	jwksResolver       core.JWKSResolver
	introspectionURLs  map[string]string           // issuer -> introspection endpoint
	introspectionCreds map[string]ClientCredentials // issuer -> credentials
	httpClient         *http.Client
	devMode            bool
}

// Option configures a Provider.
type Option func(*Provider)

// WithTrustDomains configures the set of trusted issuers.
func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled && d.Issuer != "" {
				p.trustDomains[d.Issuer] = d
			}
		}
	}
}

// WithJWKSResolver injects a shared JWKS resolver for signature verification.
func WithJWKSResolver(r core.JWKSResolver) Option {
	return func(p *Provider) { p.jwksResolver = r }
}

// WithIntrospection configures a token introspection endpoint for an issuer.
func WithIntrospection(issuer, introspectionURL string, creds ClientCredentials) Option {
	return func(p *Provider) {
		p.introspectionURLs[issuer] = introspectionURL
		p.introspectionCreds[issuer] = creds
	}
}

// WithHTTPClient sets a custom HTTP client for introspection requests.
func WithHTTPClient(c *http.Client) Option {
	return func(p *Provider) { p.httpClient = c }
}

// WithDevMode enables development mode (skips signature verification).
func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

// NewProvider creates a new OAuth 2.0 identity provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains:       make(map[string]core.TrustDomain),
		introspectionURLs:  make(map[string]string),
		introspectionCreds: make(map[string]ClientCredentials),
		httpClient:         core.NewDefaultHTTPClient(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// ValidateWorkload validates an OAuth 2.0 access token (JWT or opaque)
// and returns the resolved WorkloadIdentity.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.oauth2.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if credential == "" {
		err := fmt.Errorf("empty credential")
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Try to parse as JWT. If it parses, use the JWT path.
	// If it fails to parse, treat as opaque token.
	insecureToken, parseErr := jwt.ParseInsecure([]byte(credential))
	if parseErr == nil {
		return p.validateJWT(ctx, credential, insecureToken, span)
	}

	return p.validateOpaque(ctx, credential, span)
}

// validateJWT handles the JWT access token path (RFC 9068).
func (p *Provider) validateJWT(ctx context.Context, credential string, tok jwt.Token, span trace.Span) (*core.WorkloadIdentity, error) {
	issuer, _ := tok.Issuer()
	if issuer == "" {
		err := fmt.Errorf("OAuth2 JWT missing iss claim")
		telemetry.SpanError(span, err)
		return nil, err
	}

	sub, _ := tok.Subject()
	var clientID string
	if err := tok.Get("client_id", &clientID); err != nil {
		// client_id is optional in JWT access tokens
		clientID = ""
	}

	// Determine the principal identifier: prefer client_id, fall back to sub
	principal := clientID
	if principal == "" {
		principal = sub
	}
	if principal == "" {
		err := fmt.Errorf("OAuth2 JWT missing both sub and client_id claims")
		telemetry.SpanError(span, err)
		return nil, err
	}

	var scope string
	if err := tok.Get("scope", &scope); err != nil {
		scope = ""
	}

	span.SetAttributes(
		attribute.String("oauth2.issuer", issuer),
		attribute.String("oauth2.principal", principal),
		attribute.String("oauth2.token_type", "jwt"),
	)

	claims := map[string]interface{}{
		"issuer":     issuer,
		"token_type": "jwt",
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if clientID != "" {
		claims["client_id"] = clientID
	}
	if scope != "" {
		claims["scope"] = scope
	}

	if p.devMode {
		claims["dev_mode"] = true
		wimseURI := fmt.Sprintf("wimse://dev.local/oauth2/%s", principal)
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

	td, ok := p.trustDomains[issuer]
	if !ok {
		err := fmt.Errorf("unknown OAuth2 issuer: %s", issuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Verify JWT signature
	if p.jwksResolver != nil {
		if err := p.verifyWithResolver(ctx, credential, td.JWKSURL, span); err != nil {
			return nil, err
		}
	} else if td.JWKSURL != "" {
		keyset, fetchErr := jwk.Fetch(ctx, td.JWKSURL)
		if fetchErr != nil {
			err := fmt.Errorf("fetching JWKS for %s: %w", issuer, fetchErr)
			telemetry.SpanError(span, err)
			return nil, err
		}
		_, err := jwt.Parse([]byte(credential),
			jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithValidate(true),
		)
		if err != nil {
			err = fmt.Errorf("OAuth2 JWT validation failed: %w", err)
			telemetry.SpanError(span, err)
			return nil, err
		}
	} else {
		err := fmt.Errorf("no JWKS URL or resolver for issuer: %s", issuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	wimseURI := fmt.Sprintf("wimse://%s/oauth2/%s", td.Name, principal)

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

// validateOpaque handles the opaque token path via RFC 7662 introspection.
func (p *Provider) validateOpaque(ctx context.Context, credential string, span trace.Span) (*core.WorkloadIdentity, error) {
	span.SetAttributes(attribute.String("oauth2.token_type", "opaque"))

	if p.devMode {
		keyPrefix := credential
		if len(keyPrefix) > 8 {
			keyPrefix = keyPrefix[:8]
		}
		claims := map[string]interface{}{
			"dev_mode":   true,
			"token_type": "opaque",
			"key_prefix": keyPrefix,
		}
		return &core.WorkloadIdentity{
			ID:          "wimse://dev.local/oauth2/opaque-token",
			TrustDomain: "dev.local",
			Attestation: &core.AttestationEvidence{
				Method:    credType,
				Timestamp: time.Now().UTC(),
			},
			Claims: claims,
		}, nil
	}

	// Determine which introspection endpoint to use
	if len(p.introspectionURLs) == 0 {
		err := fmt.Errorf("no introspection endpoints configured for opaque token validation")
		telemetry.SpanError(span, err)
		return nil, err
	}
	if len(p.introspectionURLs) > 1 {
		err := fmt.Errorf("cannot determine issuer for opaque token; configure a single introspection endpoint or use JWT tokens")
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Single introspection endpoint configured — use it
	var issuerKey string
	var introspectionURL string
	for k, v := range p.introspectionURLs {
		issuerKey = k
		introspectionURL = v
	}
	creds := p.introspectionCreds[issuerKey]

	// POST to introspection endpoint
	form := url.Values{"token": {credential}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		err = fmt.Errorf("creating introspection request: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("introspection request failed: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("introspection endpoint returned %d: %s", resp.StatusCode, string(body))
		telemetry.SpanError(span, err)
		return nil, err
	}

	var introspResp IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspResp); err != nil {
		err = fmt.Errorf("decoding introspection response: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if !introspResp.Active {
		err := fmt.Errorf("token is not active")
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Determine principal from introspection response
	principal := introspResp.ClientID
	if principal == "" {
		principal = introspResp.Sub
	}
	if principal == "" {
		principal = "unknown"
	}

	// Determine issuer from introspection response or config
	responseIssuer := introspResp.Issuer
	if responseIssuer == "" {
		responseIssuer = issuerKey
	}

	span.SetAttributes(
		attribute.String("oauth2.issuer", responseIssuer),
		attribute.String("oauth2.principal", principal),
	)

	claims := map[string]interface{}{
		"issuer":     responseIssuer,
		"token_type": "opaque",
	}
	if introspResp.Sub != "" {
		claims["sub"] = introspResp.Sub
	}
	if introspResp.ClientID != "" {
		claims["client_id"] = introspResp.ClientID
	}
	if introspResp.Scope != "" {
		claims["scope"] = introspResp.Scope
	}

	td, ok := p.trustDomains[responseIssuer]
	if !ok {
		err := fmt.Errorf("unknown OAuth2 issuer from introspection: %s", responseIssuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	wimseURI := fmt.Sprintf("wimse://%s/oauth2/%s", td.Name, principal)

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
		err = fmt.Errorf("OAuth2: parsing JWS: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		err = fmt.Errorf("OAuth2: no signatures")
		telemetry.SpanError(span, err)
		return err
	}
	kid, _ := sigs[0].ProtectedHeaders().KeyID()
	alg, _ := sigs[0].ProtectedHeaders().Algorithm()

	pubKey, err := p.jwksResolver.ResolveKey(ctx, jwksURL, kid)
	if err != nil {
		err = fmt.Errorf("resolving key for OAuth2 token: %w", err)
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
		err = fmt.Errorf("OAuth2 JWT validation failed: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	return nil
}
