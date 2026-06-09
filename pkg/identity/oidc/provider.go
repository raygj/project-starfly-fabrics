package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/oidc"
	credType   = "oidc"
)

var _ core.IdentityProvider = (*Provider)(nil)

// Provider validates OIDC tokens (ID tokens and access tokens) from
// any OIDC-compliant issuer and returns WorkloadIdentity.
type Provider struct {
	trustDomains      map[string]core.TrustDomain // keyed by Issuer
	jwksResolver      core.JWKSResolver
	expectedAudiences []string
	devMode           bool
}

type Option func(*Provider)

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

// WithExpectedAudiences configures audience validation. If non-empty,
// at least one token audience must match one expected audience.
func WithExpectedAudiences(audiences []string) Option {
	return func(p *Provider) { p.expectedAudiences = audiences }
}

func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains: make(map[string]core.TrustDomain),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.oidc.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	insecureToken, err := jwt.ParseInsecure([]byte(credential))
	if err != nil {
		err = fmt.Errorf("malformed OIDC token: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	issuer, ok := insecureToken.Issuer()
	if !ok || issuer == "" {
		err = fmt.Errorf("OIDC token missing iss claim")
		telemetry.SpanError(span, err)
		return nil, err
	}

	sub, ok := insecureToken.Subject()
	if !ok || sub == "" {
		err = fmt.Errorf("OIDC token missing sub claim")
		telemetry.SpanError(span, err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("oidc.issuer", issuer),
		attribute.String("oidc.subject", sub),
	)

	claims := map[string]interface{}{
		"issuer":  issuer,
		"subject": sub,
	}
	extractOptionalClaim(insecureToken, "email", claims)
	extractOptionalClaim(insecureToken, "groups", claims)
	extractOptionalClaim(insecureToken, "roles", claims)
	extractOptionalClaim(insecureToken, "azp", claims)

	if p.devMode {
		claims["dev_mode"] = true
		wimseURI := fmt.Sprintf("wimse://dev.local/oidc/%s", sub)
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
		err = fmt.Errorf("unknown OIDC issuer: %s", issuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if p.jwksResolver != nil {
		if err := p.verifyWithResolver(ctx, credential, td.JWKSURL, span); err != nil {
			return nil, err
		}
	} else if td.JWKSURL != "" {
		keyset, fetchErr := jwk.Fetch(ctx, td.JWKSURL)
		if fetchErr != nil {
			err = fmt.Errorf("fetching JWKS for %s: %w", issuer, fetchErr)
			telemetry.SpanError(span, err)
			return nil, err
		}
		_, err = jwt.Parse([]byte(credential),
			jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithValidate(true),
		)
		if err != nil {
			err = fmt.Errorf("OIDC token validation failed: %w", err)
			telemetry.SpanError(span, err)
			return nil, err
		}
	} else {
		err = fmt.Errorf("no JWKS URL or resolver for issuer: %s", issuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if len(p.expectedAudiences) > 0 {
		tokenAud, ok := insecureToken.Audience()
		if !ok {
			err = fmt.Errorf("OIDC token missing aud claim")
			telemetry.SpanError(span, err)
			return nil, err
		}
		matched := false
		for _, ta := range tokenAud {
			for _, ea := range p.expectedAudiences {
				if ta == ea {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			err = fmt.Errorf("OIDC token audience %v not in expected audiences %v", tokenAud, p.expectedAudiences)
			telemetry.SpanError(span, err)
			return nil, err
		}
	}

	wimseURI := fmt.Sprintf("wimse://%s/oidc/%s", td.Name, sub)

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
		err = fmt.Errorf("OIDC: parsing JWS: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		err = fmt.Errorf("OIDC: no signatures")
		telemetry.SpanError(span, err)
		return err
	}
	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok {
		err = fmt.Errorf("OIDC: missing kid in JWS header")
		telemetry.SpanError(span, err)
		return err
	}
	alg, ok := sigs[0].ProtectedHeaders().Algorithm()
	if !ok {
		err = fmt.Errorf("OIDC: missing algorithm in JWS header")
		telemetry.SpanError(span, err)
		return err
	}

	pubKey, err := p.jwksResolver.ResolveKey(ctx, jwksURL, kid)
	if err != nil {
		err = fmt.Errorf("resolving key for OIDC token: %w", err)
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
		err = fmt.Errorf("OIDC token validation failed: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	return nil
}

func extractOptionalClaim(tok jwt.Token, key string, out map[string]interface{}) {
	var v interface{}
	if err := tok.Get(key, &v); err == nil && v != nil {
		out[key] = v
	}
}
