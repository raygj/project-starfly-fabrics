package spiffe

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
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
	tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/spiffe"
	credType   = "spiffe-svid"
)

var _ core.IdentityProvider = (*Provider)(nil)

// Provider validates SPIFFE JWT-SVIDs and returns WorkloadIdentity.
type Provider struct {
	trustDomains map[string]core.TrustDomain
	jwksResolver core.JWKSResolver
	devMode      bool
}

type Option func(*Provider)

func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

// WithJWKSResolver injects a shared JWKS resolver for signature verification.
func WithJWKSResolver(r core.JWKSResolver) Option {
	return func(p *Provider) { p.jwksResolver = r }
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
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.spiffe.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	insecureToken, err := jwt.ParseInsecure([]byte(credential))
	if err != nil {
		err = fmt.Errorf("malformed JWT-SVID: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	sub, ok := insecureToken.Subject()
	if !ok || sub == "" {
		err = fmt.Errorf("JWT-SVID missing sub claim")
		telemetry.SpanError(span, err)
		return nil, err
	}

	td, workloadPath, err := parseSpiffeID(sub)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("spiffe.trust_domain", td),
		attribute.String("spiffe.workload_path", workloadPath),
	)

	if p.devMode {
		wimseURI := fmt.Sprintf("wimse://dev.local/spiffe/%s", workloadPath)
		return &core.WorkloadIdentity{
			ID:          wimseURI,
			TrustDomain: "dev.local",
			Attestation: &core.AttestationEvidence{
				Method:    credType,
				Timestamp: time.Now().UTC(),
			},
			Claims: map[string]interface{}{
				"spiffe_id":    sub,
				"trust_domain": td,
				"dev_mode":     true,
			},
		}, nil
	}

	domain, ok := p.trustDomains[td]
	if !ok {
		err = fmt.Errorf("unknown SPIFFE trust domain: %s", td)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if p.jwksResolver != nil {
		if err := p.verifyWithResolver(ctx, credential, domain.JWKSURL, span); err != nil {
			return nil, err
		}
	} else if domain.JWKSURL != "" {
		keyset, fetchErr := jwk.Fetch(ctx, domain.JWKSURL)
		if fetchErr != nil {
			err = fmt.Errorf("fetching JWKS for %s: %w", td, fetchErr)
			telemetry.SpanError(span, err)
			return nil, err
		}
		_, err = jwt.Parse([]byte(credential),
			jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithValidate(true),
		)
		if err != nil {
			err = fmt.Errorf("JWT-SVID validation failed: %w", err)
			telemetry.SpanError(span, err)
			return nil, err
		}
	} else {
		err = fmt.Errorf("no JWKS URL or resolver for trust domain: %s", td)
		telemetry.SpanError(span, err)
		return nil, err
	}

	wimseURI := fmt.Sprintf("wimse://%s/spiffe/%s", td, workloadPath)

	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: td,
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: map[string]interface{}{
			"spiffe_id":    sub,
			"trust_domain": td,
		},
	}, nil
}

// verifyWithResolver extracts the kid from the JWS header, resolves the public
// key via the shared JWKSResolver, and verifies the JWT signature.
func (p *Provider) verifyWithResolver(ctx context.Context, credential, jwksURL string, span trace.Span) error {
	msg, err := jws.Parse([]byte(credential))
	if err != nil {
		err = fmt.Errorf("JWT-SVID: parsing JWS: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		err = fmt.Errorf("JWT-SVID: no signatures")
		telemetry.SpanError(span, err)
		return err
	}
	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok {
		err = fmt.Errorf("JWT-SVID: missing kid in JWS header")
		telemetry.SpanError(span, err)
		return err
	}
	alg, ok := sigs[0].ProtectedHeaders().Algorithm()
	if !ok {
		err = fmt.Errorf("JWT-SVID: missing algorithm in JWS header")
		telemetry.SpanError(span, err)
		return err
	}

	pubKey, err := p.jwksResolver.ResolveKey(ctx, jwksURL, kid)
	if err != nil {
		err = fmt.Errorf("resolving key for SPIFFE SVID: %w", err)
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
		err = fmt.Errorf("JWT-SVID validation failed: %w", err)
		telemetry.SpanError(span, err)
		return err
	}
	return nil
}

// parseSpiffeID extracts trust domain and workload path from a SPIFFE ID.
// Format: spiffe://<trust_domain>/<workload_path>
func parseSpiffeID(spiffeID string) (trustDomain, workloadPath string, err error) {
	u, err := url.Parse(spiffeID)
	if err != nil || u.Scheme != "spiffe" {
		return "", "", fmt.Errorf("invalid SPIFFE ID: %q", spiffeID)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("SPIFFE ID missing trust domain: %q", spiffeID)
	}
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		return "", "", fmt.Errorf("SPIFFE ID missing workload path: %q", spiffeID)
	}
	return u.Host, path, nil
}

// suppress unused import warnings — jwa is used by the keyset verification path.
var _ = jwa.RS256
