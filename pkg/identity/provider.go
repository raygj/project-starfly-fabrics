package identity

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const tracerName = "github.com/starfly-fabrics/starfly/pkg/identity"


// Provider implements core.IdentityProvider for K8s ServiceAccount
// validation via OIDC/JWKS. It validates SA JWTs against the cluster's
// JWKS endpoint and returns a WorkloadIdentity with a WIMSE URI.
type Provider struct {
	trustDomains map[string]core.TrustDomain // keyed by Issuer
	jwksCache    *jwk.Cache
	devMode      bool
}

var _ core.IdentityProvider = (*Provider)(nil)

// New creates a Provider that validates K8s ServiceAccount JWTs.
// It indexes enabled trust domains by Issuer and registers each
// JWKSURL with a jwk.Cache for automatic key refresh.
// When devMode is true, signature and issuer verification are skipped.
func New(ctx context.Context, domains []core.TrustDomain, devMode bool) (*Provider, error) {
	p := &Provider{
		trustDomains: make(map[string]core.TrustDomain),
		devMode:      devMode,
	}

	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache: %w", err)
	}
	p.jwksCache = cache

	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		if d.Issuer == "" || d.JWKSURL == "" {
			continue
		}
		regCtx, regCancel := context.WithTimeout(ctx, 5*time.Second)
		regErr := cache.Register(regCtx, d.JWKSURL, jwk.WithMinInterval(15*time.Minute))
		regCancel()
		if regErr != nil {
			// Non-fatal: skip unreachable JWKS endpoints (e.g. SPIRE not running).
			// Tokens from this issuer will fail validation at runtime.
			slog.Warn("k8s identity provider: skipping unreachable JWKS URL",
				"issuer", d.Issuer, "url", d.JWKSURL, "error", regErr)
			continue
		}
		p.trustDomains[d.Issuer] = d
	}

	return p, nil
}

// ValidateWorkload validates a K8s ServiceAccount JWT and returns
// a WorkloadIdentity with a WIMSE URI.
// In dev mode, signature and issuer verification are skipped — any
// parseable JWT is accepted with a synthetic "dev.local" trust domain.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, credType string) (*core.WorkloadIdentity, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "identity.ValidateWorkload")
	defer span.End()

	if credType != "k8s-sa" {
		err := fmt.Errorf("unsupported credential type: %s", credType)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Parse JWT without verification to extract issuer for trust domain lookup.
	insecureToken, err := jwt.ParseInsecure([]byte(credential))
	if err != nil {
		return nil, fmt.Errorf("malformed JWT: %w", err)
	}

	// Dev mode: skip issuer lookup and signature verification.
	if p.devMode {
		sub, _ := insecureToken.Subject()
		issuer, _ := insecureToken.Issuer()
		if sub == "" {
			sub = "dev-workload"
		}

		ns := claimString(insecureToken, "namespace", "kubernetes.io", "namespace")
		sa := claimString(insecureToken, "serviceaccount", "kubernetes.io", "serviceaccount", "name")
		if ns == "" {
			ns = "default"
		}
		if sa == "" {
			sa = sub
		}

		// If sa is already a fully-qualified WIMSE URI (e.g. a cross-fabric WIMSE JWT
		// presented as subject_token), use it directly to avoid double-prefixing.
		var wimseURI string
		if strings.HasPrefix(sa, "wimse://") {
			wimseURI = sa
		} else {
			wimseURI = fmt.Sprintf("wimse://dev.local/ns/%s/sa/%s", ns, sa)
		}

		span.SetAttributes(
			attribute.String("trust_domain", "dev.local"),
			attribute.String("attestation.method", "dev-bypass"),
		)
		return &core.WorkloadIdentity{
			ID:          wimseURI,
			TrustDomain: "dev.local",
			Attestation: &core.AttestationEvidence{
				Method:    "dev-bypass",
				Timestamp: time.Now().UTC(),
				Namespace: ns,
			},
			Claims: map[string]interface{}{
				"namespace":      ns,
				"serviceaccount": sa,
				"issuer":         issuer,
				"dev_mode":       true,
			},
		}, nil
	}

	issuer, _ := insecureToken.Issuer()
	td, ok := p.trustDomains[issuer]
	if !ok {
		err := fmt.Errorf("unknown issuer: %s", issuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// Fetch JWKS from cache and verify signature + claims.
	keyset, err := p.jwksCache.Lookup(ctx, td.JWKSURL)
	if err != nil {
		err = fmt.Errorf("fetching JWKS: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	token, err := jwt.Parse([]byte(credential),
		jwt.WithKeySet(keyset, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
	)
	if err != nil {
		err = fmt.Errorf("token validation failed: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	ns := claimString(token, "namespace", "kubernetes.io", "namespace")
	sa := claimString(token, "serviceaccount", "kubernetes.io", "serviceaccount", "name")
	pod := claimString(token, "", "kubernetes.io", "pod", "name")
	node := claimString(token, "", "kubernetes.io", "node", "name")

	wimseURI := fmt.Sprintf("wimse://%s/ns/%s/sa/%s", td.Name, ns, sa)

	span.SetAttributes(
		attribute.String("trust_domain", td.Name),
		attribute.String("attestation.method", "k8s-sa"),
	)

	claims := map[string]interface{}{
		"namespace":      ns,
		"serviceaccount": sa,
	}
	if pod != "" {
		claims["pod"] = pod
	}
	if node != "" {
		claims["node"] = node
	}

	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: td.Name,
		Attestation: &core.AttestationEvidence{
			Method:    "k8s-sa",
			Timestamp: time.Now().UTC(),
			Namespace: ns,
			NodeID:    node,
		},
		Claims: claims,
	}, nil
}

// claimString extracts a string claim from a JWT token. It first tries the
// nested path (e.g., kubernetes.io → namespace) and falls back to flatKey.
func claimString(token jwt.Token, flatKey string, path ...string) string {
	if len(path) >= 2 {
		var v interface{}
		if err := token.Get(path[0], &v); err == nil {
			val := v
			for _, key := range path[1:] {
				m, ok := val.(map[string]interface{})
				if !ok {
					break
				}
				val, ok = m[key]
				if !ok {
					break
				}
			}
			if s, ok := val.(string); ok {
				return s
			}
		}
	}
	if flatKey != "" {
		var v interface{}
		if err := token.Get(flatKey, &v); err == nil {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}
