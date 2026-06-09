package mtls

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/mtls"
	credType   = "mtls"
)

var _ core.IdentityProvider = (*Provider)(nil)

// Provider validates PEM-encoded X.509 client certificates (passed as
// base64 of the PEM) and returns WorkloadIdentity.
type Provider struct {
	trustDomains map[string]core.TrustDomain
	rootCAs      map[string]*x509.CertPool // keyed by trust domain name
	devMode      bool
}

// Option configures a Provider.
type Option func(*Provider)

// WithTrustDomains configures the set of recognised trust domains.
func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

// WithRootCAs registers a CA certificate pool for a trust domain.
// The pool is used during chain verification in prod mode.
func WithRootCAs(trustDomain string, pool *x509.CertPool) Option {
	return func(p *Provider) {
		p.rootCAs[trustDomain] = pool
	}
}

// WithDevMode enables development mode. In dev mode certificate chain
// verification is skipped and the trust domain defaults to "dev.local".
func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

// NewProvider creates a new mTLS identity provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains: make(map[string]core.TrustDomain),
		rootCAs:      make(map[string]*x509.CertPool),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// ValidateWorkload validates a base64-encoded PEM X.509 client certificate
// and returns the resolved WorkloadIdentity.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "identity.mtls.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 1. Base64 decode the credential.
	derPEM, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		err = fmt.Errorf("malformed base64 credential: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 2. PEM decode.
	block, _ := pem.Decode(derPEM)
	if block == nil {
		err = fmt.Errorf("credential is not valid PEM")
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 3. Parse the X.509 certificate.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("invalid X.509 certificate: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 4. Extract identity from the certificate.
	idURI, err := extractIdentity(cert)
	if err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	// 5. Build claims from certificate fields.
	claims := buildClaims(cert)

	// 6. Determine trust domain and verify chain.
	var trustDomain string

	if p.devMode {
		trustDomain = "dev.local"
		claims["dev_mode"] = true
		span.SetAttributes(
			attribute.String("mtls.trust_domain", trustDomain),
			attribute.String("mtls.identity", idURI),
		)

		wimseURI := replaceIDTrustDomain(idURI, trustDomain)
		return &core.WorkloadIdentity{
			ID:          wimseURI,
			TrustDomain: trustDomain,
			Attestation: &core.AttestationEvidence{
				Method:    credType,
				Timestamp: time.Now().UTC(),
			},
			Claims: claims,
		}, nil
	}

	// Prod mode: verify certificate chain against configured CA pools.
	verified := false
	for tdName, pool := range p.rootCAs {
		_, verifyErr := cert.Verify(x509.VerifyOptions{
			Roots:       pool,
			CurrentTime: time.Now(),
		})
		if verifyErr == nil {
			trustDomain = tdName
			verified = true
			break
		}
	}

	if !verified {
		err = fmt.Errorf("certificate not trusted by any configured CA")
		telemetry.SpanError(span, err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("mtls.trust_domain", trustDomain),
		attribute.String("mtls.identity", idURI),
	)

	wimseURI := replaceIDTrustDomain(idURI, trustDomain)
	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: trustDomain,
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: claims,
	}, nil
}

// extractIdentity derives a WIMSE URI from the certificate's identity
// fields. Priority: SPIFFE URI SAN > DNS SAN > Subject CN.
// The returned URI uses a placeholder trust domain "{td}" that is replaced
// later once the trust domain is resolved.
func extractIdentity(cert *x509.Certificate) (string, error) {
	// Check URI SANs first — look for spiffe:// URIs.
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			td := u.Host
			path := strings.TrimPrefix(u.Path, "/")
			_ = td // trust domain from SPIFFE URI is informational here
			return fmt.Sprintf("wimse://{td}/mtls/spiffe/%s", path), nil
		}
	}

	// Check DNS SANs next.
	if len(cert.DNSNames) > 0 {
		return fmt.Sprintf("wimse://{td}/mtls/dns/%s", cert.DNSNames[0]), nil
	}

	// Fall back to Subject CN.
	if cert.Subject.CommonName != "" {
		return fmt.Sprintf("wimse://{td}/mtls/cn/%s", cert.Subject.CommonName), nil
	}

	return "", fmt.Errorf("certificate has no identifiable subject")
}

// replaceIDTrustDomain substitutes the "{td}" placeholder in the identity URI
// with the resolved trust domain.
func replaceIDTrustDomain(idURI, td string) string {
	return strings.Replace(idURI, "{td}", td, 1)
}

// buildClaims extracts standard certificate fields into a claims map.
func buildClaims(cert *x509.Certificate) map[string]interface{} {
	claims := map[string]interface{}{
		"subject_cn": cert.Subject.CommonName,
		"issuer_cn":  cert.Issuer.CommonName,
		"serial":     cert.SerialNumber.Text(16),
		"not_after":  cert.NotAfter.Format(time.RFC3339),
	}

	if len(cert.DNSNames) > 0 {
		claims["sans_dns"] = cert.DNSNames
	}

	if len(cert.URIs) > 0 {
		uris := make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
		}
		claims["sans_uri"] = uris
	}

	if len(cert.EmailAddresses) > 0 {
		claims["sans_email"] = cert.EmailAddresses
	}

	return claims
}

// suppress unused import warning — url is used by extractIdentity via cert.URIs.
var _ = (*url.URL)(nil)
