package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	tracerName = "github.com/starfly-fabrics/starfly/pkg/identity/saml"
	credType   = "saml"
)

var _ core.IdentityProvider = (*Provider)(nil)

// Provider validates SAML 2.0 assertions and returns WorkloadIdentity.
type Provider struct {
	trustDomains      map[string]core.TrustDomain
	idpCertificates   map[string]*x509.Certificate
	expectedAudiences []string
	clockSkew         time.Duration
	devMode           bool
}

// Option configures the Provider.
type Option func(*Provider)

// WithTrustDomains maps SAML issuers to WIMSE trust domains.
func WithTrustDomains(domains []core.TrustDomain) Option {
	return func(p *Provider) {
		for _, d := range domains {
			if d.Enabled {
				p.trustDomains[d.Name] = d
			}
		}
	}
}

// WithIDPCertificates maps issuer URIs to their signing certificates.
func WithIDPCertificates(certs map[string]*x509.Certificate) Option {
	return func(p *Provider) { p.idpCertificates = certs }
}

// WithDevMode enables development mode (skips signature and condition validation).
func WithDevMode(dev bool) Option {
	return func(p *Provider) { p.devMode = dev }
}

// WithExpectedAudiences sets the allowed audience URIs for AudienceRestriction validation.
func WithExpectedAudiences(audiences []string) Option {
	return func(p *Provider) { p.expectedAudiences = audiences }
}

// WithClockSkew sets the tolerance for time-based condition checks.
func WithClockSkew(d time.Duration) Option {
	return func(p *Provider) { p.clockSkew = d }
}

// NewProvider creates a SAML identity provider.
func NewProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		trustDomains:   make(map[string]core.TrustDomain),
		idpCertificates: make(map[string]*x509.Certificate),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Assertion represents a minimal SAML 2.0 assertion for parsing.
type Assertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	Issuer             string              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            Subject             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions         Conditions          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AttributeStatement *AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// AttributeStatement wraps the list of SAML attributes.
type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Subject contains the assertion subject.
type Subject struct {
	NameID NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// NameID identifies the assertion subject.
type NameID struct {
	Format string `xml:"Format,attr,omitempty"`
	Value  string `xml:",chardata"`
}

// Conditions contains assertion validity constraints.
type Conditions struct {
	NotBefore           string               `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter        string               `xml:"NotOnOrAfter,attr,omitempty"`
	AudienceRestriction *AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

// AudienceRestriction contains the allowed audiences for a SAML assertion.
type AudienceRestriction struct {
	Audiences []Audience `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// Audience identifies an intended audience of the assertion.
type Audience struct {
	Value string `xml:",chardata"`
}

// Attribute represents a SAML attribute.
type Attribute struct {
	Name   string           `xml:"Name,attr"`
	Values []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// AttributeValue holds a single SAML attribute value.
type AttributeValue struct {
	Value string `xml:",chardata"`
}

// ValidateWorkload validates a base64-encoded SAML assertion and returns a WIMSE WorkloadIdentity.
func (p *Provider) ValidateWorkload(ctx context.Context, credential string, ct string) (*core.WorkloadIdentity, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "identity.saml.ValidateWorkload")
	defer span.End()

	if ct != credType {
		err := fmt.Errorf("unsupported credential type: %s", ct)
		telemetry.SpanError(span, err)
		return nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		err = fmt.Errorf("malformed base64 credential: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	var assertion Assertion
	if err := xml.Unmarshal(raw, &assertion); err != nil {
		err = fmt.Errorf("malformed SAML assertion XML: %w", err)
		telemetry.SpanError(span, err)
		return nil, err
	}

	if assertion.Issuer == "" {
		err := fmt.Errorf("SAML assertion missing Issuer")
		telemetry.SpanError(span, err)
		return nil, err
	}

	nameID := strings.TrimSpace(assertion.Subject.NameID.Value)
	if nameID == "" {
		err := fmt.Errorf("SAML assertion missing NameID")
		telemetry.SpanError(span, err)
		return nil, err
	}

	span.SetAttributes(
		attribute.String("saml.issuer", assertion.Issuer),
		attribute.String("saml.name_id", nameID),
	)

	if p.devMode {
		return p.buildIdentity("dev.local", nameID, assertion), nil
	}

	if err := p.validateSignature(raw, assertion.Issuer); err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	if err := p.validateConditions(assertion.Conditions); err != nil {
		telemetry.SpanError(span, err)
		return nil, err
	}

	domain, ok := p.findTrustDomain(assertion.Issuer)
	if !ok {
		err := fmt.Errorf("unknown SAML issuer: %s", assertion.Issuer)
		telemetry.SpanError(span, err)
		return nil, err
	}

	return p.buildIdentity(domain, nameID, assertion), nil
}

func (p *Provider) validateSignature(rawXML []byte, issuer string) error {
	cert, ok := p.idpCertificates[issuer]
	if !ok {
		return fmt.Errorf("no certificate for SAML issuer: %s", issuer)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawXML); err != nil {
		return fmt.Errorf("parsing XML for signature validation: %w", err)
	}

	certStore := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(&certStore)
	_, err := ctx.Validate(doc.Root())
	if err != nil {
		return fmt.Errorf("SAML signature validation failed: %w", err)
	}
	return nil
}

func (p *Provider) validateConditions(conds Conditions) error {
	now := time.Now().UTC()

	if conds.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, conds.NotBefore)
		if err != nil {
			return fmt.Errorf("invalid NotBefore: %w", err)
		}
		if now.Before(nb.Add(-p.clockSkew)) {
			return fmt.Errorf("assertion not yet valid (NotBefore: %s)", conds.NotBefore)
		}
	}

	if conds.NotOnOrAfter != "" {
		noa, err := time.Parse(time.RFC3339, conds.NotOnOrAfter)
		if err != nil {
			return fmt.Errorf("invalid NotOnOrAfter: %w", err)
		}
		if now.After(noa.Add(p.clockSkew)) || now.Equal(noa.Add(p.clockSkew)) {
			return fmt.Errorf("assertion expired (NotOnOrAfter: %s)", conds.NotOnOrAfter)
		}
	}

	if len(p.expectedAudiences) > 0 && conds.AudienceRestriction != nil {
		matched := false
		for _, aud := range conds.AudienceRestriction.Audiences {
			for _, expected := range p.expectedAudiences {
				if aud.Value == expected {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return fmt.Errorf("assertion audience not in expected audiences")
		}
	}

	return nil
}

func (p *Provider) findTrustDomain(issuer string) (string, bool) {
	for name, td := range p.trustDomains {
		if td.Issuer == issuer {
			return name, true
		}
	}
	return "", false
}

func (p *Provider) buildIdentity(trustDomain, nameID string, assertion Assertion) *core.WorkloadIdentity {
	wimseURI := fmt.Sprintf("wimse://%s/saml/%s", trustDomain, nameID)
	claims := map[string]interface{}{
		"issuer":  assertion.Issuer,
		"name_id": nameID,
	}
	if p.devMode {
		claims["dev_mode"] = true
	}

	var attrs []Attribute
	if assertion.AttributeStatement != nil {
		attrs = assertion.AttributeStatement.Attributes
	}
	for _, attr := range attrs {
		key := samlAttrKey(attr.Name)
		if key == "" {
			continue
		}
		vals := make([]string, 0, len(attr.Values))
		for _, v := range attr.Values {
			vals = append(vals, v.Value)
		}
		if len(vals) == 1 {
			claims[key] = vals[0]
		} else if len(vals) > 1 {
			claims[key] = vals
		}
	}

	return &core.WorkloadIdentity{
		ID:          wimseURI,
		TrustDomain: trustDomain,
		Attestation: &core.AttestationEvidence{
			Method:    credType,
			Timestamp: time.Now().UTC(),
		},
		Claims: claims,
	}
}

// samlAttrMap provides an explicit URI-to-claim-key mapping for standard
// SAML attribute URIs. Replaces substring matching per ADR-0007 #3.
var samlAttrMap = map[string]string{
	// SOAP/WS-Federation claim URIs
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":  "email",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":     "given_name",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":       "surname",
	"http://schemas.xmlsoap.org/claims/emailaddress":                      "email",
	"http://schemas.xmlsoap.org/claims/Group":                             "groups",
	"http://schemas.xmlsoap.org/claims/group":                             "groups",
	"http://schemas.xmlsoap.org/claims/role":                              "roles",
	"http://schemas.xmlsoap.org/claims/department":                        "department",
	// Microsoft ADFS claim URIs
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/role":        "roles",
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups":      "groups",
	// OASIS SAML attribute name URIs
	"urn:oid:0.9.2342.19200300.100.1.3":                                   "email",
	"urn:oid:2.5.4.42":                                                    "given_name",
	"urn:oid:2.5.4.4":                                                     "surname",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.7":                                   "roles",
	"urn:oid:1.3.6.1.4.1.5923.1.5.1.1":                                   "groups",
}

// samlAttrKey looks up a SAML attribute URI in the explicit mapping table.
func samlAttrKey(name string) string {
	return samlAttrMap[name]
}
