package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func loadTestAssertion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/test_assertion.xml")
	if err != nil {
		t.Fatalf("reading test assertion: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func minimalAssertion(issuer, nameID string) string {
	xml := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>%s</saml:Issuer>
  <saml:Subject>
    <saml:NameID>%s</saml:NameID>
  </saml:Subject>
</saml:Assertion>`, issuer, nameID)
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

func TestValidateWorkload(t *testing.T) {
	tests := []struct {
		name       string
		credential string
		credType   string
		devMode    bool
		trustDoms  []core.TrustDomain
		wantErr    string
		wantID     string
		wantClaims map[string]interface{}
	}{
		{
			name:       "dev mode happy path — test assertion",
			credential: loadTestAssertion(t),
			credType:   "saml",
			devMode:    true,
			wantID:     "wimse://dev.local/saml/alice@corp.example.com",
			wantClaims: map[string]interface{}{
				"issuer":  "https://idp.corp.example.com/saml2",
				"name_id": "alice@corp.example.com",
				"dev_mode": true,
			},
		},
		{
			name:       "dev mode — attribute extraction",
			credential: loadTestAssertion(t),
			credType:   "saml",
			devMode:    true,
			wantClaims: map[string]interface{}{
				"email":      "alice@corp.example.com",
				"groups":     "engineering",
				"department": "Platform",
			},
		},
		{
			name:       "dev mode — minimal assertion",
			credential: minimalAssertion("https://test.idp.com", "bob@test.com"),
			credType:   "saml",
			devMode:    true,
			wantID:     "wimse://dev.local/saml/bob@test.com",
		},
		{
			name:       "wrong cred type",
			credential: minimalAssertion("x", "y"),
			credType:   "jwt",
			devMode:    true,
			wantErr:    "unsupported credential type",
		},
		{
			name:       "malformed base64",
			credential: "not-valid-base64!!!",
			credType:   "saml",
			devMode:    true,
			wantErr:    "malformed base64",
		},
		{
			name:       "malformed XML",
			credential: base64.StdEncoding.EncodeToString([]byte("<broken>")),
			credType:   "saml",
			devMode:    true,
			wantErr:    "malformed SAML assertion XML",
		},
		{
			name:       "missing issuer",
			credential: base64.StdEncoding.EncodeToString([]byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>x</saml:NameID></saml:Subject></saml:Assertion>`)),
			credType:   "saml",
			devMode:    true,
			wantErr:    "missing Issuer",
		},
		{
			name:       "missing NameID",
			credential: base64.StdEncoding.EncodeToString([]byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID></saml:NameID></saml:Subject></saml:Assertion>`)),
			credType:   "saml",
			devMode:    true,
			wantErr:    "missing NameID",
		},
		{
			name:       "prod mode — unknown issuer",
			credential: minimalAssertion("https://unknown.idp.com", "user@test.com"),
			credType:   "saml",
			devMode:    false,
			trustDoms: []core.TrustDomain{
				{Name: "known.com", Enabled: true, Issuer: "https://known.idp.com"},
			},
			wantErr: "no certificate for SAML issuer",
		},
		{
			name:       "prod mode — no matching trust domain",
			credential: minimalAssertion("https://orphan.idp.com", "user@test.com"),
			credType:   "saml",
			devMode:    false,
			wantErr:    "no certificate for SAML issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{WithDevMode(tt.devMode)}
			if len(tt.trustDoms) > 0 {
				opts = append(opts, WithTrustDomains(tt.trustDoms))
			}

			p, err := NewProvider(opts...)
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}

			identity, err := p.ValidateWorkload(context.Background(), tt.credential, tt.credType)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantID != "" && identity.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", identity.ID, tt.wantID)
			}

			if identity.Attestation == nil || identity.Attestation.Method != "saml" {
				t.Error("Attestation should have method 'saml'")
			}

			for k, want := range tt.wantClaims {
				got, ok := identity.Claims[k]
				if !ok {
					t.Errorf("missing claim %q", k)
					continue
				}
				wantStr := fmt.Sprintf("%v", want)
				gotStr := fmt.Sprintf("%v", got)
				if gotStr != wantStr {
					t.Errorf("claim[%q] = %v, want %v", k, got, want)
				}
			}
		})
	}
}

func TestNewProvider_Options(t *testing.T) {
	p, err := NewProvider(
		WithDevMode(true),
		WithTrustDomains([]core.TrustDomain{
			{Name: "corp.com", Enabled: true, Issuer: "https://idp.corp.com"},
			{Name: "disabled.com", Enabled: false, Issuer: "https://idp.disabled.com"},
		}),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if !p.devMode {
		t.Error("devMode should be true")
	}
	if _, ok := p.trustDomains["corp.com"]; !ok {
		t.Error("corp.com trust domain should be present")
	}
	if _, ok := p.trustDomains["disabled.com"]; ok {
		t.Error("disabled.com should not be present (not enabled)")
	}
}

func TestFindTrustDomain(t *testing.T) {
	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "corp.com", Enabled: true, Issuer: "https://idp.corp.com"},
		}),
	)

	name, ok := p.findTrustDomain("https://idp.corp.com")
	if !ok || name != "corp.com" {
		t.Errorf("findTrustDomain(idp.corp.com) = %q, %v; want corp.com, true", name, ok)
	}

	_, ok = p.findTrustDomain("https://unknown.idp.com")
	if ok {
		t.Error("findTrustDomain(unknown) should return false")
	}
}

func TestBuildIdentity_NilAttributeStatement(t *testing.T) {
	p, _ := NewProvider(WithDevMode(true))
	assertion := Assertion{
		Issuer:  "https://test.idp.com",
		Subject: Subject{NameID: NameID{Value: "user@test.com"}},
	}
	id := p.buildIdentity("dev.local", "user@test.com", assertion)
	if id.ID != "wimse://dev.local/saml/user@test.com" {
		t.Errorf("ID = %q, want wimse://dev.local/saml/user@test.com", id.ID)
	}
	if _, ok := id.Claims["email"]; ok {
		t.Error("should not have email claim with nil AttributeStatement")
	}
}

func TestValidateSignature_MissingCert(t *testing.T) {
	p, _ := NewProvider()
	err := p.validateSignature([]byte("<xml/>"), "https://unknown.idp.com")
	if err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("expected 'no certificate' error, got: %v", err)
	}
}

func TestSamlAttrKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://schemas.xmlsoap.org/claims/emailaddress", "email"},
		{"http://schemas.xmlsoap.org/claims/role", "roles"},
		{"http://schemas.xmlsoap.org/claims/group", "groups"},
		{"http://schemas.xmlsoap.org/claims/department", "department"},
		{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "given_name"},
		{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "surname"},
		{"http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "roles"},
		{"urn:oid:0.9.2342.19200300.100.1.3", "email"},
		{"http://custom.example.com/custom-attr", ""},
		{"user_role_override", ""},
	}

	for _, tt := range tests {
		got := samlAttrKey(tt.input)
		if got != tt.want {
			t.Errorf("samlAttrKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidateConditions(t *testing.T) {
	p := &Provider{}

	tests := []struct {
		name    string
		conds   Conditions
		wantErr string
	}{
		{
			name:  "empty conditions — always valid",
			conds: Conditions{},
		},
		{
			name:    "expired assertion",
			conds:   Conditions{NotOnOrAfter: "2020-01-01T00:00:00Z"},
			wantErr: "expired",
		},
		{
			name:    "future assertion",
			conds:   Conditions{NotBefore: "2099-01-01T00:00:00Z"},
			wantErr: "not yet valid",
		},
		{
			name:    "invalid NotBefore format",
			conds:   Conditions{NotBefore: "not-a-date"},
			wantErr: "invalid NotBefore",
		},
		{
			name:    "invalid NotOnOrAfter format",
			conds:   Conditions{NotOnOrAfter: "not-a-date"},
			wantErr: "invalid NotOnOrAfter",
		},
		{
			name:  "valid window",
			conds: Conditions{NotBefore: "2020-01-01T00:00:00Z", NotOnOrAfter: "2099-12-31T23:59:59Z"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.validateConditions(tt.conds)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateConditions_AudienceRestriction(t *testing.T) {
	tests := []struct {
		name              string
		expectedAudiences []string
		conds             Conditions
		wantErr           string
	}{
		{
			name:              "matching audience — pass",
			expectedAudiences: []string{"https://starfly.example.com"},
			conds: Conditions{
				NotBefore:    "2020-01-01T00:00:00Z",
				NotOnOrAfter: "2099-12-31T23:59:59Z",
				AudienceRestriction: &AudienceRestriction{
					Audiences: []Audience{{Value: "https://starfly.example.com"}},
				},
			},
		},
		{
			name:              "non-matching audience — fail",
			expectedAudiences: []string{"https://other.com"},
			conds: Conditions{
				NotBefore:    "2020-01-01T00:00:00Z",
				NotOnOrAfter: "2099-12-31T23:59:59Z",
				AudienceRestriction: &AudienceRestriction{
					Audiences: []Audience{{Value: "https://starfly.example.com"}},
				},
			},
			wantErr: "audience",
		},
		{
			name:              "no expected audiences — skip check",
			expectedAudiences: nil,
			conds: Conditions{
				NotBefore:    "2020-01-01T00:00:00Z",
				NotOnOrAfter: "2099-12-31T23:59:59Z",
				AudienceRestriction: &AudienceRestriction{
					Audiences: []Audience{{Value: "https://anything.com"}},
				},
			},
		},
		{
			name:              "nil AudienceRestriction — skip check",
			expectedAudiences: []string{"https://starfly.example.com"},
			conds: Conditions{
				NotBefore:    "2020-01-01T00:00:00Z",
				NotOnOrAfter: "2099-12-31T23:59:59Z",
			},
		},
		{
			name:              "multiple audiences — one matches",
			expectedAudiences: []string{"https://starfly.example.com", "https://backup.example.com"},
			conds: Conditions{
				NotBefore:    "2020-01-01T00:00:00Z",
				NotOnOrAfter: "2099-12-31T23:59:59Z",
				AudienceRestriction: &AudienceRestriction{
					Audiences: []Audience{{Value: "https://backup.example.com"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{expectedAudiences: tt.expectedAudiences}
			err := p.validateConditions(tt.conds)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestWithIDPCertificates(t *testing.T) {
	cert := &x509.Certificate{}
	certs := map[string]*x509.Certificate{
		"https://idp.corp.com/saml2": cert,
	}
	p, err := NewProvider(WithIDPCertificates(certs))
	if err != nil {
		t.Fatal(err)
	}
	if p.idpCertificates["https://idp.corp.com/saml2"] != cert {
		t.Error("expected certificate to be set")
	}
}

func TestWithExpectedAudiences(t *testing.T) {
	p, err := NewProvider(WithExpectedAudiences([]string{"https://starfly.example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.expectedAudiences) != 1 || p.expectedAudiences[0] != "https://starfly.example.com" {
		t.Errorf("expectedAudiences = %v, want [https://starfly.example.com]", p.expectedAudiences)
	}
}

func TestWithClockSkew(t *testing.T) {
	p, err := NewProvider(WithClockSkew(30 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if p.clockSkew != 30*time.Second {
		t.Errorf("clockSkew = %v, want 30s", p.clockSkew)
	}
}

func TestValidateSignature_SignatureValidationFailsWithValidXML(t *testing.T) {
	cert := &x509.Certificate{}
	validXML := []byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.test</saml:Issuer>
</saml:Assertion>`)
	p, _ := NewProvider(WithIDPCertificates(map[string]*x509.Certificate{
		"https://idp.test": cert,
	}))
	err := p.validateSignature(validXML, "https://idp.test")
	if err == nil {
		t.Fatal("expected error for unsigned XML")
	}
	if !strings.Contains(err.Error(), "signature validation failed") {
		t.Fatalf("error = %q, want containing 'signature validation failed'", err.Error())
	}
}

func TestValidateSignature_SignatureValidationFails(t *testing.T) {
	cert := &x509.Certificate{}
	p, _ := NewProvider(WithIDPCertificates(map[string]*x509.Certificate{
		"https://idp.corp.example.com/saml2": cert,
	}))
	raw, _ := os.ReadFile("testdata/test_assertion.xml")
	err := p.validateSignature(raw, "https://idp.corp.example.com/saml2")
	if err == nil {
		t.Fatal("expected error for unsigned assertion")
	}
	if !strings.Contains(err.Error(), "signature validation failed") {
		t.Fatalf("error = %q, want containing 'signature validation failed'", err.Error())
	}
}

func TestProdMode_ValidateWorkload_UnknownIssuerAfterSignature(t *testing.T) {
	cred := minimalAssertion("https://unknown.idp.com", "user@test.com")
	p, _ := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "known.com", Enabled: true, Issuer: "https://known.idp.com"},
		}),
		WithIDPCertificates(map[string]*x509.Certificate{
			"https://unknown.idp.com": {},
		}),
	)

	_, err := p.ValidateWorkload(context.Background(), cred, "saml")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "signature validation failed") || !strings.Contains(err.Error(), "unknown SAML issuer") {
		if !strings.Contains(err.Error(), "signature validation failed") && !strings.Contains(err.Error(), "unknown SAML issuer") {
			t.Fatalf("error = %q, want containing 'signature validation failed' or 'unknown SAML issuer'", err.Error())
		}
	}
}

func assertionWithAttributes(issuer, nameID string, attrs map[string][]string) string {
	var attrElements string
	for name, values := range attrs {
		var valueElements string
		for _, v := range values {
			valueElements += fmt.Sprintf(`<saml:AttributeValue>%s</saml:AttributeValue>`, v)
		}
		attrElements += fmt.Sprintf(`<saml:Attribute Name="%s">%s</saml:Attribute>`, name, valueElements)
	}
	xml := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>%s</saml:Issuer>
  <saml:Subject>
    <saml:NameID>%s</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>%s</saml:AttributeStatement>
</saml:Assertion>`, issuer, nameID, attrElements)
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

func TestBuildIdentity_MultiValueAttributes(t *testing.T) {
	cred := assertionWithAttributes("https://idp.test", "user@test.com", map[string][]string{
		"http://schemas.xmlsoap.org/claims/role": {"admin", "viewer"},
	})

	p, _ := NewProvider(WithDevMode(true))
	identity, err := p.ValidateWorkload(context.Background(), cred, "saml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	roles, ok := identity.Claims["roles"]
	if !ok {
		t.Fatal("missing roles claim")
	}
	rolesSlice, ok := roles.([]string)
	if !ok {
		t.Fatalf("roles claim is %T, want []string", roles)
	}
	if len(rolesSlice) != 2 || rolesSlice[0] != "admin" || rolesSlice[1] != "viewer" {
		t.Errorf("roles = %v, want [admin viewer]", rolesSlice)
	}
}

func TestBuildIdentity_UnknownAttributeSkipped(t *testing.T) {
	cred := assertionWithAttributes("https://idp.test", "user@test.com", map[string][]string{
		"http://custom.example.com/custom-attr": {"custom-value"},
	})

	p, _ := NewProvider(WithDevMode(true))
	identity, err := p.ValidateWorkload(context.Background(), cred, "saml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for key := range identity.Claims {
		if key != "issuer" && key != "name_id" && key != "dev_mode" {
			t.Errorf("unexpected claim key: %q", key)
		}
	}
}

func TestValidateConditions_ClockSkew(t *testing.T) {
	futureNotBefore := time.Now().UTC().Add(10 * time.Second).Format(time.RFC3339)

	tests := []struct {
		name      string
		clockSkew time.Duration
		conds     Conditions
		wantErr   string
	}{
		{
			name:      "no clock skew — NotBefore in future fails",
			clockSkew: 0,
			conds:     Conditions{NotBefore: futureNotBefore, NotOnOrAfter: "2099-12-31T23:59:59Z"},
			wantErr:   "not yet valid",
		},
		{
			name:      "30s clock skew — NotBefore 10s in future passes",
			clockSkew: 30 * time.Second,
			conds:     Conditions{NotBefore: futureNotBefore, NotOnOrAfter: "2099-12-31T23:59:59Z"},
		},
		{
			name:      "no clock skew — recently expired fails",
			clockSkew: 0,
			conds: Conditions{
				NotBefore:    "2020-01-01T00:00:00Z",
				NotOnOrAfter: time.Now().UTC().Add(-5 * time.Second).Format(time.RFC3339),
			},
			wantErr: "expired",
		},
		{
			name:      "30s clock skew — recently expired passes",
			clockSkew: 30 * time.Second,
			conds: Conditions{
				NotBefore:    "2020-01-01T00:00:00Z",
				NotOnOrAfter: time.Now().UTC().Add(-5 * time.Second).Format(time.RFC3339),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{clockSkew: tt.clockSkew}
			err := p.validateConditions(tt.conds)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
