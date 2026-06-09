package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// testCertOpts controls how mintTestCert generates certificates.
type testCertOpts struct {
	cn       string
	dnsNames []string
	uris     []*url.URL
	emails   []string
	ips      []net.IP
	ca       *x509.Certificate // nil = self-signed
	caKey    *ecdsa.PrivateKey
	isCA     bool
	notAfter time.Time // zero = 1 hour from now
}

// mintTestCert generates an ECDSA P-256 certificate. If opts.ca is nil the
// certificate is self-signed; otherwise it is signed by the provided CA.
// Returns the parsed certificate and the private key used.
func mintTestCert(t *testing.T, opts testCertOpts) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(1 * time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: opts.cn},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     opts.dnsNames,
		URIs:         opts.uris,
		EmailAddresses: opts.emails,
		IPAddresses:  opts.ips,
	}

	if opts.isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.BasicConstraintsValid = true
	}

	parent := tmpl
	signingKey := key
	if opts.ca != nil {
		parent = opts.ca
		signingKey = opts.caKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key
}

// encodeCert PEM-encodes then base64-encodes a certificate, matching the
// credential format expected by the provider.
func encodeCert(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return base64.StdEncoding.EncodeToString(pemBytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestInterfaceAssertion(t *testing.T) {
	var _ core.IdentityProvider = (*Provider)(nil)
}

func TestDevMode_SubjectCN(t *testing.T) {
	cert, _ := mintTestCert(t, testCertOpts{cn: "my-workload"})
	cred := encodeCert(t, cert)

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "mtls")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://dev.local/mtls/cn/my-workload"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
	if identity.TrustDomain != "dev.local" {
		t.Errorf("TrustDomain = %q, want dev.local", identity.TrustDomain)
	}
	if identity.Attestation.Method != "mtls" {
		t.Errorf("Attestation.Method = %q, want mtls", identity.Attestation.Method)
	}
	if identity.Claims["subject_cn"] != "my-workload" {
		t.Errorf("subject_cn = %v, want my-workload", identity.Claims["subject_cn"])
	}
}

func TestDevMode_DNSSan(t *testing.T) {
	cert, _ := mintTestCert(t, testCertOpts{
		cn:       "ignored-cn",
		dnsNames: []string{"api.example.com"},
	})
	cred := encodeCert(t, cert)

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "mtls")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://dev.local/mtls/dns/api.example.com"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
}

func TestDevMode_SPIFFEID(t *testing.T) {
	spiffeURI, _ := url.Parse("spiffe://example.com/workload/api")
	cert, _ := mintTestCert(t, testCertOpts{
		cn:   "spiffe-workload",
		uris: []*url.URL{spiffeURI},
	})
	cred := encodeCert(t, cert)

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "mtls")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://dev.local/mtls/spiffe/workload/api"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
}

func TestDevMode_URISanPriority(t *testing.T) {
	spiffeURI, _ := url.Parse("spiffe://example.com/workload/api")
	cert, _ := mintTestCert(t, testCertOpts{
		cn:       "ignored",
		dnsNames: []string{"api.example.com"},
		uris:     []*url.URL{spiffeURI},
	})
	cred := encodeCert(t, cert)

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "mtls")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SPIFFE URI SAN should take priority over DNS SAN.
	wantURI := "wimse://dev.local/mtls/spiffe/workload/api"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q (SPIFFE URI should take priority over DNS SAN)", identity.ID, wantURI)
	}
}

func TestProdMode_TrustedCA(t *testing.T) {
	// Create a CA.
	caCert, caKey := mintTestCert(t, testCertOpts{
		cn:   "Test CA",
		isCA: true,
	})

	// Create a leaf cert signed by the CA.
	leaf, _ := mintTestCert(t, testCertOpts{
		cn:       "prod-workload",
		dnsNames: []string{"prod.example.com"},
		ca:       caCert,
		caKey:    caKey,
	})
	cred := encodeCert(t, leaf)

	// Build a cert pool containing the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	p, err := NewProvider(
		WithTrustDomains([]core.TrustDomain{
			{Name: "example.com", Enabled: true},
		}),
		WithRootCAs("example.com", pool),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	identity, err := p.ValidateWorkload(context.Background(), cred, "mtls")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURI := "wimse://example.com/mtls/dns/prod.example.com"
	if identity.ID != wantURI {
		t.Errorf("ID = %q, want %q", identity.ID, wantURI)
	}
	if identity.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want example.com", identity.TrustDomain)
	}
	if identity.Attestation.Method != "mtls" {
		t.Errorf("Attestation.Method = %q, want mtls", identity.Attestation.Method)
	}
}

func TestProdMode_UntrustedCA(t *testing.T) {
	// Create a CA that is NOT in the provider's trust store.
	unknownCA, unknownKey := mintTestCert(t, testCertOpts{
		cn:   "Unknown CA",
		isCA: true,
	})

	leaf, _ := mintTestCert(t, testCertOpts{
		cn:    "untrusted-workload",
		ca:    unknownCA,
		caKey: unknownKey,
	})
	cred := encodeCert(t, leaf)

	// Create a pool with a DIFFERENT CA.
	trustedCA, _ := mintTestCert(t, testCertOpts{
		cn:   "Trusted CA",
		isCA: true,
	})
	pool := x509.NewCertPool()
	pool.AddCert(trustedCA)

	p, err := NewProvider(
		WithRootCAs("example.com", pool),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, "mtls")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("error = %q, want containing 'not trusted'", err.Error())
	}
}

func TestProdMode_ExpiredCert(t *testing.T) {
	// Create a CA.
	caCert, caKey := mintTestCert(t, testCertOpts{
		cn:   "Test CA",
		isCA: true,
	})

	// Create a leaf cert that is already expired.
	leaf, _ := mintTestCert(t, testCertOpts{
		cn:       "expired-workload",
		ca:       caCert,
		caKey:    caKey,
		notAfter: time.Now().Add(-1 * time.Hour), // expired 1 hour ago
	})
	cred := encodeCert(t, leaf)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	p, err := NewProvider(
		WithRootCAs("example.com", pool),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, "mtls")
	if err == nil {
		t.Fatal("expected error for expired cert, got nil")
	}
	// x509.Verify returns an error for expired certs; it will hit the
	// "not trusted" path since verification fails.
	if !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("error = %q, want containing 'not trusted'", err.Error())
	}
}

func TestWrongCredType(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "anything", "oidc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported credential type") {
		t.Fatalf("error = %q, want containing 'unsupported credential type'", err.Error())
	}
}

func TestMalformedBase64(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), "!!!not-base64!!!", "mtls")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "malformed base64") {
		t.Fatalf("error = %q, want containing 'malformed base64'", err.Error())
	}
}

func TestMalformedPEM(t *testing.T) {
	// Valid base64 but not PEM content.
	notPEM := base64.StdEncoding.EncodeToString([]byte("this is not PEM data"))

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), notPEM, "mtls")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not valid PEM") {
		t.Fatalf("error = %q, want containing 'not valid PEM'", err.Error())
	}
}

func TestNoCertIdentity(t *testing.T) {
	// Create a cert with no CN, no SANs — empty subject.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{}, // no CN
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// no DNSNames, URIs, or EmailAddresses
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	cred := encodeCert(t, cert)

	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	_, err = p.ValidateWorkload(context.Background(), cred, "mtls")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no identifiable subject") {
		t.Fatalf("error = %q, want containing 'no identifiable subject'", err.Error())
	}
}
