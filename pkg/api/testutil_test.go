package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA holds in-memory CA, server, and client certificate material
// for testing mTLS handshakes.
type testCA struct {
	// CA
	CACert    *x509.Certificate
	CAKey     *ecdsa.PrivateKey
	CACertPEM []byte

	// Server
	ServerCert    *x509.Certificate
	ServerKey     *ecdsa.PrivateKey
	ServerCertPEM []byte
	ServerKeyPEM  []byte

	// Client
	ClientCert    *x509.Certificate
	ClientKey     *ecdsa.PrivateKey
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

// generateTestCA creates an in-memory CA, server cert, and client cert
// using ECDSA P-256. All certs are valid for 1 hour.
func generateTestCA(t *testing.T) *testCA {
	t.Helper()

	ca := &testCA{}

	// ── CA ────────────────────────────────────────────────────
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	ca.CAKey = caKey

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Starfly Test"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	ca.CACert, err = x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	ca.CACertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// ── Server cert ──────────────────────────────────────────
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating server key: %v", err)
	}
	ca.ServerKey = serverKey

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Starfly Test"},
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(1 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca.CACert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating server cert: %v", err)
	}
	ca.ServerCert, _ = x509.ParseCertificate(serverCertDER)
	ca.ServerCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})

	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshaling server key: %v", err)
	}
	ca.ServerKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	// ── Client cert ──────────────────────────────────────────
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	ca.ClientKey = clientKey

	spiffeURI, _ := url.Parse("spiffe://example.com/workload/test")
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "test-workload",
			Organization: []string{"Starfly Test"},
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(1 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		URIs: []*url.URL{spiffeURI},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca.CACert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating client cert: %v", err)
	}
	ca.ClientCert, _ = x509.ParseCertificate(clientCertDER)
	ca.ClientCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshaling client key: %v", err)
	}
	ca.ClientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	return ca
}

// generateExpiredClientCert creates a client cert signed by the CA that is already expired.
func (ca *testCA) generateExpiredClientCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating expired client key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject: pkix.Name{
			CommonName:   "expired-workload",
			Organization: []string{"Starfly Test"},
		},
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(-1 * time.Hour), // already expired
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.CACert, &clientKey.PublicKey, ca.CAKey)
	if err != nil {
		t.Fatalf("creating expired client cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshaling expired client key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// writeCertFiles writes CA, server cert, and server key to a temp directory
// and returns the file paths.
func (ca *testCA) writeCertFiles(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()

	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	caFile = filepath.Join(dir, "ca.crt")

	if err := os.WriteFile(certFile, ca.ServerCertPEM, 0644); err != nil {
		t.Fatalf("writing server cert: %v", err)
	}
	if err := os.WriteFile(keyFile, ca.ServerKeyPEM, 0600); err != nil {
		t.Fatalf("writing server key: %v", err)
	}
	if err := os.WriteFile(caFile, ca.CACertPEM, 0644); err != nil {
		t.Fatalf("writing CA cert: %v", err)
	}

	return certFile, keyFile, caFile
}
