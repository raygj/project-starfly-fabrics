package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestBuildMTLSConfig_ValidCerts(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, caFile := ca.writeCertFiles(t)

	cfg := core.TLSConfig{
		Enabled:    true,
		ListenAddr: ":0",
		CertFile:   certFile,
		KeyFile:    keyFile,
		ClientCA:   caFile,
	}

	tlsCfg, err := buildMTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildMTLSConfig: %v", err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.3)", tlsCfg.MinVersion, tls.VersionTLS13)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.GetCertificate == nil {
		t.Error("GetCertificate should be set for hot-reload support")
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("ClientCAs should not be nil")
	}
}

func TestBuildMTLSConfig_MissingCertFile(t *testing.T) {
	ca := generateTestCA(t)
	_, keyFile, caFile := ca.writeCertFiles(t)

	cfg := core.TLSConfig{
		Enabled:  true,
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  keyFile,
		ClientCA: caFile,
	}

	_, err := buildMTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestBuildMTLSConfig_MissingKeyFile(t *testing.T) {
	ca := generateTestCA(t)
	certFile, _, caFile := ca.writeCertFiles(t)

	cfg := core.TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  "/nonexistent/key.pem",
		ClientCA: caFile,
	}

	_, err := buildMTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestBuildMTLSConfig_InvalidCA(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, _ := ca.writeCertFiles(t)

	// Write invalid CA content.
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("writing bad CA: %v", err)
	}

	cfg := core.TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
		ClientCA: badCA,
	}

	_, err := buildMTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid CA")
	}
}

func TestBuildMTLSConfig_MissingCAFile(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, _ := ca.writeCertFiles(t)

	cfg := core.TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
		ClientCA: "/nonexistent/ca.pem",
	}

	_, err := buildMTLSConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestExtractPeerIdentity_SPIFFEUri(t *testing.T) {
	ca := generateTestCA(t)

	spiffeURI, _ := url.Parse("spiffe://example.com/workload/test")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{ca.ClientCert},
	}

	identity := extractPeerIdentity(r)
	if identity == nil {
		t.Fatal("expected non-nil identity")
	}

	if identity.Subject != "test-workload" {
		t.Errorf("Subject = %q, want %q", identity.Subject, "test-workload")
	}

	if len(identity.SPIFFEURIs) != 1 {
		t.Fatalf("SPIFFEURIs len = %d, want 1", len(identity.SPIFFEURIs))
	}
	if identity.SPIFFEURIs[0] != spiffeURI.String() {
		t.Errorf("SPIFFEURIs[0] = %q, want %q", identity.SPIFFEURIs[0], spiffeURI.String())
	}
}

func TestExtractPeerIdentity_CNOnly(t *testing.T) {
	ca := generateTestCA(t)

	// Create a client cert without SPIFFE URIs.
	// Re-use the server cert which has CN=localhost but no SPIFFE URIs.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{ca.ServerCert},
	}

	identity := extractPeerIdentity(r)
	if identity == nil {
		t.Fatal("expected non-nil identity")
	}

	if identity.Subject != "localhost" {
		t.Errorf("Subject = %q, want %q", identity.Subject, "localhost")
	}

	if len(identity.SPIFFEURIs) != 0 {
		t.Errorf("SPIFFEURIs len = %d, want 0", len(identity.SPIFFEURIs))
	}
}

func TestExtractPeerIdentity_NilTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// r.TLS is nil

	identity := extractPeerIdentity(r)
	if identity != nil {
		t.Error("expected nil identity for request without TLS")
	}
}

func TestExtractPeerIdentity_NoPeerCerts(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}

	identity := extractPeerIdentity(r)
	if identity != nil {
		t.Error("expected nil identity for request without peer certs")
	}
}

func TestMTLSMiddleware_NoPeerCert(t *testing.T) {
	handler := mtlsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// No TLS at all
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestMTLSMiddleware_WithPeerCert(t *testing.T) {
	ca := generateTestCA(t)

	var gotIdentity *PeerIdentity
	handler := mtlsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = r.Context().Value(peerIdentityKey).(*PeerIdentity)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{ca.ClientCert},
	}
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if gotIdentity == nil {
		t.Fatal("expected identity in context")
	}
	if gotIdentity.Subject != "test-workload" {
		t.Errorf("Subject = %q, want %q", gotIdentity.Subject, "test-workload")
	}
}

// ── certReloader tests ──────────────────────────────────────────────

func TestCertReloader_LoadsInitialCert(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, _ := ca.writeCertFiles(t)

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}

	// Verify the loaded cert matches the original server cert.
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing returned cert: %v", err)
	}
	if parsed.Subject.CommonName != "localhost" {
		t.Errorf("CN = %q, want %q", parsed.Subject.CommonName, "localhost")
	}
}

func TestCertReloader_InvalidPaths(t *testing.T) {
	_, err := newCertReloader("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent cert files")
	}
}

func TestCertReloader_PicksUpNewCert(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, _ := ca.writeCertFiles(t)

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	// Verify initial cert has CN=localhost.
	cert1, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (initial): %v", err)
	}
	parsed1, _ := x509.ParseCertificate(cert1.Certificate[0])
	if parsed1.Subject.CommonName != "localhost" {
		t.Fatalf("initial CN = %q, want %q", parsed1.Subject.CommonName, "localhost")
	}

	// Generate a new server cert with a different CN, signed by the same CA.
	newCertPEM, newKeyPEM := generateServerCertWithCN(t, ca, "reloaded.example.com")

	// Ensure file mod time is different (some filesystems have 1s granularity).
	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(certFile, newCertPEM, 0644); err != nil {
		t.Fatalf("writing new cert: %v", err)
	}
	if err := os.WriteFile(keyFile, newKeyPEM, 0600); err != nil {
		t.Fatalf("writing new key: %v", err)
	}

	// Force the mod time to be clearly newer.
	futureTime := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(certFile, futureTime, futureTime); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyFile, futureTime, futureTime); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}

	// GetCertificate should detect the change and reload.
	cert2, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (reloaded): %v", err)
	}
	parsed2, _ := x509.ParseCertificate(cert2.Certificate[0])
	if parsed2.Subject.CommonName != "reloaded.example.com" {
		t.Errorf("reloaded CN = %q, want %q", parsed2.Subject.CommonName, "reloaded.example.com")
	}
}

func TestCertReloader_ConcurrentAccess(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, _ := ca.writeCertFiles(t)

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cert, err := r.GetCertificate(nil)
			if err != nil {
				t.Errorf("GetCertificate: %v", err)
			}
			if cert == nil {
				t.Error("expected non-nil certificate")
			}
		}()
	}
	wg.Wait()
}

func TestCertReloader_ServesCachedOnUnchanged(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, _ := ca.writeCertFiles(t)

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	cert1, _ := r.GetCertificate(nil)
	cert2, _ := r.GetCertificate(nil)

	// Should return the same pointer when files haven't changed.
	if cert1 != cert2 {
		t.Error("expected same certificate pointer for unchanged files")
	}
}

func TestCertReloader_CertExpiry(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, _ := ca.writeCertFiles(t)

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	expiry := r.CertExpiry()
	if expiry.IsZero() {
		t.Fatal("expected non-zero expiry time")
	}

	// The test CA generates certs valid for 1 hour from now.
	// Expiry should be in the future.
	if !expiry.After(time.Now()) {
		t.Errorf("expected expiry in the future, got %v", expiry)
	}
}

// generateServerCertWithCN creates a new server cert/key pair with the given CN,
// signed by the provided test CA.
func generateServerCertWithCN(t *testing.T, ca *testCA, cn string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Starfly Test"},
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(1 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{cn},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.CACert, &key.PublicKey, ca.CAKey)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
