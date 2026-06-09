package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// certReloader watches cert/key files and reloads them when they change.
// It is safe for concurrent use by multiple goroutines.
type certReloader struct {
	certFile string
	keyFile  string

	mu      sync.RWMutex
	cert    *tls.Certificate
	modTime time.Time // latest mod time across cert and key files
}

// newCertReloader creates a certReloader that initially loads the given cert/key pair.
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
	}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload reads the cert and key files from disk and updates the cached certificate.
func (r *certReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading cert/key pair: %w", err)
	}

	modTime, err := r.latestModTime()
	if err != nil {
		return fmt.Errorf("checking file mod times: %w", err)
	}

	r.mu.Lock()
	r.cert = &cert
	r.modTime = modTime
	r.mu.Unlock()
	return nil
}

// latestModTime returns the most recent modification time of the cert and key files.
func (r *certReloader) latestModTime() (time.Time, error) {
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return time.Time{}, err
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return time.Time{}, err
	}
	t := certInfo.ModTime()
	if keyInfo.ModTime().After(t) {
		t = keyInfo.ModTime()
	}
	return t, nil
}

// GetCertificate implements the tls.Config.GetCertificate callback.
// On each TLS handshake it checks whether the cert/key files have been
// modified since last load and reloads them if necessary.
func (r *certReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	modTime, err := r.latestModTime()
	if err != nil {
		// If we can't stat the files, serve the cached cert.
		slog.Warn("cert reloader: failed to stat cert files, serving cached cert", "error", err)
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.cert, nil
	}

	r.mu.RLock()
	if !modTime.After(r.modTime) {
		defer r.mu.RUnlock()
		return r.cert, nil
	}
	r.mu.RUnlock()

	// Files changed — reload.
	if err := r.reload(); err != nil {
		slog.Error("cert reloader: failed to reload cert, serving cached cert", "error", err)
	} else {
		slog.Info("cert reloader: certificate reloaded from disk")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// CertExpiry returns the NotAfter time of the currently loaded certificate.
// It returns the zero time if no certificate is loaded or if the leaf
// certificate cannot be parsed.
func (r *certReloader) CertExpiry() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cert == nil || len(r.cert.Certificate) == 0 {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(r.cert.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return leaf.NotAfter
}

// PeerIdentity holds identity information extracted from a verified client certificate.
type PeerIdentity struct {
	Subject    string   // Certificate Subject CN
	SPIFFEURIs []string // SPIFFE URIs from SAN
	Serial     string   // Certificate serial number (hex)
}

// peerIdentityKey is the context key for the peer identity.
const peerIdentityKey contextKey = "peer_identity"

// buildMTLSConfig creates a *tls.Config for the mTLS listener.
// It loads the server cert/key and the client CA, enforcing TLS 1.3+
// and requiring client certificates verified against the CA.
func buildMTLSConfig(cfg core.TLSConfig) (*tls.Config, error) {
	tlsCfg, _, err := buildMTLSConfigWithReloader(cfg)
	return tlsCfg, err
}

// buildMTLSConfigWithReloader is like buildMTLSConfig but also returns
// the certReloader so the caller can inspect the loaded certificate
// (e.g. for health checks or metrics).
func buildMTLSConfigWithReloader(cfg core.TLSConfig) (*tls.Config, *certReloader, error) {
	reloader, err := newCertReloader(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("loading server cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.ClientCA)
	if err != nil {
		return nil, nil, fmt.Errorf("reading client CA: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("failed to parse client CA certificate")
	}

	tlsCfg := &tls.Config{
		GetCertificate: reloader.GetCertificate,
		ClientCAs:      caPool,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		MinVersion:     tls.VersionTLS13,
	}

	return tlsCfg, reloader, nil
}

// extractPeerIdentity extracts identity information from a verified TLS peer certificate.
func extractPeerIdentity(r *http.Request) *PeerIdentity {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}

	cert := r.TLS.PeerCertificates[0]

	identity := &PeerIdentity{
		Subject: cert.Subject.CommonName,
		Serial:  cert.SerialNumber.Text(16),
	}

	for _, uri := range cert.URIs {
		if isSPIFFEURI(uri) {
			identity.SPIFFEURIs = append(identity.SPIFFEURIs, uri.String())
		}
	}

	return identity
}

// isSPIFFEURI checks if a URI follows the SPIFFE ID scheme.
func isSPIFFEURI(u *url.URL) bool {
	return u != nil && u.Scheme == "spiffe"
}
