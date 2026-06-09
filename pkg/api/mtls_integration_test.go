package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// startMTLSListener creates a TLS listener on localhost and starts serving.
// Returns the listener. Registers cleanup via t.Cleanup.
func startMTLSListener(t *testing.T, srv *Server) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.mtlsServer.TLSConfig)
	if err != nil {
		t.Fatalf("starting mTLS listener: %v", err)
	}
	go func() {
		if err := srv.mtlsServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("mtls serve error: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := srv.mtlsServer.Close(); err != nil {
			t.Logf("mtls close error: %v", err)
		}
		if err := ln.Close(); err != nil {
			t.Logf("listener close error: %v", err)
		}
	})
	return ln
}

// newMTLSTestConfig returns a Config with TLS enabled using the provided cert files.
func newMTLSTestConfig(certFile, keyFile, caFile string) *core.Config {
	return &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
		TLS: core.TLSConfig{
			Enabled:    true,
			ListenAddr: ":0",
			CertFile:   certFile,
			KeyFile:    keyFile,
			ClientCA:   caFile,
		},
	}
}

func TestMTLSHandshake_Success(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, caFile := ca.writeCertFiles(t)
	srv := New(newMTLSTestConfig(certFile, keyFile, caFile), "test", nil)
	ln := startMTLSListener(t, srv)

	// Build client with valid cert.
	clientCert, err := tls.X509KeyPair(ca.ClientCertPEM, ca.ClientKeyPEM)
	if err != nil {
		t.Fatalf("loading client cert: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CACertPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	resp, err := client.Post(
		fmt.Sprintf("https://%s/v1/exchange/token", ln.Addr().String()),
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Exchange handler returns 400 (bad request, no body) — that's OK,
	// the point is the TLS handshake succeeded and we reached the handler.
	if resp.StatusCode == 0 {
		t.Fatal("expected a response status code")
	}
	t.Logf("mTLS handshake success, response status: %d", resp.StatusCode)
}

func TestMTLSHandshake_NoClientCert(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, caFile := ca.writeCertFiles(t)
	srv := New(newMTLSTestConfig(certFile, keyFile, caFile), "test", nil)
	ln := startMTLSListener(t, srv)

	// Client without any cert.
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CACertPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	_, err := client.Post(
		fmt.Sprintf("https://%s/v1/exchange/token", ln.Addr().String()),
		"application/json",
		nil,
	)
	if err == nil {
		t.Fatal("expected TLS error for missing client cert")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestMTLSHandshake_WrongCA(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, caFile := ca.writeCertFiles(t)
	srv := New(newMTLSTestConfig(certFile, keyFile, caFile), "test", nil)
	ln := startMTLSListener(t, srv)

	// Generate a completely separate CA and client cert.
	otherCA := generateTestCA(t)
	clientCert, err := tls.X509KeyPair(otherCA.ClientCertPEM, otherCA.ClientKeyPEM)
	if err != nil {
		t.Fatalf("loading other client cert: %v", err)
	}

	// Trust the server's CA for the connection, but present a cert from a different CA.
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CACertPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	_, err = client.Post(
		fmt.Sprintf("https://%s/v1/exchange/token", ln.Addr().String()),
		"application/json",
		nil,
	)
	if err == nil {
		t.Fatal("expected TLS error for wrong CA")
	}
	t.Logf("correctly rejected wrong CA: %v", err)
}

func TestMTLSHandshake_ExpiredClientCert(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, caFile := ca.writeCertFiles(t)
	srv := New(newMTLSTestConfig(certFile, keyFile, caFile), "test", nil)
	ln := startMTLSListener(t, srv)

	expiredCertPEM, expiredKeyPEM := ca.generateExpiredClientCert(t)
	clientCert, err := tls.X509KeyPair(expiredCertPEM, expiredKeyPEM)
	if err != nil {
		t.Fatalf("loading expired client cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CACertPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	_, err = client.Post(
		fmt.Sprintf("https://%s/v1/exchange/token", ln.Addr().String()),
		"application/json",
		nil,
	)
	if err == nil {
		t.Fatal("expected TLS error for expired client cert")
	}
	t.Logf("correctly rejected expired cert: %v", err)
}

func TestPlaintextEndpoints_NoTLS(t *testing.T) {
	ca := generateTestCA(t)
	certFile, keyFile, caFile := ca.writeCertFiles(t)
	srv := New(newMTLSTestConfig(certFile, keyFile, caFile), "test", nil)

	// Start plaintext listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting plaintext listener: %v", err)
	}
	go func() {
		if err := srv.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("http serve error: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := srv.httpServer.Close(); err != nil {
			t.Logf("http close error: %v", err)
		}
		if err := ln.Close(); err != nil {
			t.Logf("listener close error: %v", err)
		}
	})

	client := &http.Client{Timeout: 5 * time.Second}

	// Health endpoint should work on plaintext.
	resp, err := client.Get(fmt.Sprintf("http://%s/v1/sys/health", ln.Addr().String()))
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("health status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body)
	}

	// JWKS endpoint should work on plaintext.
	resp2, err := client.Get(fmt.Sprintf("http://%s/v1/identity/jwks", ln.Addr().String()))
	if err != nil {
		t.Fatalf("jwks request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	// JWKS returns 200 (no provider configured, empty set) or 500 — either is fine,
	// the point is the endpoint is accessible without TLS.
	t.Logf("JWKS status on plaintext: %d", resp2.StatusCode)

	// Metrics endpoint should work on plaintext.
	resp3, err := client.Get(fmt.Sprintf("http://%s/metrics", ln.Addr().String()))
	if err != nil {
		t.Fatalf("metrics request failed: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()

	if resp3.StatusCode != http.StatusOK {
		t.Errorf("metrics status = %d, want %d", resp3.StatusCode, http.StatusOK)
	}

	// Exchange endpoint should NOT be on the plaintext port when TLS is enabled.
	resp4, err := client.Post(
		fmt.Sprintf("http://%s/v1/exchange/token", ln.Addr().String()),
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatalf("exchange request failed: %v", err)
	}
	defer func() { _ = resp4.Body.Close() }()

	// Should get 404/405 since exchange is only on the mTLS port.
	if resp4.StatusCode == http.StatusOK || resp4.StatusCode == http.StatusBadRequest {
		t.Errorf("exchange on plaintext should not be routable when TLS enabled, got status %d", resp4.StatusCode)
	}
}
