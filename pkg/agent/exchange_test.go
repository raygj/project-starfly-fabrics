package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExchangeClient_Success(t *testing.T) {
	var receivedAttest string
	var receivedBody tokenExchangeRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/exchange/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}

		receivedAttest = r.Header.Get("X-Starfly-Attestation")

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			AccessToken:     "eyJhbGciOiJSUzI1NiJ9.wimse-jwt.signature",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:jwt",
			TokenType:       "Bearer",
			ExpiresIn:       300,
		})
	}))
	defer server.Close()

	client, err := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "my-service.prod",
		Scope:     "read write",
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewExchangeClient() error: %v", err)
	}

	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:     "k8s-sa",
			Credential: []byte("fake-sa-token"),
			CredType:   "urn:ietf:params:oauth:token-type:jwt",
			Metadata:   map[string]string{"namespace": "prod"},
		},
		Workload: &WorkloadMetadata{
			PID:        1234,
			BinaryHash: "sha256:abc",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}

	result, err := client.Exchange(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Exchange() error: %v", err)
	}

	if result.AccessToken != "eyJhbGciOiJSUzI1NiJ9.wimse-jwt.signature" {
		t.Errorf("AccessToken = %q", result.AccessToken)
	}
	if result.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want 300", result.ExpiresIn)
	}
	if result.IssuedAt.IsZero() {
		t.Error("expected non-zero IssuedAt")
	}

	// Verify request body.
	if receivedBody.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type = %q", receivedBody.GrantType)
	}
	if receivedBody.SubjectToken != "fake-sa-token" {
		t.Errorf("subject_token = %q", receivedBody.SubjectToken)
	}
	if receivedBody.Audience != "my-service.prod" {
		t.Errorf("audience = %q", receivedBody.Audience)
	}

	// Verify attestation header is valid JSON and excludes the credential.
	if receivedAttest == "" {
		t.Fatal("X-Starfly-Attestation header missing")
	}
	var header attestationHeader
	if err := json.Unmarshal([]byte(receivedAttest), &header); err != nil {
		t.Fatalf("attestation header is not valid JSON: %v", err)
	}
	if header.Platform.Source != "k8s-sa" {
		t.Errorf("header platform source = %q", header.Platform.Source)
	}
	if header.Workload.BinaryHash != "sha256:abc" {
		t.Errorf("header binary_hash = %q", header.Workload.BinaryHash)
	}
}

func TestExchangeClient_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{
			Error:     "invalid_grant",
			ErrorDesc: "unknown subject token type",
		})
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:     "k8s-sa",
			Credential: []byte("bad-token"),
			CredType:   "urn:ietf:params:oauth:token-type:jwt",
		},
		Workload:     &WorkloadMetadata{PID: 1},
		AgentVersion: "test",
	}

	_, err := client.Exchange(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if got := err.Error(); got == "" {
		t.Error("error message should not be empty")
	}
}

func TestExchangeClient_NoPlatformCredential(t *testing.T) {
	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: "http://localhost:9999",
		Audience:  "test",
	})

	bundle := &AttestationBundle{
		Workload:     &WorkloadMetadata{PID: 1},
		AgentVersion: "test",
	}

	_, err := client.Exchange(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected error when platform is nil")
	}
}

func TestExchangeClient_ServerUnreachable(t *testing.T) {
	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: "http://127.0.0.1:1",
		Audience:  "test",
		Timeout:   100 * time.Millisecond,
	})

	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:     "k8s-sa",
			Credential: []byte("token"),
			CredType:   "urn:ietf:params:oauth:token-type:jwt",
		},
		Workload:     &WorkloadMetadata{PID: 1},
		AgentVersion: "test",
	}

	_, err := client.Exchange(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestNewExchangeClient_WithCACert(t *testing.T) {
	certPEM := filepath.Join(t.TempDir(), "ca.pem")
	// Write a minimal self-signed cert for parsing (valid PEM, self-signed).
	_ = os.WriteFile(certPEM, generateSelfSignedCertPEM(t), 0600)

	client, err := NewExchangeClient(ExchangeClientConfig{
		ServerURL:  "https://localhost:9999",
		Audience:   "test",
		CACertPath: certPEM,
	})
	if err != nil {
		t.Fatalf("NewExchangeClient() error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewExchangeClient_CACertNotFound(t *testing.T) {
	_, err := NewExchangeClient(ExchangeClientConfig{
		ServerURL:  "https://localhost:9999",
		Audience:   "test",
		CACertPath: "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent CA cert")
	}
}

func TestNewExchangeClient_CACertInvalidPEM(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "bad-ca.pem")
	_ = os.WriteFile(certPath, []byte("not a real cert"), 0600)

	_, err := NewExchangeClient(ExchangeClientConfig{
		ServerURL:  "https://localhost:9999",
		Audience:   "test",
		CACertPath: certPath,
	})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewExchangeClient_DefaultTimeout(t *testing.T) {
	client, err := NewExchangeClient(ExchangeClientConfig{
		ServerURL: "http://localhost:9999",
		Audience:  "test",
	})
	if err != nil {
		t.Fatalf("NewExchangeClient() error: %v", err)
	}
	if client.httpClient.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", client.httpClient.Timeout)
	}
}

func TestBuildAttestationHeader_WithHardware(t *testing.T) {
	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
			Metadata: map[string]string{"namespace": "prod"},
		},
		Hardware: []*AttestationResult{
			{
				Source: "tpm2",
				Hardware: &HardwareProof{
					Type:  "tpm2",
					Quote: []byte("tpm-quote"),
					Nonce: []byte("nonce-1"),
				},
			},
		},
		Workload:     &WorkloadMetadata{PID: 1},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}

	header, err := buildAttestationHeader(bundle)
	if err != nil {
		t.Fatalf("buildAttestationHeader() error: %v", err)
	}

	var parsed attestationHeader
	if err := json.Unmarshal([]byte(header), &parsed); err != nil {
		t.Fatalf("header is not valid JSON: %v", err)
	}
	if len(parsed.Hardware) != 1 {
		t.Errorf("hardware count = %d, want 1", len(parsed.Hardware))
	}
	if parsed.Hardware[0].Type != "tpm2" {
		t.Errorf("hardware type = %q, want tpm2", parsed.Hardware[0].Type)
	}
}

func TestBuildAttestationHeader_NoHardware(t *testing.T) {
	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}

	header, err := buildAttestationHeader(bundle)
	if err != nil {
		t.Fatalf("buildAttestationHeader() error: %v", err)
	}

	var parsed attestationHeader
	if err := json.Unmarshal([]byte(header), &parsed); err != nil {
		t.Fatalf("header is not valid JSON: %v", err)
	}
	if len(parsed.Hardware) != 0 {
		t.Errorf("hardware count = %d, want 0", len(parsed.Hardware))
	}
	if parsed.Platform.Source != "k8s-sa" {
		t.Errorf("platform source = %q, want k8s-sa", parsed.Platform.Source)
	}
}

func TestBuildAttestationHeader_HardwareWithNilProof(t *testing.T) {
	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		Hardware: []*AttestationResult{
			{Source: "tpm2", Hardware: nil},
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}

	header, err := buildAttestationHeader(bundle)
	if err != nil {
		t.Fatalf("buildAttestationHeader() error: %v", err)
	}

	var parsed attestationHeader
	_ = json.Unmarshal([]byte(header), &parsed)
	if len(parsed.Hardware) != 0 {
		t.Errorf("hardware count = %d, want 0 (nil proof should be skipped)", len(parsed.Hardware))
	}
}

func TestExchangeClient_ErrorResponseWithoutJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:     "k8s-sa",
			Credential: []byte("token"),
			CredType:   "urn:ietf:params:oauth:token-type:jwt",
		},
		Workload:     &WorkloadMetadata{PID: 1},
		AgentVersion: "test",
	}

	_, err := client.Exchange(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestExchangeClient_InvalidJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
	})

	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:     "k8s-sa",
			Credential: []byte("token"),
			CredType:   "urn:ietf:params:oauth:token-type:jwt",
		},
		Workload:     &WorkloadMetadata{PID: 1},
		AgentVersion: "test",
	}

	_, err := client.Exchange(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestExchangeClient_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	client, _ := NewExchangeClient(ExchangeClientConfig{
		ServerURL: server.URL,
		Audience:  "test",
		Timeout:   10 * time.Second,
	})

	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:     "k8s-sa",
			Credential: []byte("token"),
			CredType:   "urn:ietf:params:oauth:token-type:jwt",
		},
		Workload:     &WorkloadMetadata{PID: 1},
		AgentVersion: "test",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.Exchange(ctx, bundle)
	if err == nil {
		t.Fatal("expected error for context cancellation")
	}
}

// generateSelfSignedCertPEM produces a self-signed cert in PEM format for testing.
func generateSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
