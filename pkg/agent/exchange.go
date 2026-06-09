package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ExchangeClient performs RFC 8693 token exchange against a Starfly server.
type ExchangeClient struct {
	serverURL  string
	audience   string
	scope      string
	httpClient *http.Client
}

// ExchangeClientConfig holds configuration for the exchange client.
type ExchangeClientConfig struct {
	ServerURL  string
	Audience   string
	Scope      string
	CACertPath string
	Timeout    time.Duration
}

// NewExchangeClient creates an ExchangeClient. If caCertPath is set,
// the client loads the CA certificate for TLS verification (self-signed envs).
func NewExchangeClient(cfg ExchangeClientConfig) (*ExchangeClient, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert %s: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", cfg.CACertPath)
		}
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
	}

	return &ExchangeClient{
		serverURL: cfg.ServerURL,
		audience:  cfg.Audience,
		scope:     cfg.Scope,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}, nil
}

// tokenExchangeRequest is the RFC 8693 request body.
type tokenExchangeRequest struct {
	GrantType        string `json:"grant_type"`
	SubjectToken     string `json:"subject_token"`
	SubjectTokenType string `json:"subject_token_type"`
	Audience         string `json:"audience,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// tokenExchangeResponse is the Starfly exchange response.
type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Error           string `json:"error,omitempty"`
	ErrorDesc       string `json:"error_description,omitempty"`
}

// Exchange sends the attestation bundle to Starfly and receives a WIMSE JWT.
// The platform credential goes in subject_token; the full bundle (minus
// credential) goes in the X-Starfly-Attestation header.
func (c *ExchangeClient) Exchange(ctx context.Context, bundle *AttestationBundle) (*ExchangeResult, error) {
	if bundle.Platform == nil {
		return nil, fmt.Errorf("attestation bundle has no platform credential")
	}

	reqBody := tokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     string(bundle.Platform.Credential),
		SubjectTokenType: bundle.Platform.CredType,
		Audience:         c.audience,
		Scope:            c.scope,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling exchange request: %w", err)
	}

	url := c.serverURL + "/v1/exchange/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	attestHeader, err := buildAttestationHeader(bundle)
	if err != nil {
		return nil, fmt.Errorf("building attestation header: %w", err)
	}
	req.Header.Set("X-Starfly-Attestation", attestHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange request to %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp tokenExchangeResponse
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("exchange failed (HTTP %d): %s — %s", resp.StatusCode, errResp.Error, errResp.ErrorDesc)
		}
		return nil, fmt.Errorf("exchange failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var exchangeResp tokenExchangeResponse
	if err := json.Unmarshal(respBody, &exchangeResp); err != nil {
		return nil, fmt.Errorf("decoding exchange response: %w", err)
	}

	return &ExchangeResult{
		AccessToken: exchangeResp.AccessToken,
		ExpiresIn:   exchangeResp.ExpiresIn,
		IssuedAt:    time.Now().UTC(),
	}, nil
}

// buildAttestationHeader produces the JSON for X-Starfly-Attestation.
// It includes everything except the platform credential (which is in subject_token).
type attestationHeader struct {
	Platform     attestHeaderPlatform `json:"platform"`
	Hardware     []*HardwareProof     `json:"hardware,omitempty"`
	Workload     *WorkloadMetadata    `json:"workload,omitempty"`
	AgentVersion string               `json:"agent_version"`
	Timestamp    time.Time            `json:"timestamp"`
}

type attestHeaderPlatform struct {
	Source   string            `json:"source"`
	CredType string           `json:"cred_type"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func buildAttestationHeader(bundle *AttestationBundle) (string, error) {
	header := attestationHeader{
		Platform: attestHeaderPlatform{
			Source:   bundle.Platform.Source,
			CredType: bundle.Platform.CredType,
			Metadata: bundle.Platform.Metadata,
		},
		Workload:     bundle.Workload,
		AgentVersion: bundle.AgentVersion,
		Timestamp:    bundle.Timestamp,
	}

	for _, h := range bundle.Hardware {
		if h.Hardware != nil {
			header.Hardware = append(header.Hardware, h.Hardware)
		}
	}

	data, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
