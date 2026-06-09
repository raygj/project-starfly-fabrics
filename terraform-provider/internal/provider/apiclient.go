package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// APIClient calls the Starfly HTTP API (mTLS and/or JWT).
type APIClient struct {
	endpoint   string
	httpClient *http.Client
	jwtToken   string
}

func newAPIClient(endpoint string, httpClient *http.Client, jwtToken string) *APIClient {
	if endpoint == "" {
		return nil
	}
	return &APIClient{
		endpoint:   strings.TrimRight(endpoint, "/"),
		httpClient: httpClient,
		jwtToken:   jwtToken,
	}
}

func (c *APIClient) available() bool {
	return c != nil && c.endpoint != ""
}

func (c *APIClient) request(ctx context.Context, method, path string, body any) (*http.Response, []byte, error) {
	if !c.available() {
		return nil, nil, fmt.Errorf("starfly API endpoint not configured")
	}

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.jwtToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.jwtToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, respBody, nil
}

func (c *APIClient) expectStatus(ctx context.Context, method, path string, body any, want int) ([]byte, error) {
	resp, respBody, err := c.request(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		return respBody, fmt.Errorf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, string(respBody))
	}
	return respBody, nil
}

type mcpToolListResponse struct {
	Tools []mcpToolPayload `json:"tools"`
	Count int              `json:"count"`
}

type mcpToolPayload struct {
	ToolID               string   `json:"tool_id"`
	Name                 string   `json:"name"`
	Description          string   `json:"description,omitempty"`
	ResourceURI          string   `json:"resource_uri,omitempty"`
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	MaxBlastRadius       string   `json:"max_blast_radius,omitempty"`
	RequiresExecution    bool     `json:"requires_execution,omitempty"`
	AllowedOperations    []string `json:"allowed_operations,omitempty"`
	AllowedTargets       []string `json:"allowed_targets,omitempty"`
	OwnerCommune         string   `json:"owner_commune,omitempty"`
	ServerID             string   `json:"server_id,omitempty"`
}

type streamConfigPayload struct {
	Issuer          string   `json:"iss"`
	Audience        string   `json:"aud"`
	EventsRequested []string `json:"events_requested"`
	DeliveryMethod  string   `json:"delivery_method"`
	EndpointURL     string   `json:"endpoint_url,omitempty"`
}

type streamPayload struct {
	ID     string `json:"stream_id"`
	Issuer string `json:"iss"`
	Status string `json:"status"`
}

type streamStatusPayload struct {
	StreamID string `json:"stream_id"`
	Status   string `json:"status"`
}

type agentIdentityPayload struct {
	AgentName        string            `json:"agent_name"`
	Platform         string            `json:"platform"`
	Capabilities     []string          `json:"capabilities"`
	OnBehalfOf       string            `json:"on_behalf_of,omitempty"`
	MaxBlastRadius   string            `json:"max_blast_radius,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	DelegationDepth  int               `json:"delegation_depth,omitempty"`
}

type agentIdentityResponse struct {
	WorkloadID string `json:"workload_id"`
	Token      string `json:"token"`
	SpiffeID   string `json:"spiffe_id,omitempty"`
}

type encryptionKeyPayload struct {
	PublicKey json.RawMessage `json:"public_key"`
}
