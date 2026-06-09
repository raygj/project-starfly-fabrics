package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client wraps an MCP client with automatic Starfly token acquisition.
// Before each tool call, the client requests a scoped WIMSE JWT from the
// Starfly exchange endpoint, including the RFC 8707 resource parameter
// to bind the token to the target tool.
type Client struct {
	// StarflyURL is the Starfly token exchange endpoint.
	StarflyURL string

	// SourceToken is the workload's own credential (K8s SA, SPIFFE SVID, etc.).
	SourceToken string

	// SourceTokenType is the credential type (e.g., "urn:ietf:params:oauth:token-type:jwt").
	SourceTokenType string

	// HTTPClient is the HTTP client to use for requests. Defaults to a client
	// with a 10-second timeout.
	HTTPClient *http.Client
}

// ClientOption configures the MCP client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) { cl.HTTPClient = c }
}

// NewClient creates an MCP client that acquires Starfly tokens automatically.
func NewClient(starflyURL, sourceToken, sourceTokenType string, opts ...ClientOption) *Client {
	c := &Client{
		StarflyURL:      starflyURL,
		SourceToken:     sourceToken,
		SourceTokenType: sourceTokenType,
		HTTPClient:      &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// tokenExchangeRequest is the RFC 8693 token exchange request body.
type tokenExchangeRequest struct {
	GrantType        string `json:"grant_type"`
	SubjectToken     string `json:"subject_token"`
	SubjectTokenType string `json:"subject_token_type"`
	Audience         string `json:"audience"`
	Scope            string `json:"scope,omitempty"`
	Resource         string `json:"resource,omitempty"` // RFC 8707 resource indicator
}

// tokenExchangeResponse is the RFC 8693 token exchange response body.
type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// AcquireToken requests a scoped WIMSE JWT from Starfly for the given tool.
// The resource parameter (RFC 8707) ensures the token is bound to this
// specific tool, preventing cross-tool token misuse (confused deputy).
func (c *Client) AcquireToken(ctx context.Context, toolResourceURI string, capabilities []string) (string, error) {
	scope := ""
	if len(capabilities) > 0 {
		for i, cap := range capabilities {
			if i > 0 {
				scope += " "
			}
			scope += cap
		}
	}

	reqBody := tokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     c.SourceToken,
		SubjectTokenType: c.SourceTokenType,
		Audience:         toolResourceURI,
		Resource:         toolResourceURI, // RFC 8707 — binds token to this tool
		Scope:            scope,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("mcp client: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.StarflyURL+"/v1/exchange/token", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("mcp client: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mcp client: exchange request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("mcp client: exchange returned %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("mcp client: decode response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// CallToolRequest is the parameters for an MCP tool call.
type CallToolRequest struct {
	ToolID       string                 `json:"tool_id"`
	ToolName     string                 `json:"tool_name"`
	ResourceURI  string                 `json:"resource_uri"`
	Capabilities []string               `json:"capabilities,omitempty"`
	Params       map[string]interface{} `json:"params,omitempty"`
	TargetURL    string                 `json:"target_url"`

	// ParentECTs are signed ECT tokens to include as Execution-Context
	// request headers, establishing DAG linkage per ECT spec Section 4.
	ParentECTs []string `json:"-"`
}

// CallToolResponse is the response from an MCP tool call.
type CallToolResponse struct {
	StatusCode int                    `json:"status_code"`
	Body       map[string]interface{} `json:"body,omitempty"`
	RawBody    []byte                 `json:"-"`

	// ECT is the Execution-Context token returned by the tool server,
	// captured from the Execution-Context response header.
	ECT string `json:"-"`
}

// CallTool acquires a scoped Starfly token and calls the MCP tool.
func (c *Client) CallTool(ctx context.Context, req *CallToolRequest) (*CallToolResponse, error) {
	// Acquire a scoped token for this tool.
	token, err := c.AcquireToken(ctx, req.ResourceURI, req.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("mcp client: acquire token: %w", err)
	}

	// Marshal the tool call payload.
	payload, err := json.Marshal(map[string]interface{}{
		"tool_name": req.ToolName,
		"params":    req.Params,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp client: marshal payload: %w", err)
	}

	// Call the tool with the Starfly token.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.TargetURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("mcp client: create tool request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("X-MCP-Tool-ID", req.ToolID)

	// Forward parent ECTs as Execution-Context headers (ECT spec Section 4).
	for _, ect := range req.ParentECTs {
		httpReq.Header.Add("Execution-Context", ect)
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("mcp client: tool call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		return nil, fmt.Errorf("mcp client: read response: %w", err)
	}

	result := &CallToolResponse{
		StatusCode: resp.StatusCode,
		RawBody:    rawBody,
		ECT:        resp.Header.Get("Execution-Context"),
	}

	// Try to parse as JSON.
	var bodyMap map[string]interface{}
	if json.Unmarshal(rawBody, &bodyMap) == nil {
		result.Body = bodyMap
	}

	return result, nil
}
