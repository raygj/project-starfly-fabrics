//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/audit"
	"github.com/starfly-fabrics/starfly/pkg/core"
	"github.com/starfly-fabrics/starfly/pkg/exchange"
	"github.com/starfly-fabrics/starfly/pkg/identity"
	agentpkg "github.com/starfly-fabrics/starfly/pkg/identity/agent"
)

// allowAllPolicy is a policy engine that allows everything for integration tests.
type allowAllPolicy struct{}

func (p *allowAllPolicy) Evaluate(_ context.Context, _ *core.PolicyInput) (*core.PolicyDecision, error) {
	return &core.PolicyDecision{Allowed: true}, nil
}

func (p *allowAllPolicy) LoadBundle(_ context.Context, _ string) error { return nil }

// agentAwareIdentityProvider wraps a real IdentityProvider and adds
// support for agent-* credential types by parsing self-issued JWTs.
type agentAwareIdentityProvider struct {
	inner core.IdentityProvider
}

func (p *agentAwareIdentityProvider) ValidateWorkload(ctx context.Context, credential string, credType string) (*core.WorkloadIdentity, error) {
	if strings.HasPrefix(credType, "agent-") {
		tok, err := jwt.ParseInsecure([]byte(credential))
		if err != nil {
			return nil, fmt.Errorf("malformed agent JWT: %w", err)
		}
		sub, _ := tok.Subject()
		var td string
		_ = tok.Get("td", &td)
		if td == "" {
			td = "dev.local"
		}
		var platform string
		_ = tok.Get("agent_platform", &platform)

		return &core.WorkloadIdentity{
			ID:          sub,
			TrustDomain: td,
			Attestation: &core.AttestationEvidence{
				Method:    credType,
				Timestamp: time.Now().UTC(),
			},
			Claims: map[string]interface{}{
				"agent_platform": platform,
				"dev_mode":       true,
			},
		}, nil
	}
	return p.inner.ValidateWorkload(ctx, credential, credType)
}

func setupIntegrationServer(t *testing.T) *httptest.Server {
	t.Helper()

	trustDomains := []core.TrustDomain{
		{Name: "integration.test", Enabled: true, Issuer: "starfly"},
	}

	auditor := audit.New(io.Discard)

	baseIdentity, err := identity.New(context.Background(), trustDomains, true)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	identityProvider := &agentAwareIdentityProvider{inner: baseIdentity}

	policyEngine := &allowAllPolicy{}

	exchangeEngine, err := exchange.New(identityProvider, policyEngine, auditor)
	if err != nil {
		t.Fatalf("exchange.New: %v", err)
	}

	agentProvider, err := agentpkg.NewProvider(
		agentpkg.WithTrustDomains(trustDomains),
		agentpkg.WithDevMode(true),
	)
	if err != nil {
		t.Fatalf("agentpkg.NewProvider: %v", err)
	}

	cfg := &core.Config{
		ListenAddr: ":0",
		DevMode:    true,
		RateLimit: core.RateLimitConfig{
			GlobalRate:  1000,
			GlobalBurst: 1000,
			PerIPRate:   100,
			PerIPBurst:  100,
		},
	}

	apiServer := New(cfg, "integration-test", exchangeEngine,
		WithJWKS(exchangeEngine),
		WithAgentIdentity(agentProvider),
	)

	return httptest.NewServer(apiServer.httpServer.Handler)
}

func TestAgentIdentityIntegration_MCP(t *testing.T) {
	ts := setupIntegrationServer(t)
	defer ts.Close()

	// Step 1: Issue MCP agent identity.
	issueBody := `{
		"agent_name": "code-assistant",
		"platform": "mcp",
		"capabilities": ["query-read", "tool-execute"],
		"max_blast_radius": "workspace:dev"
	}`

	resp, err := http.Post(ts.URL+"/v1/identity/agent", "application/json",
		bytes.NewBufferString(issueBody))
	if err != nil {
		t.Fatalf("Step 1 POST /v1/identity/agent: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 1: status = %d, want 200", resp.StatusCode)
	}

	var agentIdentity core.AgentIdentity
	if err := json.NewDecoder(resp.Body).Decode(&agentIdentity); err != nil {
		t.Fatalf("Step 1: decoding response: %v", err)
	}

	if !strings.HasPrefix(agentIdentity.WorkloadID, "wimse://") {
		t.Errorf("Step 1: workload_id = %q, want wimse:// prefix", agentIdentity.WorkloadID)
	}
	if !strings.Contains(agentIdentity.WorkloadID, "/agent/mcp/code-assistant") {
		t.Errorf("Step 1: workload_id = %q, want .../agent/mcp/code-assistant", agentIdentity.WorkloadID)
	}
	if agentIdentity.Token == "" {
		t.Fatal("Step 1: token is empty")
	}
	if agentIdentity.ExpiresAt.Before(time.Now()) {
		t.Error("Step 1: token already expired")
	}

	// Verify the issued token is a valid JWT.
	issuedToken, err := jwt.ParseInsecure([]byte(agentIdentity.Token))
	if err != nil {
		t.Fatalf("Step 1: parsing JWT: %v", err)
	}

	sub, _ := issuedToken.Subject()
	if sub != agentIdentity.WorkloadID {
		t.Errorf("Step 1: JWT sub = %q, want %q", sub, agentIdentity.WorkloadID)
	}

	var platform interface{}
	if err := issuedToken.Get("agent_platform", &platform); err != nil {
		t.Fatalf("Step 1: getting agent_platform: %v", err)
	}
	if platform != "mcp" {
		t.Errorf("Step 1: agent_platform = %v, want mcp", platform)
	}

	// Step 2: Exchange agent token for scoped WIMSE JWT.
	exchangeBody, _ := json.Marshal(core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     agentIdentity.Token,
		SubjectTokenType: "urn:starfly:token-type:agent-mcp",
		Audience:         "https://api.target.example.com",
		Scope:            "read:data",
	})

	resp2, err := http.Post(ts.URL+"/v1/exchange/token", "application/json",
		bytes.NewBuffer(exchangeBody))
	if err != nil {
		t.Fatalf("Step 2 POST /v1/exchange/token: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		var errResp errorResponse
		json.NewDecoder(resp2.Body).Decode(&errResp)
		t.Fatalf("Step 2: status = %d, error = %q: %q", resp2.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var exchangeResp core.TokenExchangeResponse
	if err := json.NewDecoder(resp2.Body).Decode(&exchangeResp); err != nil {
		t.Fatalf("Step 2: decoding response: %v", err)
	}

	if exchangeResp.AccessToken == "" {
		t.Fatal("Step 2: access_token is empty")
	}
	if exchangeResp.TokenType != "Bearer" {
		t.Errorf("Step 2: token_type = %q, want Bearer", exchangeResp.TokenType)
	}

	// Step 3: Verify the WIMSE JWT claims.
	wimseToken, err := jwt.ParseInsecure([]byte(exchangeResp.AccessToken))
	if err != nil {
		t.Fatalf("Step 3: parsing WIMSE JWT: %v", err)
	}

	aud, _ := wimseToken.Audience()
	if len(aud) == 0 || aud[0] != "https://api.target.example.com" {
		t.Errorf("Step 3: aud = %v, want [https://api.target.example.com]", aud)
	}

	exp, _ := wimseToken.Expiration()
	if exp.Before(time.Now()) {
		t.Error("Step 3: WIMSE token already expired")
	}

	iss, _ := wimseToken.Issuer()
	if iss != "starfly" {
		t.Errorf("Step 3: iss = %q, want starfly", iss)
	}
}

func TestAgentIdentityIntegration_A2A(t *testing.T) {
	ts := setupIntegrationServer(t)
	defer ts.Close()

	// Step 1: Issue A2A agent identity with delegation.
	issueBody := `{
		"agent_name": "trading-bot",
		"platform": "a2a",
		"capabilities": ["trade-execute", "portfolio-read"],
		"on_behalf_of": "wimse://acme.com/ns/default/sa/portfolio-mgr",
		"max_blast_radius": "namespace:trading",
		"delegation_depth": 2
	}`

	resp, err := http.Post(ts.URL+"/v1/identity/agent", "application/json",
		bytes.NewBufferString(issueBody))
	if err != nil {
		t.Fatalf("Step 1: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Step 1: status = %d, want 200", resp.StatusCode)
	}

	var agentIdentity core.AgentIdentity
	if err := json.NewDecoder(resp.Body).Decode(&agentIdentity); err != nil {
		t.Fatalf("Step 1: decoding: %v", err)
	}

	if !strings.Contains(agentIdentity.WorkloadID, "/agent/a2a/trading-bot") {
		t.Errorf("Step 1: workload_id = %q, want .../agent/a2a/trading-bot", agentIdentity.WorkloadID)
	}

	// Verify delegation_depth and obo claims in the issued token.
	tok, err := jwt.ParseInsecure([]byte(agentIdentity.Token))
	if err != nil {
		t.Fatalf("Step 1: parsing JWT: %v", err)
	}

	var obo interface{}
	if err := tok.Get("obo", &obo); err != nil {
		t.Fatalf("Step 1: getting obo: %v", err)
	}
	if obo != "wimse://acme.com/ns/default/sa/portfolio-mgr" {
		t.Errorf("Step 1: obo = %v", obo)
	}

	// Step 2: Exchange with A2A token type.
	exchangeBody, _ := json.Marshal(core.TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:     agentIdentity.Token,
		SubjectTokenType: "urn:starfly:token-type:agent-a2a",
		Audience:         "https://api.acme.example.com",
		Scope:            "trade:execute",
	})

	resp2, err := http.Post(ts.URL+"/v1/exchange/token", "application/json",
		bytes.NewBuffer(exchangeBody))
	if err != nil {
		t.Fatalf("Step 2: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		var errResp errorResponse
		json.NewDecoder(resp2.Body).Decode(&errResp)
		t.Fatalf("Step 2: status = %d, error = %q: %q", resp2.StatusCode, errResp.Error, errResp.ErrorDescription)
	}

	var exchangeResp core.TokenExchangeResponse
	if err := json.NewDecoder(resp2.Body).Decode(&exchangeResp); err != nil {
		t.Fatalf("Step 2: decoding: %v", err)
	}

	if exchangeResp.AccessToken == "" {
		t.Fatal("Step 2: access_token is empty")
	}

	// Step 3: Verify WIMSE JWT.
	wimseToken, err := jwt.ParseInsecure([]byte(exchangeResp.AccessToken))
	if err != nil {
		t.Fatalf("Step 3: parsing WIMSE JWT: %v", err)
	}

	aud, _ := wimseToken.Audience()
	if len(aud) == 0 || aud[0] != "https://api.acme.example.com" {
		t.Errorf("Step 3: aud = %v, want [https://api.acme.example.com]", aud)
	}
}
