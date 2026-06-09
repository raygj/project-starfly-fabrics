package exchange

import (
	"context"
	"errors"
	"testing"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestMapCredType_AgentTypes(t *testing.T) {
	tests := []struct {
		tokenType string
		want      string
		wantErr   bool
	}{
		{subjectTokenTypeJWT, "k8s-sa", false},
		{subjectTokenTypeSPIFFE, "spiffe-svid", false},
		{subjectTokenTypeOIDC, "oidc", false},
		{subjectTokenTypeKerberos, "kerberos", false},
		{subjectTokenTypeSAML, "saml", false},
		{subjectTokenTypeSAML2, "saml", false},
		{subjectTokenTypeAWSSTS, "aws-sts", false},
		{subjectTokenTypeGCPWIF, "gcp-wif", false},
		{subjectTokenTypeAzureMI, "azure-mi", false},
		{subjectTokenTypeMTLS, "mtls", false},
		{subjectTokenTypeOAuth2, "oauth2", false},
		{subjectTokenTypeAPIKey, "api-key", false},
		{subjectTokenTypeAgentMCP, "agent-mcp", false},
		{subjectTokenTypeAgentA2A, "agent-a2a", false},
		{subjectTokenTypeAgentPassport, "agent-passport", false},
		{"urn:totally:unknown:type", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.tokenType, func(t *testing.T) {
			got, err := mapCredType(tt.tokenType)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrUnsupportedToken) {
					t.Fatalf("expected ErrUnsupportedToken, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("mapCredType(%q) = %q, want %q", tt.tokenType, got, tt.want)
			}
		})
	}
}

func TestExchange_AgentTokenType_Succeeds(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
	}{
		{"agent-mcp", subjectTokenTypeAgentMCP},
		{"agent-a2a", subjectTokenTypeAgentA2A},
		{"agent-passport", subjectTokenTypeAgentPassport},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditor := &mockAuditor{}
			engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
			if err != nil {
				t.Fatalf("creating engine: %v", err)
			}

			req := validRequest()
			req.SubjectTokenType = tt.tokenType

			resp, err := engine.Exchange(context.Background(), req)
			if err != nil {
				t.Fatalf("exchange failed for %s: %v", tt.name, err)
			}
			if resp.AccessToken == "" {
				t.Error("access token is empty")
			}
			if resp.TokenType != "Bearer" {
				t.Errorf("token type = %q, want Bearer", resp.TokenType)
			}
		})
	}
}

func TestExchange_AgentCredType_PolicyContextEnriched(t *testing.T) {
	var capturedInput *core.PolicyInput
	capturingPolicy := &capturingMockPolicy{
		inner: &core.PolicyDecision{Allowed: true},
	}

	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), capturingPolicy, auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	// Agent request.
	req := validRequest()
	req.SubjectTokenType = subjectTokenTypeAgentMCP
	_, _ = engine.Exchange(context.Background(), req)
	capturedInput = capturingPolicy.lastInput

	if capturedInput == nil {
		t.Fatal("policy was not called")
	}
	if capturedInput.Context["is_agent"] != true {
		t.Error("is_agent not set in policy context")
	}
	if capturedInput.Context["agent_platform"] != "agent-mcp" {
		t.Errorf("agent_platform = %v, want agent-mcp", capturedInput.Context["agent_platform"])
	}

	// K8s SA request should NOT have agent context.
	capturingPolicy.lastInput = nil
	req2 := validRequest()
	_, _ = engine.Exchange(context.Background(), req2)
	capturedInput = capturingPolicy.lastInput

	if capturedInput == nil {
		t.Fatal("policy was not called for K8s request")
	}
	if _, ok := capturedInput.Context["is_agent"]; ok {
		t.Error("is_agent should not be set for K8s SA exchange")
	}
	if _, ok := capturedInput.Context["agent_platform"]; ok {
		t.Error("agent_platform should not be set for K8s SA exchange")
	}
}

func TestExchange_K8sSA_Regression(t *testing.T) {
	auditor := &mockAuditor{}
	engine, err := New(goodIdentity(), allowPolicy(nil), auditor)
	if err != nil {
		t.Fatalf("creating engine: %v", err)
	}

	resp, err := engine.Exchange(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("K8s SA exchange failed: %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", resp.TokenType)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want 300", resp.ExpiresIn)
	}
	if resp.Scope != "read:secrets" {
		t.Errorf("Scope = %q, want read:secrets", resp.Scope)
	}
}

// capturingMockPolicy captures the last PolicyInput for inspection.
type capturingMockPolicy struct {
	inner     *core.PolicyDecision
	lastInput *core.PolicyInput
}

func (m *capturingMockPolicy) Evaluate(_ context.Context, input *core.PolicyInput) (*core.PolicyDecision, error) {
	m.lastInput = input
	return m.inner, nil
}

func (m *capturingMockPolicy) LoadBundle(context.Context, string) error {
	return nil
}
