package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/starfly-fabrics/starfly/pkg/core"
)

// --- test doubles ---

type mockAuditor struct {
	events []*core.AuditEvent
}

func (m *mockAuditor) Log(_ context.Context, ev *core.AuditEvent) error {
	m.events = append(m.events, ev)
	return nil
}

type mockSyncBus struct {
	signals   []*core.Signal
	flashErr  error
}

func (m *mockSyncBus) Flash(_ context.Context, sig *core.Signal) error {
	if m.flashErr != nil {
		return m.flashErr
	}
	m.signals = append(m.signals, sig)
	return nil
}

func (m *mockSyncBus) Subscribe(_ context.Context, _ string, _ core.SignalHandler) error {
	return nil
}

func (m *mockSyncBus) Replay(_ context.Context, _ time.Time) ([]*core.Signal, error) {
	return nil, nil
}

// --- IssueAgentIdentity tests ---

func TestProvider_IssueAgentIdentity(t *testing.T) {
	tests := []struct {
		name      string
		req       *core.AgentIdentityRequest
		devMode   bool
		wantErr   error
		wantURI   string
		wantPlat  string
	}{
		{
			name: "mcp agent happy path",
			req: &core.AgentIdentityRequest{
				AgentName:    "code-assistant",
				Platform:     "mcp",
				Capabilities: []string{"query-read"},
			},
			devMode:  true,
			wantURI:  "wimse://dev.local/agent/mcp/code-assistant",
			wantPlat: "mcp",
		},
		{
			name: "a2a agent happy path",
			req: &core.AgentIdentityRequest{
				AgentName:    "trading-bot",
				Platform:     "a2a",
				Capabilities: []string{"trade-execute", "portfolio-read"},
				OnBehalfOf:   "wimse://acme.com/ns/default/sa/portfolio-mgr",
			},
			devMode:  true,
			wantURI:  "wimse://dev.local/agent/a2a/trading-bot",
			wantPlat: "a2a",
		},
		{
			name: "watsonx agent happy path",
			req: &core.AgentIdentityRequest{
				AgentName:       "compliance-checker",
				Platform:        "watsonx",
				Capabilities:    []string{"audit-read"},
				MaxBlastRadius:  "workspace:compliance",
				DelegationDepth: 2,
			},
			devMode:  true,
			wantURI:  "wimse://dev.local/agent/watsonx/compliance-checker",
			wantPlat: "watsonx",
		},
		{
			name: "custom agent happy path",
			req: &core.AgentIdentityRequest{
				AgentName:    "internal-scanner",
				Platform:     "custom",
				Capabilities: []string{"scan-run"},
			},
			devMode:  true,
			wantURI:  "wimse://dev.local/agent/custom/internal-scanner",
			wantPlat: "custom",
		},
		{
			name: "trust domain from metadata",
			req: &core.AgentIdentityRequest{
				AgentName:    "prod-agent",
				Platform:     "mcp",
				Capabilities: []string{"read"},
				Metadata:     map[string]string{"trust_domain": "acme.prod"},
			},
			devMode:  false,
			wantURI:  "wimse://acme.prod/agent/mcp/prod-agent",
			wantPlat: "mcp",
		},
		{
			name: "missing agent name",
			req: &core.AgentIdentityRequest{
				Platform:     "mcp",
				Capabilities: []string{"read"},
			},
			wantErr: ErrMissingAgentName,
		},
		{
			name: "invalid platform",
			req: &core.AgentIdentityRequest{
				AgentName:    "bad-agent",
				Platform:     "unsupported",
				Capabilities: []string{"read"},
			},
			wantErr: ErrInvalidPlatform,
		},
		{
			name: "empty capabilities",
			req: &core.AgentIdentityRequest{
				AgentName:    "no-caps",
				Platform:     "mcp",
				Capabilities: []string{},
			},
			wantErr: ErrEmptyCapabilities,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditor := &mockAuditor{}
			domains := []core.TrustDomain{
				{Name: "acme.prod", Enabled: true},
			}
			p, err := NewProvider(
				WithDevMode(tt.devMode),
				WithAuditor(auditor),
				WithTrustDomains(domains),
			)
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}

			identity, err := p.IssueAgentIdentity(context.Background(), tt.req)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if identity.WorkloadID != tt.wantURI {
				t.Errorf("workload_id = %q, want %q", identity.WorkloadID, tt.wantURI)
			}
			if identity.Token == "" {
				t.Error("token is empty")
			}
			if identity.ExpiresAt.IsZero() {
				t.Error("expires_at is zero")
			}

			// Verify JWT claims.
			tok, err := jwt.ParseInsecure([]byte(identity.Token))
			if err != nil {
				t.Fatalf("parsing issued JWT: %v", err)
			}
			sub, _ := tok.Subject()
			if sub != tt.wantURI {
				t.Errorf("JWT sub = %q, want %q", sub, tt.wantURI)
			}
			var platform interface{}
			if err := tok.Get("agent_platform", &platform); err != nil {
				t.Fatalf("getting agent_platform claim: %v", err)
			}
			if platform != tt.wantPlat {
				t.Errorf("agent_platform = %v, want %q", platform, tt.wantPlat)
			}

			// Verify audit event was recorded.
			if len(auditor.events) == 0 {
				t.Fatal("no audit event recorded")
			}
			ev := auditor.events[0]
			if ev.Action != "agent_identity_issued" {
				t.Errorf("audit action = %q, want %q", ev.Action, "agent_identity_issued")
			}
		})
	}
}

func TestProvider_IssueAgentIdentity_DelegationDepth(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	req := &core.AgentIdentityRequest{
		AgentName:       "deep-agent",
		Platform:        "a2a",
		Capabilities:    []string{"delegate"},
		DelegationDepth: 3,
	}

	identity, err := p.IssueAgentIdentity(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tok, err := jwt.ParseInsecure([]byte(identity.Token))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var depth interface{}
	if err := tok.Get("delegation_depth", &depth); err != nil {
		t.Fatalf("getting delegation_depth: %v", err)
	}
	// JWT numeric values may deserialize as json.Number or float64.
	switch v := depth.(type) {
	case json.Number:
		n, _ := v.Int64()
		if n != 3 {
			t.Errorf("delegation_depth = %d, want 3", n)
		}
	case float64:
		if int(v) != 3 {
			t.Errorf("delegation_depth = %v, want 3", v)
		}
	default:
		t.Errorf("delegation_depth unexpected type %T = %v", depth, depth)
	}
}

func TestProvider_IssueAgentIdentity_BlastRadius(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	req := &core.AgentIdentityRequest{
		AgentName:      "scoped-agent",
		Platform:       "mcp",
		Capabilities:   []string{"query-read"},
		MaxBlastRadius: "db:analytics",
	}

	identity, err := p.IssueAgentIdentity(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tok, err := jwt.ParseInsecure([]byte(identity.Token))
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	var br interface{}
	if err := tok.Get("blast_radius", &br); err != nil {
		t.Fatalf("getting blast_radius: %v", err)
	}
	if br != "db:analytics" {
		t.Errorf("blast_radius = %v, want %q", br, "db:analytics")
	}
}

// --- RevokeIdentity tests ---

func TestProvider_RevokeIdentity(t *testing.T) {
	tests := []struct {
		name       string
		identityID string
		flashErr   error
		wantErr    error
	}{
		{
			name:       "happy path",
			identityID: "wimse://dev.local/agent/mcp/test-agent",
		},
		{
			name:       "invalid identity ID - not wimse URI",
			identityID: "spiffe://example.com/bad",
			wantErr:    ErrInvalidIdentityID,
		},
		{
			name:       "invalid identity ID - empty",
			identityID: "",
			wantErr:    ErrInvalidIdentityID,
		},
		{
			name:       "sync bus flash error",
			identityID: "wimse://dev.local/agent/mcp/test-agent",
			flashErr:   errors.New("nats unavailable"),
			wantErr:    errors.New("flashing revocation signal"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditor := &mockAuditor{}
			bus := &mockSyncBus{flashErr: tt.flashErr}
			p, err := NewProvider(
				WithDevMode(true),
				WithAuditor(auditor),
				WithSyncBus(bus),
			)
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}

			err = p.RevokeIdentity(context.Background(), tt.identityID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if errors.Is(tt.wantErr, ErrInvalidIdentityID) {
					if !errors.Is(err, ErrInvalidIdentityID) {
						t.Fatalf("expected ErrInvalidIdentityID, got %v", err)
					}
				} else if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr.Error(), err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify audit event.
			found := false
			for _, ev := range auditor.events {
				if ev.Action == "agent_identity_revoked" {
					found = true
					break
				}
			}
			if !found {
				t.Error("no revocation audit event recorded")
			}

			// Verify signal was flashed.
			if len(bus.signals) == 0 {
				t.Fatal("no signal flashed on revoke")
			}
			sig := bus.signals[0]
			if sig.Type != "identity_event" {
				t.Errorf("signal type = %q, want %q", sig.Type, "identity_event")
			}
			if sig.Payload["action"] != "revoked" {
				t.Errorf("signal action = %v, want %q", sig.Payload["action"], "revoked")
			}
		})
	}
}
