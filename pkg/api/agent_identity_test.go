package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	agentpkg "github.com/starfly-fabrics/starfly/pkg/identity/agent"
)

type mockAgentIdentityProvider struct {
	issueFunc  func(ctx context.Context, req *core.AgentIdentityRequest) (*core.AgentIdentity, error)
	revokeFunc func(ctx context.Context, identityID string) error
}

func (m *mockAgentIdentityProvider) IssueAgentIdentity(ctx context.Context, req *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
	return m.issueFunc(ctx, req)
}

func (m *mockAgentIdentityProvider) RevokeIdentity(ctx context.Context, id string) error {
	if m.revokeFunc != nil {
		return m.revokeFunc(ctx, id)
	}
	return nil
}

func goodAgentProvider() *mockAgentIdentityProvider {
	return &mockAgentIdentityProvider{
		issueFunc: func(_ context.Context, req *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
			return &core.AgentIdentity{
				WorkloadID: "wimse://dev.local/agent/" + req.Platform + "/" + req.AgentName,
				Token:      "signed-jwt-placeholder",
				ExpiresAt:  time.Now().Add(5 * time.Minute),
			}, nil
		},
	}
}

func TestHandleAgentIdentity(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		provider   *mockAgentIdentityProvider
		nilProv    bool
		wantStatus int
		wantErr    string
	}{
		{
			name:       "valid MCP agent",
			body:       `{"agent_name":"code-assist","platform":"mcp","capabilities":["query-read"]}`,
			provider:   goodAgentProvider(),
			wantStatus: http.StatusOK,
		},
		{
			name:       "valid A2A agent with delegation",
			body:       `{"agent_name":"trade-bot","platform":"a2a","capabilities":["trade"],"delegation_depth":2}`,
			provider:   goodAgentProvider(),
			wantStatus: http.StatusOK,
		},
		{
			name:       "provider not configured",
			body:       `{"agent_name":"test","platform":"mcp","capabilities":["read"]}`,
			nilProv:    true,
			wantStatus: http.StatusNotImplemented,
			wantErr:    "not_implemented",
		},
		{
			name:       "malformed JSON",
			body:       `{bad json`,
			provider:   goodAgentProvider(),
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid_request",
		},
		{
			name:       "empty body",
			body:       ``,
			provider:   goodAgentProvider(),
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid_request",
		},
		{
			name: "missing agent name",
			body: `{"platform":"mcp","capabilities":["read"]}`,
			provider: &mockAgentIdentityProvider{
				issueFunc: func(_ context.Context, _ *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
					return nil, agentpkg.ErrMissingAgentName
				},
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid_request",
		},
		{
			name: "invalid platform",
			body: `{"agent_name":"test","platform":"bad","capabilities":["read"]}`,
			provider: &mockAgentIdentityProvider{
				issueFunc: func(_ context.Context, _ *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
					return nil, agentpkg.ErrInvalidPlatform
				},
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid_request",
		},
		{
			name: "empty capabilities",
			body: `{"agent_name":"test","platform":"mcp","capabilities":[]}`,
			provider: &mockAgentIdentityProvider{
				issueFunc: func(_ context.Context, _ *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
					return nil, agentpkg.ErrEmptyCapabilities
				},
			},
			wantStatus: http.StatusBadRequest,
			wantErr:    "invalid_request",
		},
		{
			name: "provider internal error",
			body: `{"agent_name":"test","platform":"mcp","capabilities":["read"]}`,
			provider: &mockAgentIdentityProvider{
				issueFunc: func(_ context.Context, _ *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
					return nil, errors.New("signing key unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantErr:    "server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []ServerOption
			if !tt.nilProv && tt.provider != nil {
				opts = append(opts, WithAgentIdentity(tt.provider))
			}

			cfg := &core.Config{
				ListenAddr: ":0",
				RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
			}
			s := New(cfg, "test", nil, opts...)

			req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent",
				strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			s.httpServer.Handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			if tt.wantErr != "" {
				var resp errorResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("decoding error response: %v", err)
				}
				if resp.Error != tt.wantErr {
					t.Errorf("error = %q, want %q", resp.Error, tt.wantErr)
				}
			}

			if tt.wantStatus == http.StatusOK {
				var identity core.AgentIdentity
				if err := json.NewDecoder(w.Body).Decode(&identity); err != nil {
					t.Fatalf("decoding identity response: %v", err)
				}
				if identity.WorkloadID == "" {
					t.Error("workload_id is empty")
				}
				if identity.Token == "" {
					t.Error("token is empty")
				}
			}
		})
	}
}

func TestHandleAgentIdentity_ResponseContentType(t *testing.T) {
	cfg := &core.Config{
		ListenAddr: ":0",
		RateLimit:  core.RateLimitConfig{GlobalRate: 100, GlobalBurst: 100, PerIPRate: 10, PerIPBurst: 10},
	}
	s := New(cfg, "test", nil, WithAgentIdentity(goodAgentProvider()))

	req := httptest.NewRequest(http.MethodPost, "/v1/identity/agent",
		strings.NewReader(`{"agent_name":"test","platform":"mcp","capabilities":["read"]}`))
	w := httptest.NewRecorder()

	s.httpServer.Handler.ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}
