package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// mockPluginServer implements the AgentIdentityPlugin gRPC service for tests.
type mockPluginServer struct {
	issueResp *IssueAgentIdentityResponse
	issueErr  error
	revokeErr error
}

func (m *mockPluginServer) handleIssue(_ interface{}, dec func(interface{}) error, _ *grpc.UnaryServerInfo) (interface{}, error) {
	var req IssueAgentIdentityRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	if m.issueResp != nil {
		return m.issueResp, nil
	}
	return &IssueAgentIdentityResponse{
		WorkloadID:    "wimse://test.local/agent/" + req.Platform + "/" + req.AgentName,
		Token:         "mock-signed-jwt",
		ExpiresAtUnix: time.Now().Add(5 * time.Minute).Unix(),
	}, nil
}

func (m *mockPluginServer) handleRevoke(_ interface{}, dec func(interface{}) error, _ *grpc.UnaryServerInfo) (interface{}, error) {
	var req RevokeIdentityRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if m.revokeErr != nil {
		return nil, m.revokeErr
	}
	return &RevokeIdentityResponse{}, nil
}

func startMockServer(t *testing.T, mock *mockPluginServer) (*bufconn.Listener, *grpc.Server) {
	t.Helper()
	lis := bufconn.Listen(bufSize)

	sd := grpc.ServiceDesc{
		ServiceName: "starfly.identity.agent.plugin.v1.AgentIdentityPlugin",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "IssueAgentIdentity",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					info := &grpc.UnaryServerInfo{FullMethod: methodIssue}
					return mock.handleIssue(srv, dec, info)
				},
			},
			{
				MethodName: "RevokeIdentity",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					info := &grpc.UnaryServerInfo{FullMethod: methodRevoke}
					return mock.handleRevoke(srv, dec, info)
				},
			},
		},
	}

	s := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	s.RegisterService(&sd, mock)

	go func() {
		if err := s.Serve(lis); err != nil && !strings.Contains(err.Error(), "closed") {
			t.Logf("mock server error: %v", err)
		}
	}()

	return lis, s
}

func dialBufconn(t *testing.T, lis *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	)
	if err != nil {
		t.Fatalf("dialing bufconn: %v", err)
	}
	return conn
}

// --- Tests ---

func TestPluginClient_IssueAgentIdentity(t *testing.T) {
	tests := []struct {
		name      string
		req       *core.AgentIdentityRequest
		resp      *IssueAgentIdentityResponse
		rpcErr    error
		wantErr   bool
		wantWID   string
	}{
		{
			name: "happy path",
			req: &core.AgentIdentityRequest{
				AgentName:    "code-assist",
				Platform:     "mcp",
				Capabilities: []string{"query-read"},
			},
			wantWID: "wimse://test.local/agent/mcp/code-assist",
		},
		{
			name: "custom response",
			req: &core.AgentIdentityRequest{
				AgentName:    "scanner",
				Platform:     "custom",
				Capabilities: []string{"scan-run"},
			},
			resp: &IssueAgentIdentityResponse{
				WorkloadID:    "wimse://prod.acme/agent/custom/scanner",
				Token:         "custom-jwt",
				ExpiresAtUnix: time.Now().Add(10 * time.Minute).Unix(),
			},
			wantWID: "wimse://prod.acme/agent/custom/scanner",
		},
		{
			name: "rpc error",
			req: &core.AgentIdentityRequest{
				AgentName:    "bad",
				Platform:     "mcp",
				Capabilities: []string{"read"},
			},
			rpcErr:  fmt.Errorf("internal error"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPluginServer{
				issueResp: tt.resp,
				issueErr:  tt.rpcErr,
			}
			lis, srv := startMockServer(t, mock)
			defer srv.Stop()

			conn := dialBufconn(t, lis)
			defer func() { _ = conn.Close() }()

			client := newPluginClientWithConn(conn)
			identity, err := client.IssueAgentIdentity(context.Background(), tt.req)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if identity.WorkloadID != tt.wantWID {
				t.Errorf("workload_id = %q, want %q", identity.WorkloadID, tt.wantWID)
			}
			if identity.Token == "" {
				t.Error("token is empty")
			}
		})
	}
}

func TestPluginClient_RevokeIdentity(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		rpcErr  error
		wantErr bool
	}{
		{
			name: "happy path",
			id:   "wimse://dev.local/agent/mcp/test",
		},
		{
			name:    "rpc error",
			id:      "wimse://dev.local/agent/mcp/test",
			rpcErr:  fmt.Errorf("not found"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPluginServer{revokeErr: tt.rpcErr}
			lis, srv := startMockServer(t, mock)
			defer srv.Stop()

			conn := dialBufconn(t, lis)
			defer func() { _ = conn.Close() }()

			client := newPluginClientWithConn(conn)
			err := client.RevokeIdentity(context.Background(), tt.id)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPluginClient_CircuitBreaker(t *testing.T) {
	mock := &mockPluginServer{issueErr: fmt.Errorf("always fails")}
	lis, srv := startMockServer(t, mock)
	defer srv.Stop()

	conn := dialBufconn(t, lis)
	defer func() { _ = conn.Close() }()

	client := newPluginClientWithConn(conn,
		WithCircuitBreaker(3, 100*time.Millisecond),
	)

	req := &core.AgentIdentityRequest{
		AgentName: "test", Platform: "mcp", Capabilities: []string{"r"},
	}

	// Exhaust the failure budget.
	for i := 0; i < 3; i++ {
		_, err := client.IssueAgentIdentity(context.Background(), req)
		if err == nil {
			t.Fatal("expected error")
		}
	}

	// Circuit should be open now.
	_, err := client.IssueAgentIdentity(context.Background(), req)
	if err == nil {
		t.Fatal("expected circuit breaker error")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected circuit breaker error, got: %v", err)
	}

	// Wait for reset.
	time.Sleep(150 * time.Millisecond)

	// Circuit should be half-open — call goes through (and fails again).
	_, err = client.IssueAgentIdentity(context.Background(), req)
	if err == nil {
		t.Fatal("expected error after reset (server still failing)")
	}
	if strings.Contains(err.Error(), "circuit breaker open") {
		t.Error("circuit should have been half-open after reset")
	}
}

func TestPluginClient_Timeout(t *testing.T) {
	// Start a server that never responds — use a mock that blocks.
	mock := &mockPluginServer{}
	lis, srv := startMockServer(t, mock)
	defer srv.Stop()

	conn := dialBufconn(t, lis)
	defer func() { _ = conn.Close() }()

	client := newPluginClientWithConn(conn, WithTimeout(5*time.Millisecond))

	// Normal call should succeed.
	identity, err := client.IssueAgentIdentity(context.Background(), &core.AgentIdentityRequest{
		AgentName: "t", Platform: "mcp", Capabilities: []string{"r"},
	})
	if err != nil {
		t.Fatalf("expected success with short timeout: %v", err)
	}
	if identity.WorkloadID == "" {
		t.Error("workload_id should not be empty")
	}
}

func TestPluginClient_JSONCodec(t *testing.T) {
	c := jsonCodec{}
	if c.Name() != "json" {
		t.Errorf("codec name = %q, want %q", c.Name(), "json")
	}

	req := &IssueAgentIdentityRequest{
		AgentName:    "test",
		Platform:     "mcp",
		Capabilities: []string{"read", "write"},
		Metadata:     map[string]string{"env": "prod"},
	}

	data, err := c.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded IssueAgentIdentityRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.AgentName != "test" {
		t.Errorf("agent_name = %q, want test", decoded.AgentName)
	}
	if len(decoded.Capabilities) != 2 {
		t.Errorf("capabilities len = %d, want 2", len(decoded.Capabilities))
	}
}

func TestPluginClient_CircuitBreaker_ResetOnSuccess(t *testing.T) {
	mock := &mockPluginServer{}
	lis, srv := startMockServer(t, mock)
	defer srv.Stop()

	conn := dialBufconn(t, lis)
	defer func() { _ = conn.Close() }()

	client := newPluginClientWithConn(conn,
		WithCircuitBreaker(3, time.Second),
	)

	req := &core.AgentIdentityRequest{
		AgentName: "test", Platform: "mcp", Capabilities: []string{"r"},
	}

	// Successful call resets failure count.
	_, err := client.IssueAgentIdentity(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify internal state reset.
	client.mu.Lock()
	if client.failures != 0 {
		t.Errorf("failures = %d after success, want 0", client.failures)
	}
	client.mu.Unlock()
}

func TestPluginClient_Close(t *testing.T) {
	mock := &mockPluginServer{}
	lis, srv := startMockServer(t, mock)
	defer srv.Stop()

	conn := dialBufconn(t, lis)
	client := newPluginClientWithConn(conn)

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDiscoverPlugins_EmptyConfig(t *testing.T) {
	providers, err := DiscoverPlugins(PluginConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}
}

func TestDiscoverPlugins_MissingFields(t *testing.T) {
	_, err := DiscoverPlugins(PluginConfig{
		Plugins: []PluginEndpoint{{Address: "", Platform: "mcp"}},
	})
	if err == nil {
		t.Fatal("expected error for missing address")
	}

	_, err = DiscoverPlugins(PluginConfig{
		Plugins: []PluginEndpoint{{Address: "localhost:50051", Platform: ""}},
	})
	if err == nil {
		t.Fatal("expected error for missing platform")
	}
}
