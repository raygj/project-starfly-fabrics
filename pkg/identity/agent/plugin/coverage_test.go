package plugin

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestNewPluginClient_Success(t *testing.T) {
	client, err := NewPluginClient("localhost:50051", WithTimeout(3*time.Second))
	if err != nil {
		t.Fatalf("NewPluginClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", client.timeout)
	}
}

func TestNewPluginClient_WithAllOptions(t *testing.T) {
	client, err := NewPluginClient("localhost:50052",
		WithTimeout(10*time.Second),
		WithCircuitBreaker(10, time.Minute),
	)
	if err != nil {
		t.Fatalf("NewPluginClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.maxFailures != 10 {
		t.Errorf("maxFailures = %d, want 10", client.maxFailures)
	}
	if client.resetAfter != time.Minute {
		t.Errorf("resetAfter = %v, want 1m", client.resetAfter)
	}
}

func TestRevokeIdentity_CircuitBreakerOpen(t *testing.T) {
	mock := &mockPluginServer{revokeErr: fmt.Errorf("always fails")}
	lis, srv := startMockServer(t, mock)
	defer srv.Stop()

	conn := dialBufconn(t, lis)
	defer func() { _ = conn.Close() }()

	client := newPluginClientWithConn(conn, WithCircuitBreaker(2, 100*time.Millisecond))

	for i := 0; i < 2; i++ {
		_ = client.RevokeIdentity(context.Background(), "wimse://test/agent/mcp/t")
	}

	err := client.RevokeIdentity(context.Background(), "wimse://test/agent/mcp/t")
	if err == nil {
		t.Fatal("expected circuit breaker error")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected circuit breaker error, got: %v", err)
	}
}

func TestIssueAgentIdentity_CircuitBreakerOpen(t *testing.T) {
	mock := &mockPluginServer{issueErr: fmt.Errorf("always fails")}
	lis, srv := startMockServer(t, mock)
	defer srv.Stop()

	conn := dialBufconn(t, lis)
	defer func() { _ = conn.Close() }()

	client := newPluginClientWithConn(conn, WithCircuitBreaker(2, 100*time.Millisecond))

	req := &core.AgentIdentityRequest{
		AgentName: "test", Platform: "mcp", Capabilities: []string{"r"},
	}

	for i := 0; i < 2; i++ {
		_, _ = client.IssueAgentIdentity(context.Background(), req)
	}

	_, err := client.IssueAgentIdentity(context.Background(), req)
	if err == nil {
		t.Fatal("expected circuit breaker error")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected circuit breaker error, got: %v", err)
	}
}

func TestDiscoverPlugins_Success(t *testing.T) {
	cfg := PluginConfig{
		Plugins: []PluginEndpoint{
			{Address: "localhost:50051", Platform: "mcp"},
			{Address: "localhost:50052", Platform: "a2a"},
		},
	}

	providers, err := DiscoverPlugins(cfg)
	if err != nil {
		t.Fatalf("DiscoverPlugins: %v", err)
	}
	if len(providers) != 2 {
		t.Errorf("providers len = %d, want 2", len(providers))
	}
	if _, ok := providers["mcp"]; !ok {
		t.Error("missing mcp provider")
	}
	if _, ok := providers["a2a"]; !ok {
		t.Error("missing a2a provider")
	}
	for _, p := range providers {
		if pc, ok := p.(*PluginClient); ok {
			_ = pc.Close()
		}
	}
}

func TestDiscoverPlugins_WithOptions(t *testing.T) {
	cfg := PluginConfig{
		Plugins: []PluginEndpoint{
			{Address: "localhost:50053", Platform: "watsonx"},
		},
	}

	providers, err := DiscoverPlugins(cfg, WithTimeout(2*time.Second), WithCircuitBreaker(3, time.Minute))
	if err != nil {
		t.Fatalf("DiscoverPlugins: %v", err)
	}
	if len(providers) != 1 {
		t.Errorf("providers len = %d, want 1", len(providers))
	}
	for _, p := range providers {
		if pc, ok := p.(*PluginClient); ok {
			if pc.timeout != 2*time.Second {
				t.Errorf("timeout = %v, want 2s", pc.timeout)
			}
			_ = pc.Close()
		}
	}
}

func TestRevokeIdentity_CircuitBreakerReset(t *testing.T) {
	mock := &mockPluginServer{revokeErr: fmt.Errorf("fails")}
	lis, srv := startMockServer(t, mock)
	defer srv.Stop()

	conn := dialBufconn(t, lis)
	defer func() { _ = conn.Close() }()

	client := newPluginClientWithConn(conn, WithCircuitBreaker(2, 100*time.Millisecond))

	for i := 0; i < 2; i++ {
		_ = client.RevokeIdentity(context.Background(), "wimse://test/agent/mcp/t")
	}

	time.Sleep(150 * time.Millisecond)

	// After reset, call goes through (and fails from the RPC, not circuit breaker).
	err := client.RevokeIdentity(context.Background(), "wimse://test/agent/mcp/t")
	if err == nil {
		t.Fatal("expected RPC error")
	}
	if strings.Contains(err.Error(), "circuit breaker open") {
		t.Error("circuit should have been half-open after reset")
	}
}
