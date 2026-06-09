package agent

import (
	"context"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestWithTTL(t *testing.T) {
	p, err := NewProvider(WithTTL(10 * time.Minute))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.ttl != 10*time.Minute {
		t.Errorf("ttl = %v, want 10m", p.ttl)
	}
}

func TestWithIssuer(t *testing.T) {
	p, err := NewProvider(WithIssuer("custom-issuer"))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.issuer != "custom-issuer" {
		t.Errorf("issuer = %q, want custom-issuer", p.issuer)
	}
}

func TestResolveTrustDomain_FallbackToFirstConfigured(t *testing.T) {
	domains := []core.TrustDomain{
		{Name: "acme.prod", Enabled: true},
	}
	p, err := NewProvider(
		WithDevMode(false),
		WithTrustDomains(domains),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	req := &core.AgentIdentityRequest{
		AgentName:    "test-agent",
		Platform:     "mcp",
		Capabilities: []string{"read"},
	}

	identity, err := p.IssueAgentIdentity(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueAgentIdentity: %v", err)
	}
	if identity.WorkloadID != "wimse://acme.prod/agent/mcp/test-agent" {
		t.Errorf("workload_id = %q, want wimse://acme.prod/agent/mcp/test-agent", identity.WorkloadID)
	}
}

func TestResolveTrustDomain_MetadataUnknownDomain(t *testing.T) {
	domains := []core.TrustDomain{
		{Name: "acme.prod", Enabled: true},
	}
	p, err := NewProvider(
		WithDevMode(false),
		WithTrustDomains(domains),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	req := &core.AgentIdentityRequest{
		AgentName:    "test-agent",
		Platform:     "mcp",
		Capabilities: []string{"read"},
		Metadata:     map[string]string{"trust_domain": "unknown.example.com"},
	}

	identity, err := p.IssueAgentIdentity(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueAgentIdentity: %v", err)
	}
	if identity.WorkloadID != "wimse://acme.prod/agent/mcp/test-agent" {
		t.Errorf("workload_id = %q, want wimse://acme.prod/agent/mcp/test-agent", identity.WorkloadID)
	}
}

func TestResolveTrustDomain_NoDomainsNotDevMode(t *testing.T) {
	p, err := NewProvider(WithDevMode(false))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	req := &core.AgentIdentityRequest{
		AgentName:    "test-agent",
		Platform:     "mcp",
		Capabilities: []string{"read"},
	}

	identity, err := p.IssueAgentIdentity(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueAgentIdentity: %v", err)
	}
	if identity.WorkloadID != "wimse://dev.local/agent/mcp/test-agent" {
		t.Errorf("workload_id = %q, want wimse://dev.local/agent/mcp/test-agent", identity.WorkloadID)
	}
}

func TestResolveTrustDomain_EmptyMetadataTrustDomain(t *testing.T) {
	domains := []core.TrustDomain{
		{Name: "acme.prod", Enabled: true},
	}
	p, err := NewProvider(
		WithDevMode(false),
		WithTrustDomains(domains),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	req := &core.AgentIdentityRequest{
		AgentName:    "test-agent",
		Platform:     "mcp",
		Capabilities: []string{"read"},
		Metadata:     map[string]string{"trust_domain": ""},
	}

	identity, err := p.IssueAgentIdentity(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueAgentIdentity: %v", err)
	}
	if identity.WorkloadID != "wimse://acme.prod/agent/mcp/test-agent" {
		t.Errorf("workload_id = %q, want wimse://acme.prod/agent/mcp/test-agent", identity.WorkloadID)
	}
}

func TestRevokeIdentity_NoAuditorNoSyncBus(t *testing.T) {
	p, err := NewProvider(WithDevMode(true))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	err = p.RevokeIdentity(context.Background(), "wimse://dev.local/agent/mcp/test")
	if err != nil {
		t.Fatalf("RevokeIdentity: %v", err)
	}
}
