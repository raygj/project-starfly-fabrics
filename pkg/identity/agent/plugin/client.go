package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

const (
	servicePath = "/starfly.identity.agent.plugin.v1.AgentIdentityPlugin/"
	methodIssue = servicePath + "IssueAgentIdentity"
	methodRevoke = servicePath + "RevokeIdentity"
)

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

// jsonCodec is a gRPC codec that uses JSON encoding.
// Drop-in replacement for protobuf codec that works without
// generated code. Replace with protobuf encoding once proto
// stubs are generated (see gen.sh).
type jsonCodec struct{}

func (jsonCodec) Marshal(v interface{}) ([]byte, error)     { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }
func (jsonCodec) Name() string                              { return "json" }

// Ensure the codec implements encoding.Codec.
var _ encoding.Codec = jsonCodec{}

var _ core.AgentIdentityProvider = (*PluginClient)(nil)

// PluginClient connects to a remote gRPC AgentIdentityPlugin and
// adapts it to core.AgentIdentityProvider.
type PluginClient struct {
	conn    *grpc.ClientConn
	timeout time.Duration

	mu          sync.Mutex
	failures    int
	maxFailures int
	resetAfter  time.Duration
	lastFailure time.Time
	tripped     bool
}

// ClientOption configures the plugin client.
type ClientOption func(*PluginClient)

func WithTimeout(d time.Duration) ClientOption {
	return func(c *PluginClient) { c.timeout = d }
}

func WithCircuitBreaker(maxFailures int, resetTimeout time.Duration) ClientOption {
	return func(c *PluginClient) {
		c.maxFailures = maxFailures
		c.resetAfter = resetTimeout
	}
}

// NewPluginClient dials the gRPC plugin at the given address.
func NewPluginClient(addr string, opts ...ClientOption) (*PluginClient, error) {
	c := &PluginClient{
		timeout:     5 * time.Second,
		maxFailures: 5,
		resetAfter:  30 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	}

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("plugin: dialing %s: %w", addr, err)
	}
	c.conn = conn
	return c, nil
}

// newPluginClientWithConn creates a client from an existing connection (for testing).
func newPluginClientWithConn(conn *grpc.ClientConn, opts ...ClientOption) *PluginClient {
	c := &PluginClient{
		conn:        conn,
		timeout:     5 * time.Second,
		maxFailures: 5,
		resetAfter:  30 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *PluginClient) IssueAgentIdentity(ctx context.Context, req *core.AgentIdentityRequest) (*core.AgentIdentity, error) {
	if err := c.checkCircuit(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	grpcReq := &IssueAgentIdentityRequest{
		AgentName:       req.AgentName,
		Platform:        req.Platform,
		Capabilities:    req.Capabilities,
		OnBehalfOf:      req.OnBehalfOf,
		MaxBlastRadius:  req.MaxBlastRadius,
		DelegationDepth: int32(req.DelegationDepth),
		Metadata:        req.Metadata,
	}

	var resp IssueAgentIdentityResponse
	if err := c.conn.Invoke(ctx, methodIssue, grpcReq, &resp); err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("plugin: IssueAgentIdentity RPC: %w", err)
	}

	c.recordSuccess()
	return &core.AgentIdentity{
		WorkloadID: resp.WorkloadID,
		SpiffeID:   resp.SpiffeID,
		Token:      resp.Token,
		ExpiresAt:  time.Unix(resp.ExpiresAtUnix, 0),
	}, nil
}

func (c *PluginClient) RevokeIdentity(ctx context.Context, identityID string) error {
	if err := c.checkCircuit(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	grpcReq := &RevokeIdentityRequest{IdentityID: identityID}
	var resp RevokeIdentityResponse
	if err := c.conn.Invoke(ctx, methodRevoke, grpcReq, &resp); err != nil {
		c.recordFailure()
		return fmt.Errorf("plugin: RevokeIdentity RPC: %w", err)
	}

	c.recordSuccess()
	return nil
}

// Close shuts down the gRPC connection.
func (c *PluginClient) Close() error {
	return c.conn.Close()
}

func (c *PluginClient) checkCircuit() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.tripped {
		return nil
	}
	if time.Since(c.lastFailure) > c.resetAfter {
		c.tripped = false
		c.failures = 0
		return nil
	}
	return fmt.Errorf("plugin: circuit breaker open (%d consecutive failures)", c.failures)
}

func (c *PluginClient) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	c.lastFailure = time.Now()
	if c.failures >= c.maxFailures {
		c.tripped = true
	}
}

func (c *PluginClient) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.tripped = false
}
