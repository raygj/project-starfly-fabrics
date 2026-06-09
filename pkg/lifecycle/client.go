package lifecycle

import (
	"context"
	"fmt"
	"log/slog"

	"go.temporal.io/sdk/client"
)

// Client wraps a Temporal SDK client for lifecycle workflow operations.
type Client struct {
	inner     client.Client
	namespace string
}

// ClientConfig holds Temporal connection settings.
type ClientConfig struct {
	HostPort  string `yaml:"hostPort"`  // e.g. "localhost:7233"
	Namespace string `yaml:"namespace"` // e.g. "starfly"
}

// NewClient connects to a Temporal server and returns a lifecycle client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.HostPort == "" {
		return nil, fmt.Errorf("lifecycle: temporal host_port is required")
	}
	ns := cfg.Namespace
	if ns == "" {
		ns = "default"
	}

	opts := client.Options{
		HostPort:  cfg.HostPort,
		Namespace: ns,
		Logger:    newSlogAdapter(),
	}

	c, err := client.Dial(opts)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: connecting to temporal at %s: %w", cfg.HostPort, err)
	}

	slog.Info("lifecycle: connected to temporal",
		"host_port", cfg.HostPort,
		"namespace", ns,
	)

	return &Client{inner: c, namespace: ns}, nil
}

// StartWorkflow starts a lifecycle workflow by name.
func (c *Client) StartWorkflow(ctx context.Context, opts client.StartWorkflowOptions, workflow interface{}, args ...interface{}) (client.WorkflowRun, error) {
	if opts.TaskQueue == "" {
		opts.TaskQueue = TaskQueue
	}
	return c.inner.ExecuteWorkflow(ctx, opts, workflow, args...)
}

// SignalWorkflow sends a signal to a running workflow.
func (c *Client) SignalWorkflow(ctx context.Context, workflowID, signalName string, arg interface{}) error {
	return c.inner.SignalWorkflow(ctx, workflowID, "", signalName, arg)
}

// Inner returns the underlying Temporal client for advanced operations.
func (c *Client) Inner() client.Client {
	return c.inner
}

// Close shuts down the Temporal client connection.
func (c *Client) Close() {
	c.inner.Close()
}

// slogAdapter adapts slog to Temporal's log interface.
type slogAdapter struct{}

func newSlogAdapter() *slogAdapter { return &slogAdapter{} }

func (s *slogAdapter) Debug(msg string, keyvals ...interface{}) {
	slog.Debug(msg, keyvals...)
}
func (s *slogAdapter) Info(msg string, keyvals ...interface{}) {
	slog.Info(msg, keyvals...)
}
func (s *slogAdapter) Warn(msg string, keyvals ...interface{}) {
	slog.Warn(msg, keyvals...)
}
func (s *slogAdapter) Error(msg string, keyvals ...interface{}) {
	slog.Error(msg, keyvals...)
}
