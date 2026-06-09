package lifecycle

import (
	"fmt"
	"log/slog"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

// Worker wraps a Temporal worker that processes lifecycle workflows
// and activities on the starfly-lifecycle task queue.
type Worker struct {
	inner      worker.Worker
	activities *Activities
}

// NewWorker creates a lifecycle worker. Call Start() to begin processing.
func NewWorker(c *Client, activities *Activities) (*Worker, error) {
	if c == nil {
		return nil, fmt.Errorf("lifecycle: client is required")
	}
	if activities == nil {
		return nil, fmt.Errorf("lifecycle: activities are required")
	}

	w := worker.New(c.inner, TaskQueue, worker.Options{})

	// Register shared activities.
	w.RegisterActivity(activities.MintExecutionScopedToken)
	w.RegisterActivity(activities.EmitLifecycleSignal)
	w.RegisterActivity(activities.RevokeCredential)
	w.RegisterActivity(activities.CheckRevocationStatus)

	slog.Info("lifecycle: worker created", "task_queue", TaskQueue)

	return &Worker{inner: w, activities: activities}, nil
}

// RegisterWorkflow registers a workflow function with the worker.
// Called by P5b-002 and P5b-003 to add rotation and compliance workflows.
func (w *Worker) RegisterWorkflow(wf interface{}) {
	w.inner.RegisterWorkflow(wf)
}

// RegisterActivity registers an additional activity with the worker.
// Called by P5b-002 and P5b-003 to add domain-specific activities.
func (w *Worker) RegisterActivity(act interface{}) {
	w.inner.RegisterActivity(act)
}

// Start begins processing workflows and activities. Non-blocking.
func (w *Worker) Start() error {
	if err := w.inner.Start(); err != nil {
		return fmt.Errorf("lifecycle: starting worker: %w", err)
	}
	slog.Info("lifecycle: worker started", "task_queue", TaskQueue)
	return nil
}

// Stop gracefully shuts down the worker, waiting for in-progress
// workflows to complete.
func (w *Worker) Stop() {
	w.inner.Stop()
	slog.Info("lifecycle: worker stopped")
}

// StartFromConfig is a convenience function that creates a client, activities,
// and worker from configuration. Returns nil for all values if lifecycle is
// disabled (empty HostPort). The caller is responsible for calling
// worker.Start() and deferring client.Close() and worker.Stop().
func StartFromConfig(cfg ClientConfig, activities *Activities) (*Client, *Worker, error) {
	if cfg.HostPort == "" {
		slog.Warn("lifecycle: temporal host_port not configured, lifecycle worker disabled")
		return nil, nil, nil
	}

	c, err := NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	w, err := NewWorker(c, activities)
	if err != nil {
		c.Close()
		return nil, nil, err
	}

	return c, w, nil
}

// NewClientFromSDK wraps an existing Temporal SDK client. Useful for testing.
func NewClientFromSDK(c client.Client, namespace string) *Client {
	return &Client{inner: c, namespace: namespace}
}
