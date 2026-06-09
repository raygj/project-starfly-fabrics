package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Config holds all configuration for the agent.
type Config struct {
	Server       string
	Audience     string
	TokenPath    string
	Scope        string
	RefreshRatio float64
	MetricsAddr  string
	CACertPath   string
	Version      string
}

// Agent wires all components together: attestors, exchange client,
// token server, renewer, and metrics.
type Agent struct {
	config    Config
	attestors []Attestor
	client    *ExchangeClient
	server    TokenServer
	renewer   *Renewer
	metrics   *Metrics
}

// NewWithAttestors constructs an Agent with explicitly provided attestors.
// Use this in tests or environments where auto-discovery is not appropriate.
func NewWithAttestors(cfg Config, attestors []Attestor) (*Agent, error) {
	client, err := NewExchangeClient(ExchangeClientConfig{
		ServerURL:  cfg.Server,
		Audience:   cfg.Audience,
		Scope:      cfg.Scope,
		CACertPath: cfg.CACertPath,
	})
	if err != nil {
		return nil, fmt.Errorf("creating exchange client: %w", err)
	}

	tokenServer := NewFileTokenServer(cfg.TokenPath)
	metrics := NewMetrics()

	renewer := NewRenewer(RenewerConfig{
		Attestors:    attestors,
		Client:       client,
		Server:       tokenServer,
		RefreshRatio: cfg.RefreshRatio,
		AgentVersion: cfg.Version,
		Metrics:      metrics,
	})

	return &Agent{
		config:    cfg,
		attestors: attestors,
		client:    client,
		server:    tokenServer,
		renewer:   renewer,
		metrics:   metrics,
	}, nil
}

// New constructs an Agent, auto-discovering available attestors.
func New(cfg Config) (*Agent, error) {
	client, err := NewExchangeClient(ExchangeClientConfig{
		ServerURL:  cfg.Server,
		Audience:   cfg.Audience,
		Scope:      cfg.Scope,
		CACertPath: cfg.CACertPath,
	})
	if err != nil {
		return nil, fmt.Errorf("creating exchange client: %w", err)
	}

	tokenServer := NewFileTokenServer(cfg.TokenPath)
	metrics := NewMetrics()

	// Auto-discover attestors. Order matters: first attestor with a
	// credential becomes the platform attestor. K8s is checked first
	// (most common), then cloud IMDS (fast 2s timeout), then binary
	// self-measurement (always available, provides workload metadata).
	attestors := []Attestor{
		NewK8sAttestor("", ""),
		NewAWSAttestor(""),
		NewGCPAttestor("", cfg.Audience),
		NewAzureAttestor("", ""),
		NewBinaryAttestor(""),
	}

	renewer := NewRenewer(RenewerConfig{
		Attestors:    attestors,
		Client:       client,
		Server:       tokenServer,
		RefreshRatio: cfg.RefreshRatio,
		AgentVersion: cfg.Version,
		Metrics:      metrics,
	})

	return &Agent{
		config:    cfg,
		attestors: attestors,
		client:    client,
		server:    tokenServer,
		renewer:   renewer,
		metrics:   metrics,
	}, nil
}

// Run starts the agent: logs discovered attestors, starts the token server
// and metrics endpoint, then runs the renewal loop until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	// Log discovered attestors and update metrics.
	for _, att := range a.attestors {
		avail := att.Available(ctx)
		status := "unavailable"
		if avail {
			status = "available"
			a.metrics.AttestationSources.WithLabelValues(att.Name()).Set(1)
		} else {
			a.metrics.AttestationSources.WithLabelValues(att.Name()).Set(0)
		}
		slog.Info("attestor discovered", "name", att.Name(), "status", status)
	}

	// Start token server.
	if err := a.server.Start(ctx); err != nil {
		return fmt.Errorf("starting token server: %w", err)
	}

	// Start metrics HTTP server.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", a.metrics.Handler())
	metricsServer := &http.Server{
		Addr:              a.config.MetricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("metrics server starting", "addr", a.config.MetricsAddr)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "error", err)
		}
	}()

	// Run renewal loop (blocks until ctx cancelled).
	err := a.renewer.Run(ctx)

	// Graceful shutdown of metrics server.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if shutErr := metricsServer.Shutdown(shutdownCtx); shutErr != nil {
		slog.Error("metrics server shutdown error", "error", shutErr)
	}

	return err
}
