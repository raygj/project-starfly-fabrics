package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Renewer performs the attest → exchange → serve loop, refreshing
// the token at a configurable fraction of its TTL.
type Renewer struct {
	attestors     []Attestor
	client        *ExchangeClient
	server        TokenServer
	ratio         float64
	version       string
	metrics       *Metrics
	backoffDelays []time.Duration // overridable for testing
}

// RenewerConfig holds parameters for the renewal loop.
type RenewerConfig struct {
	Attestors     []Attestor
	Client        *ExchangeClient
	Server        TokenServer
	RefreshRatio  float64
	AgentVersion  string
	Metrics       *Metrics
	BackoffDelays []time.Duration // override default backoff schedule (for testing)
}

// NewRenewer creates a Renewer from the given config.
func NewRenewer(cfg RenewerConfig) *Renewer {
	ratio := cfg.RefreshRatio
	if ratio <= 0 || ratio >= 1 {
		ratio = 0.8
	}
	return &Renewer{
		attestors:     cfg.Attestors,
		client:        cfg.Client,
		server:        cfg.Server,
		ratio:         ratio,
		version:       cfg.AgentVersion,
		metrics:       cfg.Metrics,
		backoffDelays: cfg.BackoffDelays,
	}
}

// Run performs an initial exchange then loops, renewing at ratio * TTL.
// It blocks until ctx is cancelled. On exchange failure it retries with
// exponential backoff (1s → 2s → 4s → … → 30s max).
func (r *Renewer) Run(ctx context.Context) error {
	for {
		result, err := r.exchangeOnce(ctx)
		if err != nil {
			slog.Error("exchange failed, will retry", "error", err)
			if r.metrics != nil {
				r.metrics.ExchangeErrorsTotal.Inc()
			}
			if backoffErr := r.backoff(ctx); backoffErr != nil {
				if errors.Is(backoffErr, ErrBackoffExhausted) {
					// All retries failed — re-enter the loop which will
					// call exchangeOnce again and re-enter backoff.
					continue
				}
				return nil // context cancelled
			}
			continue
		}

		if err := r.server.UpdateToken(result.AccessToken); err != nil {
			return fmt.Errorf("updating token: %w", err)
		}

		sleepDur := time.Duration(float64(time.Duration(result.ExpiresIn)*time.Second) * r.ratio)
		slog.Info("token exchanged, next renewal scheduled",
			"expires_in", result.ExpiresIn,
			"refresh_in", sleepDur.Round(time.Second),
		)

		if r.metrics != nil {
			r.metrics.TokenRefreshesTotal.Inc()
			r.metrics.TokenAgeSeconds.Set(0)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(sleepDur):
		}
	}
}

func (r *Renewer) exchangeOnce(ctx context.Context) (*ExchangeResult, error) {
	start := time.Now()

	bundle, err := BundleAttestations(ctx, r.attestors, r.version)
	if err != nil {
		if r.metrics != nil {
			// Determine which attestor failed from the error message prefix.
			r.metrics.AttestationFailures.WithLabelValues("bundle").Inc()
		}
		return nil, fmt.Errorf("attestation: %w", err)
	}

	result, err := r.client.Exchange(ctx, bundle)
	if err != nil {
		return nil, err
	}

	if r.metrics != nil {
		r.metrics.ExchangeLatencySeconds.Observe(time.Since(start).Seconds())
	}

	return result, nil
}

// ErrBackoffExhausted is returned when all retry attempts in the backoff
// sequence have failed. The caller should re-enter the backoff loop
// (with a delay) rather than immediately retrying.
var ErrBackoffExhausted = fmt.Errorf("backoff retries exhausted")

// backoff performs exponential backoff with configurable delays.
// Returns nil on successful exchange, ctx.Err() on cancellation, or
// ErrBackoffExhausted if all retries fail. The delays field allows
// tests to use shorter durations.
func (r *Renewer) backoff(ctx context.Context) error {
	delays := r.backoffDelays
	if len(delays) == 0 {
		delays = []time.Duration{
			1 * time.Second,
			2 * time.Second,
			4 * time.Second,
			8 * time.Second,
			16 * time.Second,
			30 * time.Second,
		}
	}

	var lastErr error
	for _, d := range delays {
		slog.Debug("backoff", "wait", d)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}

		_, err := r.exchangeOnce(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		slog.Warn("retry failed", "error", err, "next_wait", d*2)
		if r.metrics != nil {
			r.metrics.ExchangeErrorsTotal.Inc()
		}
	}

	slog.Error("backoff exhausted, will restart backoff cycle", "last_error", lastErr)
	return ErrBackoffExhausted
}
