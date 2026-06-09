package agent

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the starfly-agent.
type Metrics struct {
	AttestationSources     *prometheus.GaugeVec
	TokenAgeSeconds        prometheus.Gauge
	TokenRefreshesTotal    prometheus.Counter
	AttestationFailures    *prometheus.CounterVec
	ExchangeLatencySeconds prometheus.Histogram
	ExchangeErrorsTotal    prometheus.Counter

	registry *prometheus.Registry
}

// NewMetrics creates and registers all agent metrics.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())

	m := &Metrics{
		AttestationSources: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "starfly_agent_attestation_sources",
			Help: "Available attestation sources (1 = available, 0 = unavailable).",
		}, []string{"type"}),

		TokenAgeSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "starfly_agent_token_age_seconds",
			Help: "Seconds since last token refresh.",
		}),

		TokenRefreshesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "starfly_agent_token_refreshes_total",
			Help: "Total number of token refreshes (lifetime).",
		}),

		AttestationFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "starfly_agent_attestation_failures_total",
			Help: "Total attestation failures by source.",
		}, []string{"source"}),

		ExchangeLatencySeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "starfly_agent_exchange_latency_seconds",
			Help:    "Starfly exchange round-trip latency.",
			Buckets: prometheus.DefBuckets,
		}),

		ExchangeErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "starfly_agent_exchange_errors_total",
			Help: "Total exchange errors.",
		}),

		registry: reg,
	}

	reg.MustRegister(
		m.AttestationSources,
		m.TokenAgeSeconds,
		m.TokenRefreshesTotal,
		m.AttestationFailures,
		m.ExchangeLatencySeconds,
		m.ExchangeErrorsTotal,
	)

	return m
}

// Handler returns an http.Handler for the /metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
