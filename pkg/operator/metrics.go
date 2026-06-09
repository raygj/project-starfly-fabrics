package operator

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ReconcileTotal counts reconciliation attempts by result.
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "starfly",
			Subsystem: "operator",
			Name:      "reconcile_total",
			Help:      "Total number of reconciliation attempts.",
		},
		[]string{"result"}, // success, error, no_change
	)

	// ReconcileDuration tracks reconciliation duration.
	ReconcileDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "starfly",
			Subsystem: "operator",
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of reconciliation loops in seconds.",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15), // 1ms to ~16s
		},
	)

	// ConvergenceActionsTotal counts convergence actions by type.
	ConvergenceActionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "starfly",
			Subsystem: "operator",
			Name:      "convergence_actions_total",
			Help:      "Total number of convergence actions applied.",
		},
		[]string{"type"}, // add_trust_domain, rotate_signing_key, etc.
	)

	// WebhookValidationsTotal counts webhook validation attempts.
	WebhookValidationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "starfly",
			Subsystem: "operator",
			Name:      "webhook_validations_total",
			Help:      "Total number of webhook validation attempts.",
		},
		[]string{"result"}, // accepted, rejected
	)
)

// RegisterMetrics registers operator metrics with the given registry.
func RegisterMetrics(reg prometheus.Registerer) {
	reg.MustRegister(
		ReconcileTotal,
		ReconcileDuration,
		ConvergenceActionsTotal,
		WebhookValidationsTotal,
	)
}
