package federation

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus collectors for federation observability.
type Metrics struct {
	PeerReachable   *prometheus.GaugeVec
	PeerJWKSAge     *prometheus.GaugeVec
	PeerKeyCount    *prometheus.GaugeVec
	PeerFetchTotal  *prometheus.CounterVec
	PeerErrorTotal  *prometheus.CounterVec
}

// NewMetrics creates federation metrics and registers them.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		PeerReachable: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "starfly",
				Subsystem: "federation",
				Name:      "peer_reachable",
				Help:      "Whether a federated peer is reachable (1=healthy, 0.5=stale, 0=unreachable).",
			},
			[]string{"fabric_id"},
		),
		PeerJWKSAge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "starfly",
				Subsystem: "federation",
				Name:      "peer_jwks_age_seconds",
				Help:      "Age of the cached JWKS for a federated peer in seconds.",
			},
			[]string{"fabric_id"},
		),
		PeerKeyCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "starfly",
				Subsystem: "federation",
				Name:      "peer_key_count",
				Help:      "Number of public keys cached for a federated peer.",
			},
			[]string{"fabric_id"},
		),
		PeerFetchTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "starfly",
				Subsystem: "federation",
				Name:      "peer_fetch_total",
				Help:      "Total number of successful JWKS fetches from a federated peer.",
			},
			[]string{"fabric_id"},
		),
		PeerErrorTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "starfly",
				Subsystem: "federation",
				Name:      "peer_error_total",
				Help:      "Total number of failed JWKS fetches from a federated peer.",
			},
			[]string{"fabric_id"},
		),
	}

	if reg != nil {
		reg.MustRegister(
			m.PeerReachable,
			m.PeerJWKSAge,
			m.PeerKeyCount,
			m.PeerFetchTotal,
			m.PeerErrorTotal,
		)
	}

	return m
}

// Update refreshes all metrics from the current federation state.
func (m *Metrics) Update(state *FederationState) {
	for id, ps := range state.Peers {
		switch ps.Status {
		case PeerHealthy:
			m.PeerReachable.WithLabelValues(id).Set(1)
		case PeerStale:
			m.PeerReachable.WithLabelValues(id).Set(0.5)
		case PeerUnreachable:
			m.PeerReachable.WithLabelValues(id).Set(0)
		}

		m.PeerJWKSAge.WithLabelValues(id).Set(ps.Age().Seconds())
		m.PeerKeyCount.WithLabelValues(id).Set(float64(ps.KeyCount))
	}
}
