package metrics

import (
	"github.com/starfly-fabrics/starfly/pkg/toolcall"
)

// ToolCallMiddlewareMetrics returns a *toolcall.MiddlewareMetrics wired to
// this instance's UTC-009 Prometheus counters. Pass the result to
// toolcall.Config.Metrics when constructing the dispatch middleware.
// Returns nil when m is nil (safe for test stubs).
func (m *Metrics) ToolCallMiddlewareMetrics() *toolcall.MiddlewareMetrics {
	if m == nil {
		return nil
	}
	return &toolcall.MiddlewareMetrics{
		RecordCall: func(protocol, decision string) {
			m.ToolCallTotal.WithLabelValues(protocol, decision).Inc()
		},
		ObserveDuration: func(protocol string, seconds float64) {
			m.ToolCallDurationSeconds.WithLabelValues(protocol).Observe(seconds)
		},
		IncTie: func() {
			m.ToolCallProtocolTiesTotal.Inc()
		},
	}
}
