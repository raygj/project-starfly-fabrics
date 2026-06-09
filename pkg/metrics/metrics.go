package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "starfly"

// Metrics holds all Prometheus collectors for a Starfly unit.
type Metrics struct {
	reg *prometheus.Registry

	ExchangeRequestsTotal   *prometheus.CounterVec
	ExchangeDurationSeconds *prometheus.HistogramVec

	PolicyEvaluationsTotal          *prometheus.CounterVec
	PolicyEvaluationDurationSeconds *prometheus.HistogramVec

	StoreOperationsTotal *prometheus.CounterVec

	AuditEventsTotal *prometheus.CounterVec

	RateLimitRejectedTotal *prometheus.CounterVec

	SyncSignalsTotal *prometheus.CounterVec

	TLSHandshakeDurationSeconds *prometheus.HistogramVec

	UnitInfo *prometheus.GaugeVec

	RevocationCheckErrorsTotal prometheus.Counter

	// Autonomic health metrics (DQ-002 / P8-008).
	ExchangeActive              prometheus.Gauge
	NATSConsumerLag             prometheus.Gauge
	RevocationIndexSize         prometheus.Gauge
	JWKSFetchErrorsTotal        prometheus.Counter
	AuditBufferSize             prometheus.Gauge
	SoulSnapshotDurationSeconds prometheus.Histogram
	SoulAnchorAgeSeconds        prometheus.Gauge

	// Delegation metrics (P11-003).
	DelegationActive        *prometheus.GaugeVec
	DelegationDepthMax      prometheus.Gauge
	BlastRadiusDenialsTotal *prometheus.CounterVec

	// Execution scope metrics (P11-003).
	ExecutionScopeTotal *prometheus.CounterVec

	// Revocation detail metrics (P11-003).
	RevocationWriteDurationSeconds  prometheus.Histogram
	RevocationLookupDurationSeconds prometheus.Histogram

	// CAEP cascade metrics (P11-003).
	CAEPCascadeDurationSeconds  prometheus.Histogram
	CAEPCascadeTokensInvalidated prometheus.Counter

	// NATS detail metrics (P11-003).
	NATSPublishedTotal *prometheus.CounterVec
	NATSReceivedTotal  *prometheus.CounterVec

	// Soul detail metrics (P11-003).
	SoulManifestSequence prometheus.Gauge
	SoulAnchorReachable  prometheus.Gauge

	// Fabric topology metrics (P11-003).
	FabricUnitsTotal       prometheus.Gauge
	FabricUnitsHealthy     prometheus.Gauge
	FabricTrustDomainsTotal prometheus.Gauge

	// JWKS cache metrics (P11-003).
	JWKSCacheHitsTotal   prometheus.Counter
	JWKSCacheMissesTotal prometheus.Counter
	JWKSCacheSize        prometheus.Gauge

	// Policy detail metrics (P11-003).
	PolicyDenialsTotal     *prometheus.CounterVec
	PolicyBundleReloadTotal prometheus.Counter

	// TLS certificate expiry metric (TLS-004).
	TLSCertExpirySeconds prometheus.Gauge

	// MCP middleware metrics (P6d).
	MCPToolCallsTotal         *prometheus.CounterVec
	MCPVerifyDurationSeconds  *prometheus.HistogramVec
	MCPRegisteredTools        prometheus.Gauge
	MCPTokenAcquisitionsTotal *prometheus.CounterVec
	MCPCheckDenialsTotal      *prometheus.CounterVec

	// Secret delivery metrics (ADR-0014).
	SecretDeliveryTotal           *prometheus.CounterVec
	SecretDeliveryDurationSeconds *prometheus.HistogramVec
	SecretSourceReachable         *prometheus.GaugeVec

	// Management plane metrics (ADR-0018 Hyper PAM).
	ManagementOperationsTotal        *prometheus.CounterVec
	ManagementDenialsTotal           *prometheus.CounterVec
	ManagementBlastRadiusExceeded    *prometheus.CounterVec
	ManagementApprovalRequiredTotal  *prometheus.CounterVec
	ManagementAfterHoursTotal        *prometheus.CounterVec
	ManagementThirdPartyDenialsTotal *prometheus.CounterVec

	// Federation signal metrics (P13-006).
	FederationRelayTotal          *prometheus.CounterVec
	FederationRelayDuration       *prometheus.HistogramVec
	FederationReceivedTotal       *prometheus.CounterVec
	FederationSyncTotal           *prometheus.CounterVec
	FederationSyncMismatchesTotal *prometheus.CounterVec
	FederationRevocationLag       *prometheus.GaugeVec

	// Universal tool-call metrics (UTC-009).
	ToolCallTotal               *prometheus.CounterVec
	ToolCallDurationSeconds     *prometheus.HistogramVec
	ToolCallProtocolTiesTotal   prometheus.Counter
	ToolRegisteredTools         prometheus.Gauge
}

// New creates a Metrics instance, registers all collectors, and sets the
// unit_info gauge with the supplied labels.
func New(version, unitID, trustDomain string) *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		reg: reg,

		ExchangeRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exchange_requests_total",
			Help:      "Total number of token exchange requests.",
		}, []string{"status", "source_type", "target_domain"}),

		ExchangeDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "exchange_duration_seconds",
			Help:      "Duration of token exchange operations in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{}),

		PolicyEvaluationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "policy_evaluations_total",
			Help:      "Total number of OPA policy evaluations.",
		}, []string{"action", "decision"}),

		PolicyEvaluationDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "policy_evaluation_duration_seconds",
			Help:      "Duration of OPA policy evaluations in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{}),

		StoreOperationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "store_operations_total",
			Help:      "Total number of KV store operations.",
		}, []string{"operation"}),

		AuditEventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "audit_events_total",
			Help:      "Total number of audit events logged.",
		}, []string{"type", "action"}),

		RateLimitRejectedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "ratelimit_rejected_total",
			Help:      "Total number of requests rejected by rate limiting.",
		}, []string{"scope"}),

		SyncSignalsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "sync_signals_total",
			Help:      "Total number of sync bus signal flashes.",
		}, []string{"type", "status"}),

		TLSHandshakeDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "tls_handshake_duration_seconds",
			Help:      "Duration of TLS handshakes on the mTLS listener in seconds.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25},
		}, []string{"status"}),

		UnitInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "unit_info",
			Help:      "Static metadata about this Starfly unit.",
		}, []string{"version", "unit_id", "trust_domain"}),

		RevocationCheckErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "revocation_check_errors_total",
			Help:      "Total number of revocation check failures (fail-open events).",
		}),

		ExchangeActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "exchange_active",
			Help:      "Number of concurrent exchanges in flight.",
		}),

		NATSConsumerLag: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "nats_consumer_lag",
			Help:      "Number of messages behind on NATS signal processing.",
		}),

		RevocationIndexSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "revocation_index_size",
			Help:      "Current number of entries in the revocation index.",
		}),

		JWKSFetchErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "jwks_fetch_errors_total",
			Help:      "Total number of JWKS fetch failures.",
		}),

		AuditBufferSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "audit_buffer_size",
			Help:      "Number of audit events buffered but not yet flushed.",
		}),

		SoulSnapshotDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "soul_snapshot_duration_seconds",
			Help:      "Duration of soul manifest snapshot writes to the anchor.",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5},
		}),

		SoulAnchorAgeSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "soul_anchor_age_seconds",
			Help:      "Seconds since the last successful soul snapshot was written to the anchor.",
		}),

		// Delegation metrics (P11-003).
		DelegationActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "delegation_active",
			Help:      "Active delegation chains by depth.",
		}, []string{"depth"}),

		DelegationDepthMax: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "delegation_depth_max",
			Help:      "Maximum observed delegation depth.",
		}),

		BlastRadiusDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "blast_radius_denials_total",
			Help:      "Blast radius violations by scope.",
		}, []string{"scope"}),

		// Execution scope metrics (P11-003).
		ExecutionScopeTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "execution_scope_total",
			Help:      "Execution-scoped exchanges by action.",
		}, []string{"action"}),

		// Revocation detail metrics (P11-003).
		RevocationWriteDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "revocation_write_duration_seconds",
			Help:      "Time to write a revocation entry.",
			Buckets:   []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01},
		}),

		RevocationLookupDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "revocation_lookup_duration_seconds",
			Help:      "Time to check if a token is revoked.",
			Buckets:   []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01},
		}),

		// CAEP cascade metrics (P11-003).
		CAEPCascadeDurationSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "caep_cascade_duration_seconds",
			Help:      "Total cascade propagation time.",
			Buckets:   []float64{0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0},
		}),

		CAEPCascadeTokensInvalidated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "caep_cascade_tokens_invalidated",
			Help:      "Tokens invalidated by cascades.",
		}),

		// NATS detail metrics (P11-003).
		NATSPublishedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "nats_published_total",
			Help:      "Signals published by subject.",
		}, []string{"subject"}),

		NATSReceivedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "nats_received_total",
			Help:      "Signals received by subject.",
		}, []string{"subject"}),

		// Soul detail metrics (P11-003).
		SoulManifestSequence: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "soul_manifest_sequence",
			Help:      "Current manifest sequence number.",
		}),

		SoulAnchorReachable: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "soul_anchor_reachable",
			Help:      "Whether the soul anchor is reachable (0 or 1).",
		}),

		// Fabric topology metrics (P11-003).
		FabricUnitsTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "fabric_units_total",
			Help:      "Total units in fabric.",
		}),

		FabricUnitsHealthy: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "fabric_units_healthy",
			Help:      "Healthy units in fabric.",
		}),

		FabricTrustDomainsTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "fabric_trust_domains_total",
			Help:      "Number of trust domains.",
		}),

		// JWKS cache metrics (P11-003).
		JWKSCacheHitsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "jwks_cache_hits_total",
			Help:      "JWKS cache hits.",
		}),

		JWKSCacheMissesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "jwks_cache_misses_total",
			Help:      "JWKS cache misses.",
		}),

		JWKSCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "jwks_cache_size",
			Help:      "Current JWKS cache size.",
		}),

		// Policy detail metrics (P11-003).
		PolicyDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "policy_denials_total",
			Help:      "Policy denials by rule name.",
		}, []string{"rule"}),

		PolicyBundleReloadTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "policy_bundle_reload_total",
			Help:      "Policy bundle reloads.",
		}),

		// TLS certificate expiry metric (TLS-004).
		TLSCertExpirySeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "tls_cert_expiry_seconds",
			Help:      "Seconds until the TLS certificate expires.",
		}),

		// MCP middleware metrics (P6d).
		MCPToolCallsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "mcp_tool_calls_total",
			Help:      "Total MCP tool call verification attempts.",
		}, []string{"tool_id", "decision"}),

		MCPVerifyDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "mcp_verify_duration_seconds",
			Help:      "Duration of MCP tool call verification.",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		}, []string{}),

		MCPRegisteredTools: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "mcp_registered_tools",
			Help:      "Number of tools in the MCP registry.",
		}),

		MCPTokenAcquisitionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "mcp_token_acquisitions_total",
			Help:      "Total MCP client token acquisition attempts.",
		}, []string{"status"}),

		MCPCheckDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "mcp_check_denials_total",
			Help:      "MCP verification denials by pipeline check name.",
		}, []string{"check"}),

		// Universal tool-call metrics (UTC-009).
		ToolCallTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tool_call_total",
			Help:      "Total universal tool call verification attempts by protocol and decision.",
		}, []string{"protocol", "decision"}),

		ToolCallDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "tool_call_duration_seconds",
			Help:      "Duration of universal tool call verification by protocol.",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
		}, []string{"protocol"}),

		ToolCallProtocolTiesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tool_call_protocol_ties_total",
			Help:      "Number of times two adapters returned equal confidence — anomaly indicator for protocol confusion attempts.",
		}),

		ToolRegisteredTools: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "tool_registered_tools",
			Help:      "Number of tools in the universal tool registry.",
		}),

		// Secret delivery metrics (ADR-0014).
		SecretDeliveryTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "secret_delivery_total",
			Help:      "Total secret delivery attempts by source and result.",
		}, []string{"source", "result"}),

		SecretDeliveryDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "secret_delivery_duration_seconds",
			Help:      "Duration of secret delivery operations.",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
		}, []string{"source"}),

		SecretSourceReachable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "secret_source_reachable",
			Help:      "Whether a secret source is reachable (0 or 1).",
		}, []string{"source"}),

		// Management plane metrics (ADR-0018 Hyper PAM).
		ManagementOperationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "management_operations_total",
			Help:      "Total management plane operations by tool and result.",
		}, []string{"tool_id", "exec_act", "result"}),

		ManagementDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "management_denials_total",
			Help:      "Total management plane denials by tool and reason.",
		}, []string{"tool_id", "exec_act", "denial_reason"}),

		ManagementBlastRadiusExceeded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "management_blast_radius_exceeded_total",
			Help:      "Total management operations that exceeded blast radius.",
		}, []string{"tool_id"}),

		ManagementApprovalRequiredTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "management_approval_required_total",
			Help:      "Total management operations requiring multi-person approval.",
		}, []string{"tool_id", "exec_act"}),

		ManagementAfterHoursTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "management_after_hours_attempts_total",
			Help:      "Total management operations attempted outside business hours.",
		}, []string{"tool_id"}),

		ManagementThirdPartyDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "management_third_party_denials_total",
			Help:      "Total management operations denied for third-party accounts.",
		}, []string{"vendor", "exec_act"}),

		// Federation signal metrics (P13-006).
		FederationRelayTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "federation_relay_total",
			Help:      "Total revocation signals relayed to federation peers.",
		}, []string{"peer", "result"}),

		FederationRelayDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "federation_relay_duration_seconds",
			Help:      "Duration of revocation relay to federation peers.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5},
		}, []string{"peer"}),

		FederationReceivedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "federation_received_total",
			Help:      "Total revocation signals received from federation peers.",
		}, []string{"peer", "result"}),

		FederationSyncTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "federation_sync_total",
			Help:      "Total hash-based revocation sync attempts with federation peers.",
		}, []string{"peer", "result"}),

		FederationSyncMismatchesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "federation_sync_mismatches_total",
			Help:      "Total revocation hash mismatches detected with federation peers.",
		}, []string{"peer"}),

		FederationRevocationLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "federation_revocation_lag_seconds",
			Help:      "Seconds since last successful revocation relay to federation peer.",
		}, []string{"peer"}),
	}

	reg.MustRegister(
		m.ExchangeRequestsTotal,
		m.ExchangeDurationSeconds,
		m.PolicyEvaluationsTotal,
		m.PolicyEvaluationDurationSeconds,
		m.StoreOperationsTotal,
		m.AuditEventsTotal,
		m.RateLimitRejectedTotal,
		m.SyncSignalsTotal,
		m.TLSHandshakeDurationSeconds,
		m.UnitInfo,
		m.RevocationCheckErrorsTotal,
		m.ExchangeActive,
		m.NATSConsumerLag,
		m.RevocationIndexSize,
		m.JWKSFetchErrorsTotal,
		m.AuditBufferSize,
		m.SoulSnapshotDurationSeconds,
		m.SoulAnchorAgeSeconds,
		// P11-003 additions.
		m.DelegationActive,
		m.DelegationDepthMax,
		m.BlastRadiusDenialsTotal,
		m.ExecutionScopeTotal,
		m.RevocationWriteDurationSeconds,
		m.RevocationLookupDurationSeconds,
		m.CAEPCascadeDurationSeconds,
		m.CAEPCascadeTokensInvalidated,
		m.NATSPublishedTotal,
		m.NATSReceivedTotal,
		m.SoulManifestSequence,
		m.SoulAnchorReachable,
		m.FabricUnitsTotal,
		m.FabricUnitsHealthy,
		m.FabricTrustDomainsTotal,
		m.JWKSCacheHitsTotal,
		m.JWKSCacheMissesTotal,
		m.JWKSCacheSize,
		m.PolicyDenialsTotal,
		m.PolicyBundleReloadTotal,
		// TLS-004.
		m.TLSCertExpirySeconds,
		// P6d additions.
		m.MCPToolCallsTotal,
		m.MCPVerifyDurationSeconds,
		m.MCPRegisteredTools,
		m.MCPTokenAcquisitionsTotal,
		m.MCPCheckDenialsTotal,
		// ADR-0014 additions.
		m.SecretDeliveryTotal,
		m.SecretDeliveryDurationSeconds,
		m.SecretSourceReachable,
		// ADR-0018 Hyper PAM additions.
		m.ManagementOperationsTotal,
		m.ManagementDenialsTotal,
		m.ManagementBlastRadiusExceeded,
		m.ManagementApprovalRequiredTotal,
		m.ManagementAfterHoursTotal,
		m.ManagementThirdPartyDenialsTotal,
		// P13-006 additions.
		m.FederationRelayTotal,
		m.FederationRelayDuration,
		m.FederationReceivedTotal,
		m.FederationSyncTotal,
		m.FederationSyncMismatchesTotal,
		m.FederationRevocationLag,
		// UTC-009 additions.
		m.ToolCallTotal,
		m.ToolCallDurationSeconds,
		m.ToolCallProtocolTiesTotal,
		m.ToolRegisteredTools,
	)

	// Set the info gauge once — value 1 makes it visible in /metrics.
	m.UnitInfo.WithLabelValues(version, unitID, trustDomain).Set(1)

	return m
}

// Handler returns an http.Handler that serves the Prometheus metrics
// endpoint for the custom registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
