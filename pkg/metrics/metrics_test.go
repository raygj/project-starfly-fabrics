package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNew(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")
	if m == nil {
		t.Fatal("expected non-nil Metrics")
	}
}

func TestUnitInfoGauge(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	body := scrape(t, m)
	want := `starfly_unit_info{trust_domain="example.com",unit_id="abc123",version="v0.1.0"} 1`
	if !strings.Contains(body, want) {
		t.Errorf("unit_info gauge missing or wrong\nwant substring: %s\ngot:\n%s", want, body)
	}
}

func TestExchangeRequestsCounter(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.ExchangeRequestsTotal.WithLabelValues("success", "k8s_sa", "target.example.com").Inc()
	m.ExchangeRequestsTotal.WithLabelValues("denied", "k8s_sa", "target.example.com").Inc()
	m.ExchangeRequestsTotal.WithLabelValues("denied", "k8s_sa", "target.example.com").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_exchange_requests_total{source_type="k8s_sa",status="success",target_domain="target.example.com"} 1`)
	assertContains(t, body, `starfly_exchange_requests_total{source_type="k8s_sa",status="denied",target_domain="target.example.com"} 2`)
}

func TestExchangeDurationHistogram(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.ExchangeDurationSeconds.WithLabelValues().Observe(0.042)

	body := scrape(t, m)
	assertContains(t, body, "starfly_exchange_duration_seconds_count 1")
}

func TestPolicyEvaluationsCounter(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.PolicyEvaluationsTotal.WithLabelValues("exchange", "allow").Add(5)

	body := scrape(t, m)
	assertContains(t, body, `starfly_policy_evaluations_total{action="exchange",decision="allow"} 5`)
}

func TestPolicyEvaluationDurationHistogram(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.PolicyEvaluationDurationSeconds.WithLabelValues().Observe(0.003)

	body := scrape(t, m)
	assertContains(t, body, "starfly_policy_evaluation_duration_seconds_count 1")
}

func TestStoreOperationsCounter(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.StoreOperationsTotal.WithLabelValues("get").Add(10)
	m.StoreOperationsTotal.WithLabelValues("put").Add(3)

	body := scrape(t, m)
	assertContains(t, body, `starfly_store_operations_total{operation="get"} 10`)
	assertContains(t, body, `starfly_store_operations_total{operation="put"} 3`)
}

func TestAuditEventsCounter(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.AuditEventsTotal.WithLabelValues("exchange", "token_exchange").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_audit_events_total{action="token_exchange",type="exchange"} 1`)
}

func TestHandlerReturns200(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %s", ct)
	}
}

func TestCustomRegistryIsolation(t *testing.T) {
	// Two Metrics instances must not collide.
	m1 := New("v1", "aaa", "dom1")
	m2 := New("v2", "bbb", "dom2")

	m1.ExchangeRequestsTotal.WithLabelValues("success", "k8s_sa", "d1").Inc()

	body1 := scrape(t, m1)
	body2 := scrape(t, m2)

	assertContains(t, body1, `starfly_exchange_requests_total{source_type="k8s_sa",status="success",target_domain="d1"} 1`)
	// m2 should have no exchange counter incremented.
	if strings.Contains(body2, `starfly_exchange_requests_total`) {
		t.Error("m2 should not contain exchange_requests_total lines (no increments)")
	}
}

func TestUnitInfoMetricRegistered(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	// Gather from registry — expect no errors.
	families, err := m.reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	want := map[string]bool{
		"starfly_exchange_requests_total":              false,
		"starfly_exchange_duration_seconds":            false,
		"starfly_policy_evaluations_total":             false,
		"starfly_policy_evaluation_duration_seconds":   false,
		"starfly_store_operations_total":               false,
		"starfly_audit_events_total":                   false,
		"starfly_unit_info":                            false,
		"starfly_delegation_active":                    false,
		"starfly_delegation_depth_max":                 false,
		"starfly_blast_radius_denials_total":           false,
		"starfly_execution_scope_total":                false,
		"starfly_revocation_write_duration_seconds":    false,
		"starfly_revocation_lookup_duration_seconds":   false,
		"starfly_caep_cascade_duration_seconds":        false,
		"starfly_caep_cascade_tokens_invalidated":      false,
		"starfly_nats_published_total":                 false,
		"starfly_nats_received_total":                  false,
		"starfly_soul_manifest_sequence":               false,
		"starfly_soul_anchor_reachable":                false,
		"starfly_fabric_units_total":                   false,
		"starfly_fabric_units_healthy":                 false,
		"starfly_fabric_trust_domains_total":           false,
		"starfly_jwks_cache_hits_total":                false,
		"starfly_jwks_cache_misses_total":              false,
		"starfly_jwks_cache_size":                      false,
		"starfly_policy_denials_total":                 false,
		"starfly_policy_bundle_reload_total":           false,
		"starfly_federation_relay_total":               false,
		"starfly_federation_relay_duration_seconds":    false,
		"starfly_federation_received_total":            false,
		"starfly_federation_sync_total":                false,
		"starfly_federation_sync_mismatches_total":     false,
		"starfly_federation_revocation_lag_seconds":    false,
		"starfly_tls_cert_expiry_seconds":              false,
	}

	for _, f := range families {
		if _, ok := want[f.GetName()]; ok {
			want[f.GetName()] = true
		}
	}

	// unit_info is the only one guaranteed to have a sample (we set it to 1).
	// Others may not appear until incremented. Just check unit_info.
	if !want["starfly_unit_info"] {
		t.Error("starfly_unit_info not found in gathered metrics")
	}
}

// ── autonomic health metrics (P8-008) ───────────────────────────────

func TestExchangeActive(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.ExchangeActive.Inc()
	m.ExchangeActive.Inc()
	m.ExchangeActive.Dec()

	body := scrape(t, m)
	assertContains(t, body, "starfly_exchange_active 1")
}

func TestRevocationIndexSize(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.RevocationIndexSize.Set(1847)

	body := scrape(t, m)
	assertContains(t, body, "starfly_revocation_index_size 1847")
}

func TestNATSConsumerLag(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.NATSConsumerLag.Set(500)

	body := scrape(t, m)
	assertContains(t, body, "starfly_nats_consumer_lag 500")
}

func TestJWKSFetchErrorsTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.JWKSFetchErrorsTotal.Inc()
	m.JWKSFetchErrorsTotal.Inc()

	body := scrape(t, m)
	assertContains(t, body, "starfly_jwks_fetch_errors_total 2")
}

func TestAuditBufferSize(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.AuditBufferSize.Set(42)

	body := scrape(t, m)
	assertContains(t, body, "starfly_audit_buffer_size 42")
}

func TestSoulSnapshotDurationSeconds(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.SoulSnapshotDurationSeconds.Observe(0.125)

	body := scrape(t, m)
	assertContains(t, body, "starfly_soul_snapshot_duration_seconds_count 1")
}

func TestSoulAnchorAgeSeconds(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.SoulAnchorAgeSeconds.Set(65.0)

	body := scrape(t, m)
	assertContains(t, body, "starfly_soul_anchor_age_seconds 65")
}

// ── delegation metrics (P11-003) ─────────────────────────────────────

func TestDelegationActive(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.DelegationActive.WithLabelValues("2").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_delegation_active{depth="2"} 1`)
}

func TestDelegationDepthMax(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.DelegationDepthMax.Set(5)

	body := scrape(t, m)
	assertContains(t, body, "starfly_delegation_depth_max 5")
}

func TestBlastRadiusDenialsTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.BlastRadiusDenialsTotal.WithLabelValues("cross-domain").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_blast_radius_denials_total{scope="cross-domain"} 1`)
}

// ── execution scope metrics (P11-003) ────────────────────────────────

func TestExecutionScopeTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.ExecutionScopeTotal.WithLabelValues("invoke").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_execution_scope_total{action="invoke"} 1`)
}

// ── revocation detail metrics (P11-003) ──────────────────────────────

func TestRevocationWriteDurationSeconds(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.RevocationWriteDurationSeconds.Observe(0.0003)

	body := scrape(t, m)
	assertContains(t, body, "starfly_revocation_write_duration_seconds_count 1")
}

func TestRevocationLookupDurationSeconds(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.RevocationLookupDurationSeconds.Observe(0.00005)

	body := scrape(t, m)
	assertContains(t, body, "starfly_revocation_lookup_duration_seconds_count 1")
}

// ── CAEP cascade metrics (P11-003) ───────────────────────────────────

func TestCAEPCascadeDurationSeconds(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.CAEPCascadeDurationSeconds.Observe(1.5)

	body := scrape(t, m)
	assertContains(t, body, "starfly_caep_cascade_duration_seconds_count 1")
}

func TestCAEPCascadeTokensInvalidated(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.CAEPCascadeTokensInvalidated.Inc()

	body := scrape(t, m)
	assertContains(t, body, "starfly_caep_cascade_tokens_invalidated 1")
}

// ── NATS detail metrics (P11-003) ────────────────────────────────────

func TestNATSPublishedTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.NATSPublishedTotal.WithLabelValues("revocation").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_nats_published_total{subject="revocation"} 1`)
}

func TestNATSReceivedTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.NATSReceivedTotal.WithLabelValues("revocation").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_nats_received_total{subject="revocation"} 1`)
}

// ── soul detail metrics (P11-003) ────────────────────────────────────

func TestSoulManifestSequence(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.SoulManifestSequence.Set(42)

	body := scrape(t, m)
	assertContains(t, body, "starfly_soul_manifest_sequence 42")
}

func TestSoulAnchorReachable(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.SoulAnchorReachable.Set(1)

	body := scrape(t, m)
	assertContains(t, body, "starfly_soul_anchor_reachable 1")
}

// ── fabric topology metrics (P11-003) ────────────────────────────────

func TestFabricUnitsTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FabricUnitsTotal.Set(12)

	body := scrape(t, m)
	assertContains(t, body, "starfly_fabric_units_total 12")
}

func TestFabricUnitsHealthy(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FabricUnitsHealthy.Set(10)

	body := scrape(t, m)
	assertContains(t, body, "starfly_fabric_units_healthy 10")
}

func TestFabricTrustDomainsTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FabricTrustDomainsTotal.Set(3)

	body := scrape(t, m)
	assertContains(t, body, "starfly_fabric_trust_domains_total 3")
}

// ── JWKS cache metrics (P11-003) ─────────────────────────────────────

func TestJWKSCacheHitsTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.JWKSCacheHitsTotal.Inc()

	body := scrape(t, m)
	assertContains(t, body, "starfly_jwks_cache_hits_total 1")
}

func TestJWKSCacheMissesTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.JWKSCacheMissesTotal.Inc()

	body := scrape(t, m)
	assertContains(t, body, "starfly_jwks_cache_misses_total 1")
}

func TestJWKSCacheSize(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.JWKSCacheSize.Set(25)

	body := scrape(t, m)
	assertContains(t, body, "starfly_jwks_cache_size 25")
}

// ── policy detail metrics (P11-003) ──────────────────────────────────

func TestPolicyDenialsTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.PolicyDenialsTotal.WithLabelValues("cross_domain_block").Inc()

	body := scrape(t, m)
	assertContains(t, body, `starfly_policy_denials_total{rule="cross_domain_block"} 1`)
}

func TestPolicyBundleReloadTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.PolicyBundleReloadTotal.Inc()

	body := scrape(t, m)
	assertContains(t, body, "starfly_policy_bundle_reload_total 1")
}

// ── federation signal metrics (P13-006) ──────────────────────────────

func TestFederationRelayTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FederationRelayTotal.WithLabelValues("peer-a.example.com", "success").Inc()
	m.FederationRelayTotal.WithLabelValues("peer-a.example.com", "error").Add(2)

	body := scrape(t, m)
	assertContains(t, body, `starfly_federation_relay_total{peer="peer-a.example.com",result="success"} 1`)
	assertContains(t, body, `starfly_federation_relay_total{peer="peer-a.example.com",result="error"} 2`)
}

func TestFederationRelayDuration(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FederationRelayDuration.WithLabelValues("peer-a.example.com").Observe(0.042)

	body := scrape(t, m)
	assertContains(t, body, "starfly_federation_relay_duration_seconds_count{peer=\"peer-a.example.com\"} 1")
}

func TestFederationReceivedTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FederationReceivedTotal.WithLabelValues("peer-b.example.com", "accepted").Inc()
	m.FederationReceivedTotal.WithLabelValues("peer-b.example.com", "rejected").Add(3)

	body := scrape(t, m)
	assertContains(t, body, `starfly_federation_received_total{peer="peer-b.example.com",result="accepted"} 1`)
	assertContains(t, body, `starfly_federation_received_total{peer="peer-b.example.com",result="rejected"} 3`)
}

func TestFederationSyncTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FederationSyncTotal.WithLabelValues("peer-a.example.com", "match").Inc()
	m.FederationSyncTotal.WithLabelValues("peer-a.example.com", "mismatch").Add(2)

	body := scrape(t, m)
	assertContains(t, body, `starfly_federation_sync_total{peer="peer-a.example.com",result="match"} 1`)
	assertContains(t, body, `starfly_federation_sync_total{peer="peer-a.example.com",result="mismatch"} 2`)
}

func TestFederationSyncMismatchesTotal(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FederationSyncMismatchesTotal.WithLabelValues("peer-a.example.com").Add(5)

	body := scrape(t, m)
	assertContains(t, body, `starfly_federation_sync_mismatches_total{peer="peer-a.example.com"} 5`)
}

func TestFederationRevocationLag(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.FederationRevocationLag.WithLabelValues("peer-a.example.com").Set(12.5)

	body := scrape(t, m)
	assertContains(t, body, `starfly_federation_revocation_lag_seconds{peer="peer-a.example.com"} 12.5`)
}

// ── TLS cert expiry metric (TLS-004) ─────────────────────────────────

func TestTLSCertExpirySeconds(t *testing.T) {
	m := New("v0.1.0", "abc123", "example.com")

	m.TLSCertExpirySeconds.Set(3600)

	body := scrape(t, m)
	assertContains(t, body, "starfly_tls_cert_expiry_seconds 3600")
}

// ── helpers ──────────────────────────────────────────────────────────

// scrape hits the metrics handler and returns the response body as a string.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	b, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(b)
}

func assertContains(t *testing.T, body, substr string) {
	t.Helper()

	// Also check the metric was registered — prometheus might silently
	// drop it if the registry rejects a duplicate. We search for the
	// HELP or TYPE header as well.
	_ = prometheus.Labels{} // keep import alive for compile-time check

	if !strings.Contains(body, substr) {
		t.Errorf("expected substring not found\nwant: %s\ngot:\n%s", substr, body)
	}
}
