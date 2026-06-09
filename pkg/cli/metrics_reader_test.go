package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleMetrics = `# HELP starfly_unit_info Static metadata about this Starfly unit.
# TYPE starfly_unit_info gauge
starfly_unit_info{version="0.4.0",unit_id="starfly-0",trust_domain="prod-us-east-1"} 1
# HELP starfly_fabric_units_total Total units in fabric.
# TYPE starfly_fabric_units_total gauge
starfly_fabric_units_total 5
# HELP starfly_fabric_units_healthy Healthy units in fabric.
# TYPE starfly_fabric_units_healthy gauge
starfly_fabric_units_healthy 5
# HELP starfly_exchange_requests_total Total number of token exchange requests.
# TYPE starfly_exchange_requests_total counter
starfly_exchange_requests_total{status="success",source_type="k8s-sa",target_domain="prod"} 2847
# HELP starfly_revocation_index_size Current number of entries in the revocation index.
# TYPE starfly_revocation_index_size gauge
starfly_revocation_index_size 147
# HELP starfly_soul_manifest_sequence Current manifest sequence number.
# TYPE starfly_soul_manifest_sequence gauge
starfly_soul_manifest_sequence 47
# HELP starfly_soul_anchor_age_seconds Seconds since the last successful soul snapshot.
# TYPE starfly_soul_anchor_age_seconds gauge
starfly_soul_anchor_age_seconds 8
# HELP starfly_fabric_trust_domains_total Number of trust domains.
# TYPE starfly_fabric_trust_domains_total gauge
starfly_fabric_trust_domains_total 3
`

func TestParseMetrics_AllHealthy(t *testing.T) {
	s, err := ParseMetrics(strings.NewReader(sampleMetrics))
	if err != nil {
		t.Fatalf("ParseMetrics: %v", err)
	}

	if s.FabricID != "prod-us-east-1" {
		t.Errorf("FabricID = %q, want %q", s.FabricID, "prod-us-east-1")
	}
	if s.UnitsTotal != 5 {
		t.Errorf("UnitsTotal = %d, want 5", s.UnitsTotal)
	}
	if s.UnitsHealthy != 5 {
		t.Errorf("UnitsHealthy = %d, want 5", s.UnitsHealthy)
	}
	if s.ExchangeRate != 2847 {
		t.Errorf("ExchangeRate = %f, want 2847", s.ExchangeRate)
	}
	if s.RevocationsActive != 147 {
		t.Errorf("RevocationsActive = %d, want 147", s.RevocationsActive)
	}
	if s.SoulSequence != 47 {
		t.Errorf("SoulSequence = %d, want 47", s.SoulSequence)
	}
	if s.SoulAge != 8*time.Second {
		t.Errorf("SoulAge = %v, want 8s", s.SoulAge)
	}
	if s.TrustDomains != 3 {
		t.Errorf("TrustDomains = %d, want 3", s.TrustDomains)
	}
}

func TestParseMetrics_Degraded(t *testing.T) {
	degraded := `# TYPE starfly_unit_info gauge
starfly_unit_info{version="0.4.0",unit_id="starfly-0",trust_domain="staging"} 1
starfly_fabric_units_total 3
starfly_fabric_units_healthy 1
starfly_revocation_index_size 0
starfly_soul_manifest_sequence 2
starfly_soul_anchor_age_seconds 3600
starfly_fabric_trust_domains_total 1
`

	s, err := ParseMetrics(strings.NewReader(degraded))
	if err != nil {
		t.Fatalf("ParseMetrics: %v", err)
	}

	if s.FabricID != "staging" {
		t.Errorf("FabricID = %q, want %q", s.FabricID, "staging")
	}
	if s.UnitsTotal != 3 {
		t.Errorf("UnitsTotal = %d, want 3", s.UnitsTotal)
	}
	if s.UnitsHealthy != 1 {
		t.Errorf("UnitsHealthy = %d, want 1", s.UnitsHealthy)
	}
	if s.SoulAge != time.Hour {
		t.Errorf("SoulAge = %v, want 1h", s.SoulAge)
	}
}

func TestFormatStatus_AllHealthy(t *testing.T) {
	// Set NO_COLOR to get predictable output without ANSI codes.
	t.Setenv("NO_COLOR", "1")

	s := &FabricStatus{
		FabricID:         "prod-us-east-1",
		UnitsTotal:       5,
		UnitsHealthy:     5,
		ExchangeRate:     2847,
		ExchangeP99:      1.4,
		RevocationsActive: 147,
		SoulSequence:     47,
		SoulAge:          8 * time.Second,
		TrustDomains:     3,
	}

	out := FormatStatus(s)

	expects := []string{
		"Fabric: prod-us-east-1 (5 units, all healthy)",
		"Exchanges: 2,847/min (p99: 1.4ms)",
		"Revocations: 147 active",
		"Soul: seq 47, 8s ago",
		"Trust domains: 3",
	}

	for _, exp := range expects {
		if !strings.Contains(out, exp) {
			t.Errorf("FormatStatus output missing %q\ngot:\n%s", exp, out)
		}
	}
}

func TestFormatStatus_Degraded(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	s := &FabricStatus{
		FabricID:         "staging",
		UnitsTotal:       3,
		UnitsHealthy:     1,
		ExchangeRate:     42,
		RevocationsActive: 0,
		SoulSequence:     2,
		SoulAge:          time.Hour,
		TrustDomains:     1,
	}

	out := FormatStatus(s)

	if !strings.Contains(out, "1/3 healthy") {
		t.Errorf("degraded output should show '1/3 healthy', got:\n%s", out)
	}
	if !strings.Contains(out, "Revocations: 0 active") {
		t.Errorf("degraded output should show '0 active' revocations, got:\n%s", out)
	}
	if !strings.Contains(out, "1h ago") {
		t.Errorf("degraded output should show '1h ago' soul age, got:\n%s", out)
	}
}

func TestFormatStatusJSON_Valid(t *testing.T) {
	s := &FabricStatus{
		FabricID:         "prod-us-east-1",
		UnitsTotal:       5,
		UnitsHealthy:     5,
		ExchangeRate:     2847,
		ExchangeP99:      1.4,
		RevocationsActive: 147,
		SoulSequence:     47,
		SoulAge:          8 * time.Second,
		TrustDomains:     3,
	}

	data, err := FormatStatusJSON(s)
	if err != nil {
		t.Fatalf("FormatStatusJSON: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("FormatStatusJSON produced invalid JSON: %v\noutput: %s", err, string(data))
	}

	if parsed["fabric_id"] != "prod-us-east-1" {
		t.Errorf("JSON fabric_id = %v, want prod-us-east-1", parsed["fabric_id"])
	}
	if parsed["units_total"].(float64) != 5 {
		t.Errorf("JSON units_total = %v, want 5", parsed["units_total"])
	}
	if parsed["soul_sequence"].(float64) != 47 {
		t.Errorf("JSON soul_sequence = %v, want 47", parsed["soul_sequence"])
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{2847, "2,847"},
		{1234567, "1,234,567"},
	}
	for _, tc := range tests {
		got := formatNumber(tc.input)
		if got != tc.want {
			t.Errorf("formatNumber(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReadMetrics_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	s, err := ReadMetrics(srv.URL)
	if err != nil {
		t.Fatalf("ReadMetrics: %v", err)
	}
	if s.FabricID != "prod-us-east-1" {
		t.Errorf("FabricID = %q, want prod-us-east-1", s.FabricID)
	}
}

func TestReadMetrics_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := ReadMetrics(srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestReadMetrics_ConnectionError(t *testing.T) {
	_, err := ReadMetrics("http://127.0.0.1:1/metrics")
	if err == nil {
		t.Fatal("expected error for unreachable endpoint")
	}
}

func TestReadSignalMetrics_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(sampleSignalMetrics))
	}))
	defer srv.Close()

	s, err := ReadSignalMetrics(srv.URL)
	if err != nil {
		t.Fatalf("ReadSignalMetrics: %v", err)
	}
	if len(s.Peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(s.Peers))
	}
}

func TestReadSignalMetrics_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := ReadSignalMetrics(srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 403")
	}
}

func TestHealthSummary_NoUnits(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := healthSummary(0, 0)
	if got != "no units" {
		t.Errorf("healthSummary(0,0) = %q, want 'no units'", got)
	}
}

func TestFormatLag_Positive(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := formatLag(3.5, ColorGreen)
	if got != "3.5s" {
		t.Errorf("formatLag(3.5) = %q, want '3.5s'", got)
	}
}

func TestFormatLag_Zero(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := formatLag(0, ColorGreen)
	if got != "n/a" {
		t.Errorf("formatLag(0) = %q, want 'n/a'", got)
	}
}

func TestFormatStatus_NoFabricID(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	s := &FabricStatus{UnitsTotal: 0}
	out := FormatStatus(s)
	if !strings.Contains(out, "(unknown)") {
		t.Errorf("expected (unknown) for missing fabricID, got:\n%s", out)
	}
}

func TestSplitMetricLine_SingleToken(t *testing.T) {
	name, value := splitMetricLine("single")
	if name != "" || value != "" {
		t.Errorf("expected empty for single-token line, got name=%q value=%q", name, value)
	}
}

func TestExtractLabel(t *testing.T) {
	line := `starfly_unit_info{version="0.4.0",unit_id="starfly-0",trust_domain="prod-us-east-1"} 1`

	got := extractLabel(line, "trust_domain")
	if got != "prod-us-east-1" {
		t.Errorf("extractLabel(trust_domain) = %q, want %q", got, "prod-us-east-1")
	}

	got = extractLabel(line, "version")
	if got != "0.4.0" {
		t.Errorf("extractLabel(version) = %q, want %q", got, "0.4.0")
	}

	got = extractLabel(line, "missing")
	if got != "" {
		t.Errorf("extractLabel(missing) = %q, want empty", got)
	}
}
