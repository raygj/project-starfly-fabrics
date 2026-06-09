package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleSignalMetrics = `# HELP starfly_federation_relay_total Total revocation signals relayed to federation peers.
# TYPE starfly_federation_relay_total counter
starfly_federation_relay_total{peer="prod-eu-west-1",result="ok"} 47
starfly_federation_relay_total{peer="prod-eu-west-1",result="error"} 0
starfly_federation_relay_total{peer="prod-ap-south-1",result="ok"} 31
starfly_federation_relay_total{peer="prod-ap-south-1",result="error"} 0
# HELP starfly_federation_received_total Total revocation signals received from federation peers.
# TYPE starfly_federation_received_total counter
starfly_federation_received_total{peer="prod-eu-west-1",result="ok"} 23
starfly_federation_received_total{peer="prod-ap-south-1",result="ok"} 18
# HELP starfly_federation_revocation_lag_seconds Seconds since last successful revocation relay to federation peer.
# TYPE starfly_federation_revocation_lag_seconds gauge
starfly_federation_revocation_lag_seconds{peer="prod-eu-west-1"} 1.2
starfly_federation_revocation_lag_seconds{peer="prod-ap-south-1"} 0.8
`

func TestParseSignalMetrics_Healthy(t *testing.T) {
	s, err := ParseSignalMetrics(strings.NewReader(sampleSignalMetrics))
	if err != nil {
		t.Fatalf("ParseSignalMetrics: %v", err)
	}

	if len(s.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(s.Peers))
	}

	// Sorted by fabric ID: prod-ap-south-1 comes first.
	ap := s.Peers[0]
	eu := s.Peers[1]

	if ap.FabricID != "prod-ap-south-1" {
		t.Errorf("first peer = %q, want prod-ap-south-1", ap.FabricID)
	}
	if eu.FabricID != "prod-eu-west-1" {
		t.Errorf("second peer = %q, want prod-eu-west-1", eu.FabricID)
	}

	if eu.RelayedTotal != 47 {
		t.Errorf("eu relayed = %v, want 47", eu.RelayedTotal)
	}
	if eu.ReceivedTotal != 23 {
		t.Errorf("eu received = %v, want 23", eu.ReceivedTotal)
	}
	if eu.LagSeconds != 1.2 {
		t.Errorf("eu lag = %v, want 1.2", eu.LagSeconds)
	}
	if eu.Transport != "https" {
		t.Errorf("eu transport = %q, want https", eu.Transport)
	}
	if eu.Status() != "healthy" {
		t.Errorf("eu status = %q, want healthy", eu.Status())
	}

	if ap.RelayedTotal != 31 {
		t.Errorf("ap relayed = %v, want 31", ap.RelayedTotal)
	}
	if ap.ReceivedTotal != 18 {
		t.Errorf("ap received = %v, want 18", ap.ReceivedTotal)
	}
	if ap.LagSeconds != 0.8 {
		t.Errorf("ap lag = %v, want 0.8", ap.LagSeconds)
	}
	if ap.Status() != "healthy" {
		t.Errorf("ap status = %q, want healthy", ap.Status())
	}
}

func TestParseSignalMetrics_Degraded(t *testing.T) {
	degraded := `starfly_federation_relay_total{peer="staging-1",result="ok"} 7
starfly_federation_relay_total{peer="staging-1",result="error"} 3
starfly_federation_received_total{peer="staging-1",result="ok"} 5
starfly_federation_revocation_lag_seconds{peer="staging-1"} 25.4
`
	s, err := ParseSignalMetrics(strings.NewReader(degraded))
	if err != nil {
		t.Fatalf("ParseSignalMetrics: %v", err)
	}

	if len(s.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(s.Peers))
	}

	p := s.Peers[0]
	if p.FabricID != "staging-1" {
		t.Errorf("fabric_id = %q, want staging-1", p.FabricID)
	}
	if p.Status() != "degraded" {
		t.Errorf("status = %q, want degraded", p.Status())
	}
	if p.Transport != "https" {
		t.Errorf("transport = %q, want https", p.Transport)
	}
	if p.ErrorTotal != 3 {
		t.Errorf("errors = %v, want 3", p.ErrorTotal)
	}
	if p.RelayedTotal != 7 {
		t.Errorf("relayed = %v, want 7", p.RelayedTotal)
	}
}

func TestParseSignalMetrics_Down(t *testing.T) {
	down := `starfly_federation_relay_total{peer="dead-peer",result="ok"} 50
starfly_federation_relay_total{peer="dead-peer",result="error"} 50
starfly_federation_received_total{peer="dead-peer",result="ok"} 0
starfly_federation_revocation_lag_seconds{peer="dead-peer"} 120.5
`
	s, err := ParseSignalMetrics(strings.NewReader(down))
	if err != nil {
		t.Fatalf("ParseSignalMetrics: %v", err)
	}

	if len(s.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(s.Peers))
	}

	p := s.Peers[0]
	if p.Status() != "down" {
		t.Errorf("status = %q, want down", p.Status())
	}
}

func TestParseSignalMetrics_Empty(t *testing.T) {
	s, err := ParseSignalMetrics(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseSignalMetrics: %v", err)
	}

	if len(s.Peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(s.Peers))
	}
}

func TestFormatSignalStatus_Healthy(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	s := &FederationSignalStatus{
		Peers: []*PeerSignalMetrics{
			{
				FabricID:      "prod-eu-west-1",
				Transport:     "https",
				RelayedTotal:  47,
				ReceivedTotal: 23,
				LagSeconds:    1.2,
				Reachable:     1,
			},
			{
				FabricID:      "prod-ap-south-1",
				Transport:     "https",
				RelayedTotal:  31,
				ReceivedTotal: 18,
				LagSeconds:    0.8,
				Reachable:     1,
			},
		},
	}

	out := FormatSignalStatus(s)

	expects := []string{
		"Federation Signal Gateway",
		"2 peers",
		"2 healthy",
		"prod-eu-west-1",
		"prod-ap-south-1",
		"relayed:",
		"received:",
		"lag:",
		"[OK] healthy",
	}

	for _, exp := range expects {
		if !strings.Contains(out, exp) {
			t.Errorf("output missing %q\ngot:\n%s", exp, out)
		}
	}
}

func TestFormatSignalStatus_Empty(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	out := FormatSignalStatus(&FederationSignalStatus{})
	if !strings.Contains(out, "No federation signal peers detected") {
		t.Errorf("empty output should indicate no peers, got:\n%s", out)
	}

	out = FormatSignalStatus(nil)
	if !strings.Contains(out, "No federation signal peers detected") {
		t.Errorf("nil output should indicate no peers, got:\n%s", out)
	}
}

func TestFormatSignalStatus_WithErrors(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	s := &FederationSignalStatus{
		Peers: []*PeerSignalMetrics{
			{
				FabricID:      "bad-peer",
				Transport:     "https",
				RelayedTotal:  10,
				ReceivedTotal: 0,
				ErrorTotal:    5,
				LagSeconds:    120,
				Reachable:     0,
			},
		},
	}

	out := FormatSignalStatus(s)

	if !strings.Contains(out, "1 down") {
		t.Errorf("output should show '1 down', got:\n%s", out)
	}
	if !strings.Contains(out, "errors: 5") {
		t.Errorf("output should show error count, got:\n%s", out)
	}
}

func TestFormatSignalStatusJSON_Valid(t *testing.T) {
	s := &FederationSignalStatus{
		Peers: []*PeerSignalMetrics{
			{
				FabricID:      "prod-eu-west-1",
				Transport:     "https",
				RelayedTotal:  47,
				ReceivedTotal: 23,
				LagSeconds:    1.2,
				Reachable:     1,
			},
		},
	}

	data, err := FormatSignalStatusJSON(s)
	if err != nil {
		t.Fatalf("FormatSignalStatusJSON: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("produced invalid JSON: %v\noutput: %s", err, string(data))
	}

	peers, ok := parsed["peers"].([]interface{})
	if !ok || len(peers) != 1 {
		t.Fatalf("expected 1 peer in JSON, got %v", parsed["peers"])
	}

	peer := peers[0].(map[string]interface{})
	if peer["fabric_id"] != "prod-eu-west-1" {
		t.Errorf("JSON fabric_id = %v, want prod-eu-west-1", peer["fabric_id"])
	}
	if peer["relayed_total"].(float64) != 47 {
		t.Errorf("JSON relayed_total = %v, want 47", peer["relayed_total"])
	}
}

func TestPeerSignalMetrics_Status(t *testing.T) {
	tests := []struct {
		name      string
		reachable float64
		lag       float64
		want      string
	}{
		{"healthy low lag", 1, 0.5, "healthy"},
		{"healthy at threshold", 1, 9.9, "healthy"},
		{"degraded by lag", 1, 15, "degraded"},
		{"degraded by reachable", 0.5, 1, "degraded"},
		{"down by reachable", 0, 1, "down"},
		{"down by high lag", 1, 61, "down"},
		{"down zero reachable high lag", 0, 120, "down"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &PeerSignalMetrics{
				Reachable:  tc.reachable,
				LagSeconds: tc.lag,
			}
			if got := p.Status(); got != tc.want {
				t.Errorf("Status() = %q, want %q", got, tc.want)
			}
		})
	}
}
