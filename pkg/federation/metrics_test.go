package federation

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func TestNewMetrics_RegistersCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	if m.PeerReachable == nil {
		t.Fatal("PeerReachable is nil")
	}
	if m.PeerJWKSAge == nil {
		t.Fatal("PeerJWKSAge is nil")
	}
	if m.PeerKeyCount == nil {
		t.Fatal("PeerKeyCount is nil")
	}
	if m.PeerFetchTotal == nil {
		t.Fatal("PeerFetchTotal is nil")
	}
	if m.PeerErrorTotal == nil {
		t.Fatal("PeerErrorTotal is nil")
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather error: %v", err)
	}
	if len(families) != 0 {
		t.Logf("gathered %d metric families before any writes (expected 0 or more)", len(families))
	}
}

func TestNewMetrics_NilRegisterer(t *testing.T) {
	m := NewMetrics(nil)
	if m == nil {
		t.Fatal("NewMetrics(nil) should return non-nil metrics")
	}
	if m.PeerReachable == nil {
		t.Error("PeerReachable should be initialized even with nil registerer")
	}
}

func gaugeValue(g prometheus.Gauge) float64 {
	m := &io_prometheus_client.Metric{}
	if err := g.Write(m); err != nil {
		return -1
	}
	return m.GetGauge().GetValue()
}

func TestMetrics_Update(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	now := time.Now()
	state := &FederationState{
		Peers: map[string]*PeerState{
			"fabric-healthy": {
				Config:   PeerConfig{FabricID: "fabric-healthy"},
				Status:   PeerHealthy,
				LastSeen: now.Add(-10 * time.Second),
				KeyCount: 5,
			},
			"fabric-stale": {
				Config:   PeerConfig{FabricID: "fabric-stale"},
				Status:   PeerStale,
				LastSeen: now.Add(-6 * time.Minute),
				KeyCount: 3,
			},
			"fabric-down": {
				Config:   PeerConfig{FabricID: "fabric-down"},
				Status:   PeerUnreachable,
				KeyCount: 0,
			},
		},
	}

	m.Update(state)

	if v := gaugeValue(m.PeerReachable.WithLabelValues("fabric-healthy")); v != 1 {
		t.Errorf("healthy peer reachable = %v, want 1", v)
	}
	if v := gaugeValue(m.PeerReachable.WithLabelValues("fabric-stale")); v != 0.5 {
		t.Errorf("stale peer reachable = %v, want 0.5", v)
	}
	if v := gaugeValue(m.PeerReachable.WithLabelValues("fabric-down")); v != 0 {
		t.Errorf("unreachable peer reachable = %v, want 0", v)
	}
	if v := gaugeValue(m.PeerKeyCount.WithLabelValues("fabric-healthy")); v != 5 {
		t.Errorf("healthy peer key count = %v, want 5", v)
	}
}
