package federation

import (
	"testing"
	"time"
)

func TestPeerConfig_ApplyDefaults(t *testing.T) {
	pc := PeerConfig{FabricID: "test"}
	pc.ApplyDefaults()

	if pc.RefreshInterval != DefaultRefreshInterval {
		t.Errorf("RefreshInterval = %v, want %v", pc.RefreshInterval, DefaultRefreshInterval)
	}
	if pc.StalenessThreshold != DefaultStalenessThreshold {
		t.Errorf("StalenessThreshold = %v, want %v", pc.StalenessThreshold, DefaultStalenessThreshold)
	}
}

func TestPeerConfig_ApplyDefaults_PreservesExplicit(t *testing.T) {
	pc := PeerConfig{
		FabricID:           "test",
		RefreshInterval:    30 * time.Second,
		StalenessThreshold: 10 * time.Minute,
	}
	pc.ApplyDefaults()

	if pc.RefreshInterval != 30*time.Second {
		t.Errorf("RefreshInterval changed to %v, should preserve 30s", pc.RefreshInterval)
	}
	if pc.StalenessThreshold != 10*time.Minute {
		t.Errorf("StalenessThreshold changed to %v, should preserve 10m", pc.StalenessThreshold)
	}
}

func TestPeerState_IsHealthy(t *testing.T) {
	tests := []struct {
		status PeerStatus
		want   bool
	}{
		{PeerHealthy, true},
		{PeerStale, false},
		{PeerUnreachable, false},
	}
	for _, tt := range tests {
		ps := PeerState{Status: tt.status}
		if got := ps.IsHealthy(); got != tt.want {
			t.Errorf("IsHealthy() for status %q = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestPeerState_Age(t *testing.T) {
	ps := PeerState{LastSeen: time.Now().Add(-2 * time.Minute)}
	age := ps.Age()
	if age < 1*time.Minute || age > 3*time.Minute {
		t.Errorf("Age() = %v, expected ~2m", age)
	}
}

func TestPeerState_Age_Zero(t *testing.T) {
	ps := PeerState{}
	if ps.Age() != 0 {
		t.Errorf("Age() for zero LastSeen should be 0, got %v", ps.Age())
	}
}

func TestFederationState_Counts(t *testing.T) {
	fs := &FederationState{
		Peers: map[string]*PeerState{
			"a": {Status: PeerHealthy},
			"b": {Status: PeerHealthy},
			"c": {Status: PeerStale},
			"d": {Status: PeerUnreachable},
		},
	}

	if fs.PeerCount() != 4 {
		t.Errorf("PeerCount() = %d, want 4", fs.PeerCount())
	}
	if fs.HealthyCount() != 2 {
		t.Errorf("HealthyCount() = %d, want 2", fs.HealthyCount())
	}
	if fs.StaleCount() != 1 {
		t.Errorf("StaleCount() = %d, want 1", fs.StaleCount())
	}
	if fs.UnreachableCount() != 1 {
		t.Errorf("UnreachableCount() = %d, want 1", fs.UnreachableCount())
	}
}

func TestFederationState_Empty(t *testing.T) {
	fs := &FederationState{Peers: map[string]*PeerState{}}
	if fs.PeerCount() != 0 {
		t.Errorf("PeerCount() = %d for empty, want 0", fs.PeerCount())
	}
	if fs.HealthyCount() != 0 {
		t.Errorf("HealthyCount() = %d for empty, want 0", fs.HealthyCount())
	}
}
