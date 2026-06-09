package federation

import (
	"testing"
	"time"
)

func TestRevocationSignalConstruction(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(1 * time.Hour)

	sig := RevocationSignal{
		SubjectID:    "spiffe://example.com/workload/api-server",
		Reason:       "session-revoked",
		RevokedAt:    now,
		ExpiresAt:    expires,
		EventJTI:     "evt-abc-123",
		SourceFabric: "fabric-us-east-1",
		TrustDomain:  "example.com",
	}

	if sig.SubjectID != "spiffe://example.com/workload/api-server" {
		t.Errorf("SubjectID = %q, want spiffe://example.com/workload/api-server", sig.SubjectID)
	}
	if sig.Reason != "session-revoked" {
		t.Errorf("Reason = %q, want session-revoked", sig.Reason)
	}
	if !sig.RevokedAt.Equal(now) {
		t.Errorf("RevokedAt = %v, want %v", sig.RevokedAt, now)
	}
	if !sig.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", sig.ExpiresAt, expires)
	}
	if sig.EventJTI != "evt-abc-123" {
		t.Errorf("EventJTI = %q, want evt-abc-123", sig.EventJTI)
	}
	if sig.SourceFabric != "fabric-us-east-1" {
		t.Errorf("SourceFabric = %q, want fabric-us-east-1", sig.SourceFabric)
	}
	if sig.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want example.com", sig.TrustDomain)
	}
}

func TestGatewayStateHealthyCount(t *testing.T) {
	gs := GatewayState{
		Peers: map[string]*PeerSignalState{
			"fabric-a": {FabricID: "fabric-a", Status: SignalHealthy},
			"fabric-b": {FabricID: "fabric-b", Status: SignalDegraded},
			"fabric-c": {FabricID: "fabric-c", Status: SignalHealthy},
			"fabric-d": {FabricID: "fabric-d", Status: SignalDown},
		},
	}

	if got := gs.HealthyCount(); got != 2 {
		t.Errorf("HealthyCount() = %d, want 2", got)
	}
}

func TestGatewayStateDegradedCount(t *testing.T) {
	gs := GatewayState{
		Peers: map[string]*PeerSignalState{
			"fabric-a": {FabricID: "fabric-a", Status: SignalHealthy},
			"fabric-b": {FabricID: "fabric-b", Status: SignalDegraded},
			"fabric-c": {FabricID: "fabric-c", Status: SignalDegraded},
			"fabric-d": {FabricID: "fabric-d", Status: SignalDown},
		},
	}

	if got := gs.DegradedCount(); got != 2 {
		t.Errorf("DegradedCount() = %d, want 2", got)
	}
}

func TestGatewayStateDownCount(t *testing.T) {
	gs := GatewayState{
		Peers: map[string]*PeerSignalState{
			"fabric-a": {FabricID: "fabric-a", Status: SignalHealthy},
			"fabric-b": {FabricID: "fabric-b", Status: SignalDown},
			"fabric-c": {FabricID: "fabric-c", Status: SignalDown},
			"fabric-d": {FabricID: "fabric-d", Status: SignalDown},
		},
	}

	if got := gs.DownCount(); got != 3 {
		t.Errorf("DownCount() = %d, want 3", got)
	}
}

func TestPeerSignalConfigDefaults(t *testing.T) {
	psc := PeerSignalConfig{
		FabricID: "fabric-peer",
		Endpoint: "https://peer.example.com/v1/signals/events",
	}

	psc.ApplyDefaults()

	if psc.Transport != "https" {
		t.Errorf("Transport = %q, want https", psc.Transport)
	}
	if psc.RelayTimeout != 2*time.Second {
		t.Errorf("RelayTimeout = %v, want 2s", psc.RelayTimeout)
	}
	if psc.SyncInterval != 30*time.Second {
		t.Errorf("SyncInterval = %v, want 30s", psc.SyncInterval)
	}
}

func TestPeerSignalConfigDefaultsPreserveExplicit(t *testing.T) {
	psc := PeerSignalConfig{
		FabricID:     "fabric-peer",
		Endpoint:     "https://peer.example.com/v1/signals/events",
		Transport:    "nats",
		RelayTimeout: 5 * time.Second,
		SyncInterval: 1 * time.Minute,
	}

	psc.ApplyDefaults()

	if psc.Transport != "nats" {
		t.Errorf("Transport = %q, want nats (explicit value should be preserved)", psc.Transport)
	}
	if psc.RelayTimeout != 5*time.Second {
		t.Errorf("RelayTimeout = %v, want 5s (explicit value should be preserved)", psc.RelayTimeout)
	}
	if psc.SyncInterval != 1*time.Minute {
		t.Errorf("SyncInterval = %v, want 1m (explicit value should be preserved)", psc.SyncInterval)
	}
}

func TestValidateSignalGatewayConfigRejectsEmptyFabricID(t *testing.T) {
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{
				FabricID: "",
				Endpoint: "https://peer.example.com/v1/signals/events",
			},
		},
	}

	err := ValidateSignalGatewayConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty fabricId, got nil")
	}
	if got := err.Error(); got != "peers[0]: fabricId is required" {
		t.Errorf("error = %q, want peers[0]: fabricId is required", got)
	}
}

func TestValidateSignalGatewayConfigRejectsEmptyEndpoint(t *testing.T) {
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{
				FabricID: "fabric-peer",
				Endpoint: "",
			},
		},
	}

	err := ValidateSignalGatewayConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty endpoint, got nil")
	}
	if got := err.Error(); got != "peers[0] (fabric-peer): endpoint is required" {
		t.Errorf("error = %q, want peers[0] (fabric-peer): endpoint is required", got)
	}
}

func TestValidateSignalGatewayConfigRejectsInvalidTransport(t *testing.T) {
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{
				FabricID:  "fabric-peer",
				Endpoint:  "https://peer.example.com/v1/signals/events",
				Transport: "grpc",
			},
		},
	}

	err := ValidateSignalGatewayConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid transport, got nil")
	}
}

func TestValidateSignalGatewayConfigAcceptsValid(t *testing.T) {
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{
				FabricID:     "fabric-us-east",
				Endpoint:     "https://east.example.com/v1/signals/events",
				Transport:    "https",
				RelayTimeout: 3 * time.Second,
				SyncInterval: 15 * time.Second,
				MTLSSecret:   "east-mtls-cert",
			},
		},
	}

	if err := ValidateSignalGatewayConfig(cfg); err != nil {
		t.Errorf("expected nil error for valid config, got %v", err)
	}
}

func TestValidateSignalGatewayConfigRejectsNATS(t *testing.T) {
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{
				FabricID:  "fabric-eu-west",
				Endpoint:  "nats://eu.example.com:4222",
				Transport: "nats",
			},
		},
	}

	err := ValidateSignalGatewayConfig(cfg)
	if err == nil {
		t.Fatal("expected error for nats transport, got nil")
	}
	if got := err.Error(); got != "peers[0] (fabric-eu-west): transport \"nats\" not yet implemented" {
		t.Errorf("error = %q, want nats not yet implemented message", got)
	}
}

func TestValidateSignalGatewayConfigAcceptsEmpty(t *testing.T) {
	cfg := SignalGatewayConfig{}

	if err := ValidateSignalGatewayConfig(cfg); err != nil {
		t.Errorf("expected nil error for empty config (no peers), got %v", err)
	}
}

func TestValidateSignalGatewayConfigRejectsDuplicateFabricID(t *testing.T) {
	cfg := SignalGatewayConfig{
		Peers: []PeerSignalConfig{
			{FabricID: "fabric-east", Endpoint: "https://east.example.com/v1/signals/events"},
			{FabricID: "fabric-west", Endpoint: "https://west.example.com/v1/signals/events"},
			{FabricID: "fabric-east", Endpoint: "https://east2.example.com/v1/signals/events"},
		},
	}

	err := ValidateSignalGatewayConfig(cfg)
	if err == nil {
		t.Fatal("expected error for duplicate fabricId, got nil")
	}
	wantSubstr := "duplicate fabricId"
	if got := err.Error(); !containsSubstring(got, wantSubstr) {
		t.Errorf("error = %q, want substring %q", got, wantSubstr)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestZeroValueGatewayStateNoPanic(t *testing.T) {
	var gs GatewayState

	// All methods should return 0 without panicking on nil map.
	if got := gs.HealthyCount(); got != 0 {
		t.Errorf("HealthyCount() on zero-value = %d, want 0", got)
	}
	if got := gs.DegradedCount(); got != 0 {
		t.Errorf("DegradedCount() on zero-value = %d, want 0", got)
	}
	if got := gs.DownCount(); got != 0 {
		t.Errorf("DownCount() on zero-value = %d, want 0", got)
	}
}
