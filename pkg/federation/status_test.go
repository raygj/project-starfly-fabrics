package federation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFormatStatus_NilState(t *testing.T) {
	got := FormatStatus(nil)
	if got != "No federation peers configured.\n" {
		t.Errorf("FormatStatus(nil) = %q, want empty-peers message", got)
	}
}

func TestFormatStatus_NoPeers(t *testing.T) {
	got := FormatStatus(&FederationState{Peers: map[string]*PeerState{}})
	if got != "No federation peers configured.\n" {
		t.Errorf("FormatStatus(empty) = %q, want empty-peers message", got)
	}
}

func TestFormatStatus_WithPeers(t *testing.T) {
	now := time.Now()
	state := &FederationState{
		Peers: map[string]*PeerState{
			"fabric-eu": {
				Config:     PeerConfig{FabricID: "fabric-eu", JWKSEndpoint: "https://eu.example.com/.well-known/jwks.json"},
				Status:     PeerHealthy,
				LastSeen:   now.Add(-30 * time.Second),
				KeyCount:   3,
				FetchCount: 10,
				ErrorCount: 0,
			},
			"fabric-us": {
				Config:     PeerConfig{FabricID: "fabric-us", JWKSEndpoint: "https://us.example.com/.well-known/jwks.json"},
				Status:     PeerStale,
				LastSeen:   now.Add(-10 * time.Minute),
				KeyCount:   2,
				FetchCount: 5,
				ErrorCount: 3,
				LastError:  "connection refused",
			},
		},
	}

	got := FormatStatus(state)

	if !strings.Contains(got, "Federation Peers: 2 total") {
		t.Errorf("missing header line in output:\n%s", got)
	}
	if !strings.Contains(got, "[OK]") {
		t.Error("missing [OK] status icon for healthy peer")
	}
	if !strings.Contains(got, "[!!]") {
		t.Error("missing [!!] status icon for stale peer")
	}
	if !strings.Contains(got, "connection refused") {
		t.Error("missing last error for stale peer")
	}
	if !strings.Contains(got, "Last Seen:") {
		t.Error("missing Last Seen line")
	}
}

func TestFormatStatus_NeverSeenPeer(t *testing.T) {
	state := &FederationState{
		Peers: map[string]*PeerState{
			"fabric-new": {
				Config:   PeerConfig{FabricID: "fabric-new", JWKSEndpoint: "https://new.example.com/jwks"},
				Status:   PeerUnreachable,
				KeyCount: 0,
			},
		},
	}

	got := FormatStatus(state)
	if !strings.Contains(got, "Last Seen:  never") {
		t.Errorf("expected 'Last Seen:  never' for zero LastSeen, got:\n%s", got)
	}
	if !strings.Contains(got, "[XX]") {
		t.Error("missing [XX] status icon for unreachable peer")
	}
}

func TestFormatStatusJSON(t *testing.T) {
	state := &FederationState{
		Peers: map[string]*PeerState{
			"fabric-eu": {
				Config: PeerConfig{FabricID: "fabric-eu"},
				Status: PeerHealthy,
			},
		},
		UpdatedAt: time.Now(),
	}

	data, err := FormatStatusJSON(state)
	if err != nil {
		t.Fatalf("FormatStatusJSON error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestStatusIcon(t *testing.T) {
	tests := []struct {
		status PeerStatus
		want   string
	}{
		{PeerHealthy, "[OK]"},
		{PeerStale, "[!!]"},
		{PeerUnreachable, "[XX]"},
		{PeerStatus("unknown"), "[??]"},
	}
	for _, tc := range tests {
		got := statusIcon(tc.status)
		if got != tc.want {
			t.Errorf("statusIcon(%q) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "2m"},
		{2 * time.Hour, "2.0h"},
		{150 * time.Minute, "2.5h"},
	}
	for _, tc := range tests {
		got := formatDuration(tc.d)
		if got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
