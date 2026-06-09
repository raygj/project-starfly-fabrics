package exchange

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

func TestParseAttestationHeader_Empty(t *testing.T) {
	att, err := ParseAttestationHeader("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if att != nil {
		t.Fatal("expected nil for empty header")
	}
}

func TestParseAttestationHeader_Valid(t *testing.T) {
	header := buildTestAttestHeader(t, "k8s-sa", "urn:ietf:params:oauth:token-type:jwt", "sha256:abc123")

	att, err := ParseAttestationHeader(header)
	if err != nil {
		t.Fatalf("ParseAttestationHeader: %v", err)
	}

	if att.Platform.Source != "k8s-sa" {
		t.Errorf("platform.source = %q, want k8s-sa", att.Platform.Source)
	}
	if att.Platform.CredType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Errorf("platform.cred_type = %q", att.Platform.CredType)
	}
	if att.Workload == nil {
		t.Fatal("expected workload metadata")
	}
	if att.Workload.BinaryHash != "sha256:abc123" {
		t.Errorf("workload.binary_hash = %q", att.Workload.BinaryHash)
	}
	if att.AgentVersion != "v0.1.0" {
		t.Errorf("agent_version = %q", att.AgentVersion)
	}
	if att.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestParseAttestationHeader_MalformedJSON(t *testing.T) {
	_, err := ParseAttestationHeader("{not-json")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseAttestationHeader_MissingPlatformSource(t *testing.T) {
	header := `{"platform":{"source":"","cred_type":"jwt"},"agent_version":"v0.1.0","timestamp":"2026-03-20T00:00:00Z"}`
	_, err := ParseAttestationHeader(header)
	if err == nil {
		t.Fatal("expected error for missing platform.source")
	}
}

func TestParseAttestationHeader_WithHardware(t *testing.T) {
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		Hardware: []*core.ServerAttestHardware{
			{
				Type:  "tpm2",
				Quote: []byte("tpm-quote-data"),
				Nonce: []byte("nonce-1"),
			},
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}
	data, _ := json.Marshal(att)

	parsed, err := ParseAttestationHeader(string(data))
	if err != nil {
		t.Fatalf("ParseAttestationHeader: %v", err)
	}
	if len(parsed.Hardware) != 1 {
		t.Fatalf("hardware count = %d, want 1", len(parsed.Hardware))
	}
	if parsed.Hardware[0].Type != "tpm2" {
		t.Errorf("hardware type = %q, want tpm2", parsed.Hardware[0].Type)
	}
}

func TestServerAttestation_AssuranceLevel(t *testing.T) {
	tests := []struct {
		name string
		att  *core.ServerAttestation
		want string
	}{
		{
			name: "nil attestation",
			att:  nil,
			want: "none",
		},
		{
			name: "software only",
			att: &core.ServerAttestation{
				Platform: core.ServerAttestPlatform{Source: "k8s-sa"},
			},
			want: "software",
		},
		{
			name: "with hardware",
			att: &core.ServerAttestation{
				Platform: core.ServerAttestPlatform{Source: "k8s-sa"},
				Hardware: []*core.ServerAttestHardware{
					{Type: "tpm2", Quote: []byte("q"), Nonce: []byte("n")},
				},
			},
			want: "hardware",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.att.AssuranceLevel()
			if got != tt.want {
				t.Errorf("AssuranceLevel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateAttestation_Nil(t *testing.T) {
	if err := ValidateAttestation(nil, 0); err != nil {
		t.Fatalf("unexpected error for nil: %v", err)
	}
}

func TestValidateAttestation_Valid(t *testing.T) {
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}
	if err := ValidateAttestation(att, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAttestation_MissingPlatformSource(t *testing.T) {
	att := &core.ServerAttestation{
		Platform:     core.ServerAttestPlatform{CredType: "jwt"},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}
	err := ValidateAttestation(att, 0)
	if err == nil {
		t.Fatal("expected error for missing platform.source")
	}
}

func TestValidateAttestation_MissingCredType(t *testing.T) {
	att := &core.ServerAttestation{
		Platform:     core.ServerAttestPlatform{Source: "k8s-sa"},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}
	if err := ValidateAttestation(att, 0); err == nil {
		t.Fatal("expected error for missing cred_type")
	}
}

func TestValidateAttestation_MissingAgentVersion(t *testing.T) {
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		Timestamp: time.Now().UTC(),
	}
	if err := ValidateAttestation(att, 0); err == nil {
		t.Fatal("expected error for missing agent_version")
	}
}

func TestValidateAttestation_MissingTimestamp(t *testing.T) {
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		AgentVersion: "v0.1.0",
	}
	if err := ValidateAttestation(att, 0); err == nil {
		t.Fatal("expected error for missing timestamp")
	}
}

func TestValidateAttestation_StaleTimestamp(t *testing.T) {
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().Add(-10 * time.Minute),
	}
	if err := ValidateAttestation(att, 5*time.Minute); err == nil {
		t.Fatal("expected error for stale timestamp")
	}
}

func TestValidateAttestation_FutureTimestamp(t *testing.T) {
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().Add(5 * time.Minute),
	}
	if err := ValidateAttestation(att, 0); err == nil {
		t.Fatal("expected error for future timestamp")
	}
}

func TestValidateAttestation_CustomFreshnessWindow(t *testing.T) {
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   "k8s-sa",
			CredType: "urn:ietf:params:oauth:token-type:jwt",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().Add(-3 * time.Minute),
	}
	// With 2 minute window, should fail.
	if err := ValidateAttestation(att, 2*time.Minute); err == nil {
		t.Fatal("expected error with 2m window")
	}
	// With 5 minute window, should pass.
	if err := ValidateAttestation(att, 5*time.Minute); err != nil {
		t.Fatalf("unexpected error with 5m window: %v", err)
	}
}

// buildTestAttestHeader creates a valid X-Starfly-Attestation JSON string.
func buildTestAttestHeader(t *testing.T, source, credType, binaryHash string) string {
	t.Helper()
	att := &core.ServerAttestation{
		Platform: core.ServerAttestPlatform{
			Source:   source,
			CredType: credType,
			Metadata: map[string]string{"namespace": "default"},
		},
		Workload: &core.ServerAttestWorkload{
			PID:        1234,
			BinaryHash: binaryHash,
			Namespace:  "default",
			PodName:    "my-pod",
		},
		AgentVersion: "v0.1.0",
		Timestamp:    time.Now().UTC(),
	}
	data, err := json.Marshal(att)
	if err != nil {
		t.Fatalf("marshaling test attestation: %v", err)
	}
	return string(data)
}
