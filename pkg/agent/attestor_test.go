package agent

import (
	"context"
	"encoding/json"
	"testing"
)

type mockAttestor struct {
	name      string
	available bool
	result    *AttestationResult
	err       error
}

func (m *mockAttestor) Name() string                                          { return m.name }
func (m *mockAttestor) Available(_ context.Context) bool                      { return m.available }
func (m *mockAttestor) Attest(_ context.Context) (*AttestationResult, error)  { return m.result, m.err }

func TestBundleAttestations(t *testing.T) {
	tests := []struct {
		name       string
		attestors  []Attestor
		wantErr    bool
		checkBundle func(t *testing.T, b *AttestationBundle)
	}{
		{
			name: "single platform attestor",
			attestors: []Attestor{
				&mockAttestor{
					name:      "k8s-sa",
					available: true,
					result: &AttestationResult{
						Source:     "k8s-sa",
						Credential: []byte("fake-sa-token"),
						CredType:   "urn:ietf:params:oauth:token-type:jwt",
						Metadata:   map[string]string{"namespace": "default", "pod_name": "my-pod"},
					},
				},
			},
			checkBundle: func(t *testing.T, b *AttestationBundle) {
				t.Helper()
				if b.Platform == nil {
					t.Fatal("expected platform attestation")
				}
				if b.Platform.Source != "k8s-sa" {
					t.Errorf("platform source = %q, want k8s-sa", b.Platform.Source)
				}
				if b.Workload.Namespace != "default" {
					t.Errorf("namespace = %q, want default", b.Workload.Namespace)
				}
				if b.Workload.PodName != "my-pod" {
					t.Errorf("pod_name = %q, want my-pod", b.Workload.PodName)
				}
				if b.Workload.PID == 0 {
					t.Error("expected non-zero PID")
				}
			},
		},
		{
			name: "skips unavailable attestors",
			attestors: []Attestor{
				&mockAttestor{name: "tpm2", available: false},
				&mockAttestor{
					name:      "k8s-sa",
					available: true,
					result: &AttestationResult{
						Source:     "k8s-sa",
						Credential: []byte("token"),
						CredType:   "urn:ietf:params:oauth:token-type:jwt",
					},
				},
			},
			checkBundle: func(t *testing.T, b *AttestationBundle) {
				t.Helper()
				if b.Platform.Source != "k8s-sa" {
					t.Errorf("platform source = %q, want k8s-sa", b.Platform.Source)
				}
				if len(b.Hardware) != 0 {
					t.Errorf("hardware attestations = %d, want 0", len(b.Hardware))
				}
			},
		},
		{
			name: "platform plus binary measurement",
			attestors: []Attestor{
				&mockAttestor{
					name:      "k8s-sa",
					available: true,
					result: &AttestationResult{
						Source:     "k8s-sa",
						Credential: []byte("token"),
						CredType:   "urn:ietf:params:oauth:token-type:jwt",
					},
				},
				&mockAttestor{
					name:      "binary-self",
					available: true,
					result: &AttestationResult{
						Source:   "binary-self",
						Metadata: map[string]string{"binary_hash": "sha256:abc123"},
					},
				},
			},
			checkBundle: func(t *testing.T, b *AttestationBundle) {
				t.Helper()
				if b.Workload.BinaryHash != "sha256:abc123" {
					t.Errorf("binary_hash = %q, want sha256:abc123", b.Workload.BinaryHash)
				}
			},
		},
		{
			name: "hardware attestor populates hardware slice",
			attestors: []Attestor{
				&mockAttestor{
					name:      "k8s-sa",
					available: true,
					result: &AttestationResult{
						Source:     "k8s-sa",
						Credential: []byte("token"),
						CredType:   "urn:ietf:params:oauth:token-type:jwt",
					},
				},
				&mockAttestor{
					name:      "tpm2",
					available: true,
					result: &AttestationResult{
						Source: "tpm2",
						Hardware: &HardwareProof{
							Type:  "tpm2",
							Quote: []byte("tpm-quote"),
							Nonce: []byte("nonce-1"),
						},
					},
				},
			},
			checkBundle: func(t *testing.T, b *AttestationBundle) {
				t.Helper()
				if len(b.Hardware) != 1 {
					t.Fatalf("hardware attestations = %d, want 1", len(b.Hardware))
				}
				if b.Hardware[0].Hardware.Type != "tpm2" {
					t.Errorf("hardware type = %q, want tpm2", b.Hardware[0].Hardware.Type)
				}
			},
		},
		{
			name: "no platform credential errors",
			attestors: []Attestor{
				&mockAttestor{
					name:      "binary-self",
					available: true,
					result: &AttestationResult{
						Source:   "binary-self",
						Metadata: map[string]string{"binary_hash": "sha256:abc"},
					},
				},
			},
			wantErr: true,
		},
		{
			name:      "empty attestors errors",
			attestors: []Attestor{},
			wantErr:   true,
		},
		{
			name: "all unavailable errors",
			attestors: []Attestor{
				&mockAttestor{name: "k8s-sa", available: false},
				&mockAttestor{name: "tpm2", available: false},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := BundleAttestations(context.Background(), tt.attestors, "test-v0.0.1")
			if (err != nil) != tt.wantErr {
				t.Fatalf("BundleAttestations() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if bundle.AgentVersion != "test-v0.0.1" {
				t.Errorf("agent_version = %q, want test-v0.0.1", bundle.AgentVersion)
			}
			if bundle.Timestamp.IsZero() {
				t.Error("expected non-zero timestamp")
			}
			if tt.checkBundle != nil {
				tt.checkBundle(t, bundle)
			}
		})
	}
}

func TestAttestationBundleJSON(t *testing.T) {
	bundle := &AttestationBundle{
		Platform: &AttestationResult{
			Source:     "k8s-sa",
			Credential: []byte("test-token"),
			CredType:   "urn:ietf:params:oauth:token-type:jwt",
			Metadata:   map[string]string{"namespace": "prod"},
		},
		Workload: &WorkloadMetadata{
			PID:        1234,
			BinaryHash: "sha256:deadbeef",
			Namespace:  "prod",
			PodName:    "my-pod-abc",
		},
		AgentVersion: "v0.1.0",
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded AttestationBundle
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Platform.Source != "k8s-sa" {
		t.Errorf("decoded platform source = %q, want k8s-sa", decoded.Platform.Source)
	}
	if decoded.Workload.BinaryHash != "sha256:deadbeef" {
		t.Errorf("decoded binary_hash = %q, want sha256:deadbeef", decoded.Workload.BinaryHash)
	}
	if decoded.AgentVersion != "v0.1.0" {
		t.Errorf("decoded agent_version = %q, want v0.1.0", decoded.AgentVersion)
	}
}
