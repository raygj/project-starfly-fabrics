package agent

import (
	"context"
	"time"
)

// AttestationResult is one layer of proof from one attestor.
type AttestationResult struct {
	Source     string            `json:"source"`
	Credential []byte           `json:"credential,omitempty"`
	CredType   string           `json:"cred_type,omitempty"`
	Hardware   *HardwareProof   `json:"hardware,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// HardwareProof is attestation from silicon (TPM, GPU, enclave).
type HardwareProof struct {
	Type         string            `json:"type"`
	Quote        []byte            `json:"quote"`
	PCRs         map[int][]byte    `json:"pcrs,omitempty"`
	Firmware     string            `json:"firmware,omitempty"`
	Nonce        []byte            `json:"nonce"`
	Measurements map[string]string `json:"measurements,omitempty"`
}

// AttestationBundle is the complete attestation package sent to Starfly.
type AttestationBundle struct {
	Platform     *AttestationResult   `json:"platform"`
	Hardware     []*AttestationResult `json:"hardware,omitempty"`
	Workload     *WorkloadMetadata    `json:"workload"`
	AgentVersion string               `json:"agent_version"`
	Timestamp    time.Time            `json:"timestamp"`
}

// WorkloadMetadata describes the running process.
type WorkloadMetadata struct {
	PID         int               `json:"pid"`
	BinaryHash  string            `json:"binary_hash,omitempty"`
	ImageDigest string            `json:"image_digest,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	PodName     string            `json:"pod_name,omitempty"`
	NodeName    string            `json:"node_name,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// TokenServer makes the WIMSE JWT available to the workload.
type TokenServer interface {
	Start(ctx context.Context) error
	UpdateToken(token string) error
	Name() string
}

// ExchangeResult holds the response from a successful token exchange.
type ExchangeResult struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   int       `json:"expires_in"`
	IssuedAt    time.Time `json:"issued_at"`
}
