// Package agent implements the starfly-agent client-side attestation pipeline.
//
// The agent discovers the workload's environment, gathers attestation signals
// from available trust layers, bundles them, and exchanges with the Starfly
// fabric server for a WIMSE JWT. See ADR-0013 for the full architecture.
package agent

import (
	"context"
	"fmt"
	"os"
	"time"
)

// Attestor gathers proof about the workload's environment.
// Each attestor handles one trust layer.
// The agent runs all available attestors and bundles the results.
//
// Implementations must be safe for concurrent use.
// Implementations must return quickly — attestation is in the boot path.
// If an attestor is unavailable, Available() returns false. No error.
type Attestor interface {
	Name() string
	Available(ctx context.Context) bool
	Attest(ctx context.Context) (*AttestationResult, error)
}

// ContinuousAttestor extends Attestor with periodic re-attestation.
// If re-attestation detects drift from the initial result, OnDrift
// determines whether the agent should re-exchange or self-revoke.
type ContinuousAttestor interface {
	Attestor
	Interval() time.Duration
	OnDrift(ctx context.Context, initial, current *AttestationResult) Action
}

// Action indicates what the agent should do when continuous attestation
// detects drift from the initial attestation state.
type Action int

const (
	ActionNone      Action = iota // No action needed.
	ActionReExchange              // Re-attest and re-exchange.
	ActionRevoke                  // Self-revoke and stop serving tokens.
)

// BundleAttestations runs all available attestors and assembles an
// AttestationBundle. Attestors where Available() returns false are skipped.
// At least one attestor must produce a result with a non-nil Credential
// to serve as the platform credential.
func BundleAttestations(ctx context.Context, attestors []Attestor, agentVersion string) (*AttestationBundle, error) {
	bundle := &AttestationBundle{
		Workload: &WorkloadMetadata{
			PID: os.Getpid(),
		},
		AgentVersion: agentVersion,
		Timestamp:    time.Now().UTC(),
	}

	for _, a := range attestors {
		if !a.Available(ctx) {
			continue
		}

		result, err := a.Attest(ctx)
		if err != nil {
			return nil, fmt.Errorf("attestor %s: %w", a.Name(), err)
		}

		if result.Hardware != nil {
			bundle.Hardware = append(bundle.Hardware, result)
			continue
		}

		if result.Credential != nil && bundle.Platform == nil {
			bundle.Platform = result
		}

		if hash, ok := result.Metadata["binary_hash"]; ok {
			bundle.Workload.BinaryHash = hash
		}
		if ns, ok := result.Metadata["namespace"]; ok {
			bundle.Workload.Namespace = ns
		}
		if pod, ok := result.Metadata["pod_name"]; ok {
			bundle.Workload.PodName = pod
		}
		if node, ok := result.Metadata["node_name"]; ok {
			bundle.Workload.NodeName = node
		}
		if img, ok := result.Metadata["image_digest"]; ok {
			bundle.Workload.ImageDigest = img
		}
	}

	if bundle.Platform == nil {
		return nil, fmt.Errorf("no platform credential available: all attestors either unavailable or returned no credential")
	}

	return bundle, nil
}
