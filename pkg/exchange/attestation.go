package exchange

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// AttestationHeaderName is the HTTP header carrying attestation metadata.
const AttestationHeaderName = "X-Starfly-Attestation"

// DefaultAttestationFreshnessWindow is the maximum age of an attestation
// timestamp before it is rejected as stale.
const DefaultAttestationFreshnessWindow = 5 * time.Minute

// ErrInvalidAttestation is returned when the attestation header is present
// but cannot be parsed.
var ErrInvalidAttestation = fmt.Errorf("invalid attestation header")

// ErrStaleAttestation is returned when the attestation timestamp is older
// than the configured freshness window.
var ErrStaleAttestation = fmt.Errorf("stale attestation")

// ParseAttestationHeader deserializes the X-Starfly-Attestation JSON header
// into a ServerAttestation. Returns nil if the header is empty (absent).
// Returns an error if the header is present but malformed.
func ParseAttestationHeader(header string) (*core.ServerAttestation, error) {
	if header == "" {
		return nil, nil
	}

	var att core.ServerAttestation
	if err := json.Unmarshal([]byte(header), &att); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAttestation, err)
	}

	// Platform source is required when attestation is present.
	if att.Platform.Source == "" {
		return nil, fmt.Errorf("%w: missing platform.source", ErrInvalidAttestation)
	}

	return &att, nil
}

// ValidateAttestation checks that a parsed attestation bundle meets
// server-side requirements: required fields present, timestamp fresh.
// The freshnessWindow parameter controls how old a timestamp can be;
// pass 0 to use DefaultAttestationFreshnessWindow.
func ValidateAttestation(att *core.ServerAttestation, freshnessWindow time.Duration) error {
	if att == nil {
		return nil
	}

	if freshnessWindow == 0 {
		freshnessWindow = DefaultAttestationFreshnessWindow
	}

	// Required fields.
	if att.Platform.Source == "" {
		return fmt.Errorf("%w: missing platform.source", ErrInvalidAttestation)
	}
	if att.Platform.CredType == "" {
		return fmt.Errorf("%w: missing platform.cred_type", ErrInvalidAttestation)
	}
	if att.AgentVersion == "" {
		return fmt.Errorf("%w: missing agent_version", ErrInvalidAttestation)
	}

	// Timestamp freshness.
	if att.Timestamp.IsZero() {
		return fmt.Errorf("%w: missing timestamp", ErrInvalidAttestation)
	}
	age := time.Since(att.Timestamp)
	if age > freshnessWindow {
		return fmt.Errorf("%w: timestamp age %s exceeds %s window", ErrStaleAttestation, age.Round(time.Second), freshnessWindow)
	}
	// Reject timestamps in the future (clock skew tolerance: 30s).
	if att.Timestamp.After(time.Now().Add(30 * time.Second)) {
		return fmt.Errorf("%w: timestamp is in the future", ErrInvalidAttestation)
	}

	return nil
}
