// Package lifecycle provides Temporal-based credential lifecycle automation
// for Starfly Fabrics. It wraps the exchange engine, signal engine, and
// revocation index as Temporal activities, enabling durable workflows for
// key rotation, compliance scanning, and credential lifecycle management.
//
// The lifecycle worker is optional — Starfly runs without it when no
// Temporal server is configured. When enabled, it registers workflows
// and activities on a single task queue ("starfly-lifecycle").
package lifecycle

import "time"

// Task queue name for all lifecycle workflows.
const TaskQueue = "starfly-lifecycle"

// Lifecycle SSF event type URIs.
const (
	EventTypeRotationInitiated    = "https://schemas.openid.net/secevent/starfly/event-type/rotation-initiated"
	EventTypeRotationComplete     = "https://schemas.openid.net/secevent/starfly/event-type/rotation-complete"
	EventTypeRotationRollback     = "https://schemas.openid.net/secevent/starfly/event-type/rotation-rollback"
	EventTypeComplianceScanStart  = "https://schemas.openid.net/secevent/starfly/event-type/compliance-scan-started"
	EventTypeComplianceFinding    = "https://schemas.openid.net/secevent/starfly/event-type/compliance-finding"
	EventTypeComplianceScanDone   = "https://schemas.openid.net/secevent/starfly/event-type/compliance-scan-complete"
	EventTypeCredentialExpired    = "https://schemas.openid.net/secevent/starfly/event-type/credential-expired"
)

// LifecycleSignal is the payload for Temporal signals that trigger
// lifecycle actions (e.g., on-demand compliance scan).
type LifecycleSignal struct {
	// Action is the requested lifecycle action.
	Action string `json:"action"` // "scan", "rotate", "cancel"

	// Reason explains why the action was triggered.
	Reason string `json:"reason,omitempty"`

	// RequestedAt is when the signal was sent.
	RequestedAt time.Time `json:"requested_at"`
}

// RevokeRequest is the input to the RevokeCredential activity.
type RevokeRequest struct {
	SubjectID string `json:"subject_id"`
	Reason    string `json:"reason"`
	ExpiresIn time.Duration `json:"expires_in"`
}

// RevocationResult is the output of the CheckRevocationStatus activity.
type RevocationResult struct {
	Revoked   bool   `json:"revoked"`
	Reason    string `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}
