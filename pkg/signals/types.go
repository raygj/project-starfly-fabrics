package signals

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/starfly-fabrics/starfly/pkg/core"
)

// ─────────────────────────────────────────────────────────────────────
// SSF EVENT TYPES
// Standard CAEP/RISC event URIs per OpenID SSF 1.0 Final Spec.
// ─────────────────────────────────────────────────────────────────────

// CAEP event type URIs.
const (
	EventCredentialChange       = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	EventSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventTokenClaimsChange      = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
)

// RISC event type URIs.
const (
	EventAccountDisabled      = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventAccountEnabled       = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	EventAccountCredChange    = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
	EventIdentifierChanged    = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
	EventIdentifierRecycled   = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
	EventAccountPurged        = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	EventOptIn                = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
	EventOptOutInitiated      = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
	EventOptOutCancelled      = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
	EventOptOutEffective      = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"
	EventRecoveryActivated    = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
	EventRecoveryInfoChanged  = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"
	EventSessionsRevoked      = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
)

// Starfly-specific event type URIs (extensions to SSF).
const (
	EventTokenRevoked    = "https://starfly.dev/secevent/event-type/token-revoked"
	EventPolicyViolation = "https://starfly.dev/secevent/event-type/policy-violation"
)

// MCP-specific CAEP event type URIs.
// These extend the signal fabric to cover MCP tool lifecycle events,
// enabling revocation cascades when MCP infrastructure changes.
const (
	// EventMCPToolCompromised fires when an MCP tool is identified as compromised.
	// Action: revoke all tokens scoped to this tool's resource URI.
	EventMCPToolCompromised = "https://starfly.dev/secevent/event-type/mcp-tool-compromised"

	// EventMCPServerDeregistered fires when an MCP server is removed.
	// Action: revoke all tokens for tools hosted on this server and alert operators.
	EventMCPServerDeregistered = "https://starfly.dev/secevent/event-type/mcp-server-deregistered"

	// EventMCPPermissionChanged fires when an MCP tool's required capabilities change.
	// Action: re-evaluate outstanding tokens against the new capability requirements.
	EventMCPPermissionChanged = "https://starfly.dev/secevent/event-type/mcp-permission-changed"
)

// ─────────────────────────────────────────────────────────────────────
// SSF DELIVERY METHODS
// ─────────────────────────────────────────────────────────────────────

// Delivery method URIs per OpenID SSF 1.0.
const (
	DeliveryPush = "https://schemas.openid.net/secevent/risc/delivery-method/push"
	DeliveryPoll = "https://schemas.openid.net/secevent/risc/delivery-method/poll"
)

// ─────────────────────────────────────────────────────────────────────
// STREAM STATUS
// ─────────────────────────────────────────────────────────────────────

// Stream status values per SSF 1.0.
const (
	StreamStatusEnabled  = "enabled"
	StreamStatusPaused   = "paused"
	StreamStatusDisabled = "disabled"
)

// ─────────────────────────────────────────────────────────────────────
// CAEP-SPECIFIC CLAIM VALUES
// ─────────────────────────────────────────────────────────────────────

// CAEP change type values.
const (
	ChangeTypeCreate  = "create"
	ChangeTypeRevoke  = "revoke"
	ChangeTypeUpdate  = "update"
	ChangeTypeDelete  = "delete"
)

// CAEP reason values for credential-change.
const (
	ReasonAdminAction     = "admin"
	ReasonUserAction      = "user"
	ReasonPolicy          = "policy"
	ReasonSuspiciousAct   = "suspicious_activity"
	ReasonExpired         = "expired"
)

// CAEP compliance status values.
const (
	ComplianceCompliant    = "compliant"
	ComplianceNotCompliant = "not-compliant"
)

// ─────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────

// NewSecurityEvent creates a SecurityEvent with a generated JTI and current timestamp.
func NewSecurityEvent(issuer, audience string, subID *core.SubjectIdentifier) *core.SecurityEvent {
	return &core.SecurityEvent{
		Issuer:    issuer,
		JTI:       generateJTI(),
		IssuedAt:  time.Now().Unix(),
		Audience:  audience,
		SubjectID: subID,
		Events:    make(map[string]map[string]interface{}),
	}
}

// AddEvent adds an event payload to a SecurityEvent.
func AddEvent(evt *core.SecurityEvent, eventType string, claims map[string]interface{}) {
	evt.Events[eventType] = claims
}

// generateJTI creates a random 16-byte hex JTI.
func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EventTypes returns a list of all supported CAEP/RISC event types.
func EventTypes() []string {
	return []string{
		EventCredentialChange,
		EventDeviceComplianceChange,
		EventSessionRevoked,
		EventAssuranceLevelChange,
		EventTokenClaimsChange,
		EventAccountDisabled,
		EventAccountEnabled,
		EventAccountCredChange,
		EventIdentifierChanged,
		EventTokenRevoked,
		EventPolicyViolation,
		EventMCPToolCompromised,
		EventMCPServerDeregistered,
		EventMCPPermissionChanged,
	}
}
