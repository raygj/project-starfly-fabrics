# Starfly Fabrics — Default Signal Processing Policy
#
# This policy governs how incoming SSF/CAEP events are processed.
# Determines whether a received signal should be propagated,
# trigger token revocation, or be logged and ignored.
#
# The allow/reason rules gate whether a signal is accepted for processing.
# The propagate/revoke_tokens rules control downstream behavior.

package starfly.signal

default allow := false
default propagate := true
default revoke_tokens := false

# HARDEN-006: allowlist of recognized CAEP/RISC event type URIs.
# Events containing any type outside this set are denied.
allowed_event_types := {
	"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
	"https://schemas.openid.net/secevent/caep/event-type/credential-change",
	"https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
	"https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
	"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
	"https://schemas.openid.net/secevent/risc/event-type/account-enabled",
	"https://schemas.openid.net/secevent/risc/event-type/account-purged",
	"https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
	"https://schemas.openid.net/secevent/risc/event-type/identifier-changed",
	"https://schemas.openid.net/secevent/risc/event-type/recovery-activated",
}

# Every event type in the SET must be in the allowlist.
all_event_types_allowed if {
	event_types := {t | t := input.context.event_types[_]}
	count(event_types - allowed_event_types) == 0
}

# Allow signal processing when:
# 1. The subject has valid attestation, AND
# 2. All event types are in the allowlist.
allow if {
	input.subject.attestation != null
	input.subject.attestation.method != ""
	all_event_types_allowed
}

# Deny reason when attestation is missing.
reason := "subject has no attestation evidence" if {
	not allow
	input.subject.attestation == null
}

# Deny reason when event types are not in the allowlist.
reason := "unknown event type" if {
	not allow
	input.subject.attestation != null
	not all_event_types_allowed
}

# CAEP device compliance change — revoke tokens if device is non-compliant
revoke_tokens if {
	input.context.event_types[_] == "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	input.context.current_status == "not-compliant"
}

# CAEP session revoked — propagate and revoke
revoke_tokens if {
	input.context.event_types[_] == "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
}

# RISC account disabled — revoke all tokens for this subject
revoke_tokens if {
	input.context.event_types[_] == "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
}

# CAEP credential change — propagate but don't auto-revoke
propagate if {
	input.context.event_types[_] == "https://schemas.openid.net/secevent/caep/event-type/credential-change"
}

# Surface revoke_tokens in the claims map so the receiver can act on it.
# The engine queries data.starfly.signal.claims — not revoke_tokens directly.
claims := {"revoke_tokens": revoke_tokens}
