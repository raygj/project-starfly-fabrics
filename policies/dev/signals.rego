# Dev-mode allow-all signal policy.
# NOT for production — allows all signal processing without restriction.

package starfly.signal

default allow := true
default propagate := true
default revoke_tokens := false

# Revoke tokens when session is explicitly revoked via CAEP.
# Enables chaos-loadgen denial testing against the revocation index.
revoke_tokens if {
	input.context.event_types[_] == "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
}

# Surface revoke_tokens in the claims map so the receiver can act on it.
# The engine queries data.starfly.signal.claims — not revoke_tokens directly.
claims := {"revoke_tokens": revoke_tokens}
