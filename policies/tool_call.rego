# Starfly Fabrics — Universal Tool Call Policy
#
# Protocol-agnostic policy for the universal tool-call layer (ADR-0022).
# Covers MCP, HTTP/REST, and A2A protocols through a single rule set.
#
# This supersedes policies/mcp.rego for new deployments; the mcp.rego
# package is preserved for backward compatibility with existing middleware.
#
# CoSAI threat coverage:
#   - Confused deputy (audience mismatch, RFC 8707)
#   - Protocol confusion (tool protocol gate)
#   - Privilege escalation (capability check)
#   - Scope violation (blast radius)
#   - Unauthorized tool access (identity + attestation)

package starfly.tool_call

import future.keywords.in

default allow := false

# Allow when all security gates pass.
allow if {
	valid_identity
	valid_protocol
	valid_audience
	valid_capabilities
	valid_blast_radius
}

# ── Identity ─────────────────────────────────────────────────────────────────

# Identity must carry an attestation from a recognized method.
valid_identity if {
	input.subject.attestation != null
	input.subject.attestation.method != ""
	input.subject.trust_domain != ""
}

# ── Protocol gate ─────────────────────────────────────────────────────────────

# The requesting protocol must be in the tool's declared allowed_protocols list.
# An empty allowed_protocols means "all protocols permitted" (dev/open tools).
valid_protocol if {
	count(input.context.allowed_protocols) == 0
}

valid_protocol if {
	input.context.protocol in input.context.allowed_protocols
}

# ── Audience ─────────────────────────────────────────────────────────────────

# Audience must match the tool's resource URI (RFC 8707).
# Core confused-deputy mitigation: a token issued for tool-A cannot reach tool-B.
valid_audience if {
	input.context.resource != ""
	input.context.audience == input.context.resource
}

# Resource URI not configured → skip audience check (open/dev tools).
valid_audience if {
	input.context.resource == ""
}

# ── Capability + Blast Radius ─────────────────────────────────────────────────

# Hard enforcement lives in Go (verifier.go); the OPA layer is permissive here
# and serves as an auditable record of the enforcement decision.
default valid_capabilities := true
default valid_blast_radius := true

# ── Deny Reasons ──────────────────────────────────────────────────────────────

reason := "identity has no attestation evidence" if {
	not valid_identity
}

reason := "protocol not permitted for this tool" if {
	valid_identity
	not valid_protocol
}

reason := "token audience does not match tool resource URI (confused deputy)" if {
	valid_identity
	valid_protocol
	not valid_audience
}

reason := "token lacks required capabilities for this tool" if {
	valid_identity
	valid_protocol
	valid_audience
	not valid_capabilities
}

reason := "token blast radius exceeds tool maximum" if {
	valid_identity
	valid_protocol
	valid_audience
	valid_capabilities
	not valid_blast_radius
}
