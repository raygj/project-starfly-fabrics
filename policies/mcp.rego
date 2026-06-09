# Starfly Fabrics — MCP Tool Call Policy
#
# This policy governs MCP tool access decisions.
# Evaluates whether a workload identity is allowed to call
# an MCP tool based on capabilities, blast radius, audience,
# and confused deputy mitigation.
#
# CoSAI threat coverage:
#   - Confused deputy (audience mismatch)
#   - Privilege escalation (capability check)
#   - Scope violation (blast radius)
#   - Unauthorized tool access (identity + attestation)

package starfly.mcp_tool_call

import future.keywords.in

default allow := false

# Allow MCP tool call when all checks pass.
allow if {
	valid_identity
	valid_audience
	valid_capabilities
	valid_blast_radius
}

# Identity must be attested via a recognized method.
valid_identity if {
	input.subject.attestation != null
	input.subject.attestation.method != ""
	input.subject.trust_domain != ""
}

# Audience must match the tool's resource URI (RFC 8707).
# This is the core confused deputy mitigation: a token issued for
# tool-A cannot be used against tool-B.
valid_audience if {
	input.context.resource != ""
	input.context.audience == input.context.resource
}

# If no resource URI is configured, skip audience check (dev mode).
valid_audience if {
	input.context.resource == ""
}

# Capability enforcement is handled in Go before policy evaluation.
# The OPA policy performs a permissive check here; hard enforcement
# lives in mcp.VerifyToolCall (checkCapabilities).
default valid_capabilities := true

# Blast radius enforcement is handled in Go before policy evaluation.
default valid_blast_radius := true

# Deny reasons for debugging.
reason := "identity has no attestation evidence" if {
	not valid_identity
}

reason := "token audience does not match tool resource URI (confused deputy)" if {
	valid_identity
	not valid_audience
}

reason := "token lacks required capabilities for this tool" if {
	valid_identity
	valid_audience
	not valid_capabilities
}

reason := "token blast radius exceeds tool maximum" if {
	valid_identity
	valid_audience
	valid_capabilities
	not valid_blast_radius
}
