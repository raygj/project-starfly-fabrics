# Starfly Fabrics — Agent Identity Policy
#
# This policy governs agent identity issuance decisions.
# Evaluates whether an agent is allowed to receive a WIMSE JWT
# based on capabilities, blast radius, and delegation depth.

package starfly.agent_identity

default allow := false

allow if {
	is_agent
	valid_capabilities
	valid_blast_radius
	valid_delegation_depth
}

is_agent if {
	input.context.is_agent == true
}

valid_capabilities if {
	count(input.context.capabilities) > 0
}

valid_blast_radius if {
	not input.context.max_blast_radius
}

valid_blast_radius if {
	input.context.blast_radius <= input.context.max_blast_radius
}

valid_delegation_depth if {
	not input.context.delegation_depth
}

valid_delegation_depth if {
	is_null(input.context.delegation_depth)
}

valid_delegation_depth if {
	input.context.delegation_depth >= 0
}
