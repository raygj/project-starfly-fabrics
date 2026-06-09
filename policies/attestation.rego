# Starfly Fabrics — Binary Hash Allowlist Policy (SA-005)
#
# When an agent sends attestation metadata, this policy denies exchange
# if the agent's binary hash is not in the approved allowlist.
# This catches supply chain substitution — only known-good agent binaries
# can exchange credentials.
#
# This policy is OPT-IN:
# - If no attestation is present, the policy allows (backward compat).
# - If attestation is present but has no binary hash, the policy allows.
# - The allowlist is maintained in data.approved_agent_hashes.
#
# See ADR-0013 for the attestation architecture.

package starfly.attestation

import future.keywords.in

default allow := true

# Deny if attestation provides a binary hash that is not in the allowlist.
allow := false if {
    input.context.attestation != null
    input.context.attestation.workload != null
    input.context.attestation.workload.binary_hash != ""
    count(data.approved_agent_hashes) > 0
    not hash_approved
}

# Check if the binary hash is in the approved set.
hash_approved if {
    some approved in data.approved_agent_hashes
    approved == input.context.attestation.workload.binary_hash
}

# Reason for denial.
reason := "agent binary hash not in approved allowlist" if {
    not allow
}

# Computed assurance level (passthrough from attestation).
assurance_level := input.context.attestation.assurance_level if {
    input.context.attestation != null
}

assurance_level := "none" if {
    input.context.attestation == null
}
