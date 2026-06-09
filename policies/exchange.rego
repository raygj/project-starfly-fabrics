# Starfly Fabrics — Default Token Exchange Policy
#
# This policy governs all token exchange decisions.
# Every exchange request is evaluated against these rules.
#
# Override by mounting custom policies at /etc/starfly/policies/
# or configuring an OPA bundle source.

package starfly.exchange

import future.keywords.in

default allow := false

# Allow token exchange when:
# 1. Subject has a valid, attested identity
# 2. Target audience is in a trusted trust domain
# 3. Requested scope is within the subject's capabilities
allow if {
    valid_subject
    trusted_target
    valid_scope
}

# Subject must have attestation evidence
valid_subject if {
    input.subject.attestation != null
    input.subject.attestation.method != ""
    input.subject.trust_domain != ""
}

# Target must be in configured trust domains
trusted_target if {
    some td in data.trust_domains
    td.name == input.target
    td.enabled == true
}

# Scope must be within subject's allowed scopes
valid_scope if {
    # If no specific scope requested, allow
    input.context.scope == ""
}

valid_scope if {
    # Check scope against allowed scopes for this trust domain pair
    some mapping in data.scope_mappings
    mapping.source_domain == input.subject.trust_domain
    mapping.target_domain == input.target
    input.context.scope in mapping.allowed_scopes
}

# Deny reasons for debugging
reason := "subject has no attestation evidence" if {
    not valid_subject
}

reason := "target is not a trusted trust domain" if {
    valid_subject
    not trusted_target
}

reason := "requested scope is not allowed for this trust domain pair" if {
    valid_subject
    trusted_target
    not valid_scope
}

# HARDEN-016: cap delegation depth so on-behalf-of chains cannot be extended indefinitely.
claims := {"delegation_depth": 2}
