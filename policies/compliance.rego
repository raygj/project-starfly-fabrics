# Starfly Fabrics — Compliance Scan Policy
#
# This policy evaluates credential contexts for compliance violations.
# The compliance scan workflow (Temporal) calls this policy to produce
# findings for the ScanReport.
#
# Override thresholds by setting data.compliance_config in data.json.

package starfly.compliance

import future.keywords.in

# --- Configurable thresholds (override via data.compliance_config) ---

default _max_ttl_seconds := 3600

_max_ttl_seconds := data.compliance_config.max_ttl_seconds

default _max_delegation_depth := 3

_max_delegation_depth := data.compliance_config.max_delegation_depth

default _approved_credential_types := {"k8s-sa", "spiffe-svid", "oidc", "x509", "wimse-jwt", "agent-jwt"}

_approved_credential_types := data.compliance_config.approved_credential_types

# --- Main decision ---

default compliant := false

compliant if {
	count(findings) == 0
}

# findings is the set of all triggered compliance violations.
findings contains {
	"rule": "excessive_ttl",
	"severity": "high",
	"message": sprintf("TTL of %ds exceeds maximum of %ds", [input.ttl_seconds, _max_ttl_seconds]),
	"remediation": sprintf("Reduce token TTL to %ds or less", [_max_ttl_seconds]),
} if {
	input.ttl_seconds > _max_ttl_seconds
}

findings contains {
	"rule": "deep_delegation",
	"severity": "high",
	"message": sprintf("Delegation depth %d exceeds maximum of %d", [input.delegation_depth, _max_delegation_depth]),
	"remediation": sprintf("Reduce delegation chain to %d or fewer levels", [_max_delegation_depth]),
} if {
	input.delegation_depth > _max_delegation_depth
}

findings contains {
	"rule": "unscoped_execution",
	"severity": "critical",
	"message": "Execution-scoped credential has no trust domain binding",
	"remediation": "Bind the credential to a trust domain before granting execution scope",
} if {
	input.has_execution_scope == true
	input.trust_domain == ""
}

findings contains {
	"rule": "revocation_unhealthy",
	"severity": "critical",
	"message": "Revocation index is not responding",
	"remediation": "Investigate revocation index health before issuing new credentials",
} if {
	input.revocation_healthy == false
}

findings contains {
	"rule": "unknown_credential_type",
	"severity": "medium",
	"message": sprintf("Credential type %q is not in the approved list", [input.credential_type]),
	"remediation": "Use an approved credential type or request approval for a new type",
} if {
	not input.credential_type in _approved_credential_types
}
