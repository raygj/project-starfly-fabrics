# Starfly Fabrics — Compliance Policy Tests
#
# Run: opa test communes/starfly/policies/

package starfly.compliance

import future.keywords.in

# --- Helper: base input that passes all checks ---

_clean_input := {
	"credential_type": "k8s-sa",
	"ttl_seconds": 1800,
	"delegation_depth": 1,
	"has_execution_scope": false,
	"trust_domain": "cluster.local",
	"revocation_healthy": true,
}

# --- excessive_ttl ---

test_excessive_ttl_flagged if {
	result := findings with input as object.union(_clean_input, {"ttl_seconds": 7200})
	some f in result
	f.rule == "excessive_ttl"
	f.severity == "high"
}

test_normal_ttl_not_flagged if {
	result := findings with input as object.union(_clean_input, {"ttl_seconds": 1800})
	count({f | some f in result; f.rule == "excessive_ttl"}) == 0
}

test_zero_ttl_not_flagged if {
	result := findings with input as object.union(_clean_input, {"ttl_seconds": 0})
	count({f | some f in result; f.rule == "excessive_ttl"}) == 0
}

test_ttl_at_boundary_not_flagged if {
	result := findings with input as object.union(_clean_input, {"ttl_seconds": 3600})
	count({f | some f in result; f.rule == "excessive_ttl"}) == 0
}

# --- deep_delegation ---

test_deep_delegation_flagged if {
	result := findings with input as object.union(_clean_input, {"delegation_depth": 5})
	some f in result
	f.rule == "deep_delegation"
	f.severity == "high"
}

test_normal_delegation_not_flagged if {
	result := findings with input as object.union(_clean_input, {"delegation_depth": 2})
	count({f | some f in result; f.rule == "deep_delegation"}) == 0
}

test_delegation_at_boundary_not_flagged if {
	result := findings with input as object.union(_clean_input, {"delegation_depth": 3})
	count({f | some f in result; f.rule == "deep_delegation"}) == 0
}

# --- unscoped_execution ---

test_unscoped_execution_flagged if {
	result := findings with input as object.union(_clean_input, {"has_execution_scope": true, "trust_domain": ""})
	some f in result
	f.rule == "unscoped_execution"
	f.severity == "critical"
}

test_scoped_execution_not_flagged if {
	result := findings with input as object.union(_clean_input, {"has_execution_scope": true, "trust_domain": "cluster.local"})
	count({f | some f in result; f.rule == "unscoped_execution"}) == 0
}

test_no_execution_scope_empty_domain if {
	result := findings with input as object.union(_clean_input, {"has_execution_scope": false, "trust_domain": ""})
	count({f | some f in result; f.rule == "unscoped_execution"}) == 0
}

# --- revocation_unhealthy ---

test_revocation_unhealthy_flagged if {
	result := findings with input as object.union(_clean_input, {"revocation_healthy": false})
	some f in result
	f.rule == "revocation_unhealthy"
	f.severity == "critical"
}

test_revocation_healthy_not_flagged if {
	result := findings with input as object.union(_clean_input, {"revocation_healthy": true})
	count({f | some f in result; f.rule == "revocation_unhealthy"}) == 0
}

# --- unknown_credential_type ---

test_unknown_credential_type_flagged if {
	result := findings with input as object.union(_clean_input, {"credential_type": "mystery-token"})
	some f in result
	f.rule == "unknown_credential_type"
	f.severity == "medium"
}

test_known_credential_type_not_flagged if {
	result := findings with input as object.union(_clean_input, {"credential_type": "spiffe-svid"})
	count({f | some f in result; f.rule == "unknown_credential_type"}) == 0
}

# --- compliant helper ---

test_compliant_clean_input if {
	compliant with input as _clean_input
}

test_not_compliant_with_violation if {
	not compliant with input as object.union(_clean_input, {"ttl_seconds": 7200})
}

# --- multiple findings ---

test_multiple_findings if {
	bad_input := {
		"credential_type": "unknown-thing",
		"ttl_seconds": 9999,
		"delegation_depth": 10,
		"has_execution_scope": true,
		"trust_domain": "",
		"revocation_healthy": false,
	}
	result := findings with input as bad_input
	count(result) == 5
}

# --- configurable thresholds ---

test_custom_max_ttl_override if {
	result := findings with input as object.union(_clean_input, {"ttl_seconds": 500}) with data.compliance_config as {"max_ttl_seconds": 300}
	some f in result
	f.rule == "excessive_ttl"
}

test_custom_delegation_depth_override if {
	result := findings with input as object.union(_clean_input, {"delegation_depth": 2}) with data.compliance_config as {"max_delegation_depth": 1}
	some f in result
	f.rule == "deep_delegation"
}
