# Starfly Fabrics — Agent Identity Policy Tests

package starfly.agent_identity

test_allow_valid_agent if {
	allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read", "write"],
		"blast_radius": 3,
		"max_blast_radius": 3,
		"delegation_depth": 2,
	}}
}

test_deny_non_agent if {
	not allow with input as {"context": {
		"is_agent": false,
		"capabilities": ["read"],
		"blast_radius": 1,
		"max_blast_radius": 1,
		"delegation_depth": 0,
	}}
}

test_deny_empty_capabilities if {
	not allow with input as {"context": {
		"is_agent": true,
		"capabilities": [],
		"blast_radius": 1,
		"max_blast_radius": 1,
		"delegation_depth": 0,
	}}
}

test_deny_blast_radius_exceeds_max if {
	not allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read"],
		"blast_radius": 5,
		"max_blast_radius": 3,
		"delegation_depth": 0,
	}}
}

test_allow_delegation_depth_null if {
	allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read"],
		"blast_radius": 1,
		"max_blast_radius": 1,
		"delegation_depth": null,
	}}
}

test_allow_delegation_depth_zero if {
	allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read"],
		"blast_radius": 1,
		"max_blast_radius": 1,
		"delegation_depth": 0,
	}}
}

test_deny_delegation_depth_negative if {
	not allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read"],
		"blast_radius": 1,
		"max_blast_radius": 1,
		"delegation_depth": -1,
	}}
}

test_allow_delegation_depth_unset if {
	allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read"],
		"blast_radius": 1,
		"max_blast_radius": 1,
	}}
}

test_allow_blast_radius_below_max if {
	allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read"],
		"blast_radius": 2,
		"max_blast_radius": 5,
		"delegation_depth": 1,
	}}
}

test_allow_no_max_blast_radius if {
	allow with input as {"context": {
		"is_agent": true,
		"capabilities": ["read"],
		"blast_radius": 10,
		"delegation_depth": 1,
	}}
}
