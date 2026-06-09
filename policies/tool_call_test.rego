# Tests for policies/tool_call.rego
package starfly.tool_call_test

import rego.v1

# ── helpers ───────────────────────────────────────────────────────────────────

base_input := {
	"subject": {
		"id": "spiffe://example.com/agent",
		"trust_domain": "example.com",
		"attestation": {
			"method": "mcp",
			"timestamp": "2026-01-01T00:00:00Z",
		},
	},
	"action": "tool_call",
	"target": "search-tool",
	"context": {
		"protocol": "mcp",
		"allowed_protocols": ["mcp"],
		"resource": "mcp://search-tool",
		"audience": "mcp://search-tool",
		"capabilities": ["read"],
		"blast_radius": "namespace:dev",
		"issuer": "https://starfly.test",
	},
}

# ── allow: happy path ─────────────────────────────────────────────────────────

test_allow_valid_mcp if {
	allow with input as base_input
}

test_allow_open_protocols if {
	# empty allowed_protocols = all protocols permitted
	inp := json.patch(base_input, [{"op": "replace", "path": "/context/allowed_protocols", "value": []}])
	allow with input as inp
}

test_allow_http_protocol if {
	inp := json.patch(base_input, [
		{"op": "replace", "path": "/context/protocol", "value": "http"},
		{"op": "replace", "path": "/context/allowed_protocols", "value": ["mcp", "http"]},
		{"op": "replace", "path": "/context/resource", "value": "http://search-tool"},
		{"op": "replace", "path": "/context/audience", "value": "http://search-tool"},
	])
	allow with input as inp
}

# ── deny: bad identity ─────────────────────────────────────────────────────────

test_deny_no_attestation if {
	inp := json.patch(base_input, [{"op": "remove", "path": "/subject/attestation"}])
	not allow with input as inp
}

test_deny_no_trust_domain if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/subject/trust_domain", "value": ""}])
	not allow with input as inp
}

# ── deny: protocol confusion ──────────────────────────────────────────────────

test_deny_protocol_confusion_http_on_mcp_only if {
	# tool only allows mcp; attacker sends via http
	inp := json.patch(base_input, [{"op": "replace", "path": "/context/protocol", "value": "http"}])
	not allow with input as inp
}

test_deny_protocol_confusion_a2a_on_mcp_only if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/context/protocol", "value": "a2a"}])
	not allow with input as inp
}

# ── deny: confused deputy ────────────────────────────────────────────────────

test_deny_audience_mismatch if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/context/audience", "value": "mcp://other-tool"}])
	not allow with input as inp
}

# ── deny reasons ────────────────────────────────────────────────────────────

test_reason_no_identity if {
	inp := json.patch(base_input, [{"op": "remove", "path": "/subject/attestation"}])
	starfly.tool_call.reason == "identity has no attestation evidence" with input as inp
}

test_reason_protocol_denied if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/context/protocol", "value": "http"}])
	starfly.tool_call.reason == "protocol not permitted for this tool" with input as inp
}

test_reason_confused_deputy if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/context/audience", "value": "mcp://other-tool"}])
	starfly.tool_call.reason == "token audience does not match tool resource URI (confused deputy)" with input as inp
}
