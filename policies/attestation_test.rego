# Starfly Fabrics — Binary Hash Allowlist Policy Tests (SA-005)

package starfly.attestation_test

import data.starfly.attestation

# ── Allow cases ──────────────────────────────────────────────────────

test_allow_no_attestation if {
    attestation.allow with input as {"context": {}}
}

test_allow_no_attestation_null if {
    attestation.allow with input as {"context": {"attestation": null}}
}

test_allow_attestation_no_binary_hash if {
    attestation.allow with input as {
        "context": {
            "attestation": {
                "workload": {"namespace": "prod"},
                "assurance_level": "software",
            },
        },
    }
}

test_allow_approved_hash if {
    attestation.allow with input as {
        "context": {
            "attestation": {
                "workload": {"binary_hash": "sha256:abc123"},
                "assurance_level": "software",
            },
        },
    } with data.approved_agent_hashes as ["sha256:abc123", "sha256:def456"]
}

test_allow_empty_allowlist if {
    attestation.allow with input as {
        "context": {
            "attestation": {
                "workload": {"binary_hash": "sha256:unknown"},
                "assurance_level": "software",
            },
        },
    } with data.approved_agent_hashes as []
}

# ── Deny cases ───────────────────────────────────────────────────────

test_deny_unknown_hash if {
    not attestation.allow with input as {
        "context": {
            "attestation": {
                "workload": {"binary_hash": "sha256:malicious"},
                "assurance_level": "software",
            },
        },
    } with data.approved_agent_hashes as ["sha256:abc123", "sha256:def456"]
}

test_deny_reason if {
    attestation.reason == "agent binary hash not in approved allowlist" with input as {
        "context": {
            "attestation": {
                "workload": {"binary_hash": "sha256:malicious"},
                "assurance_level": "software",
            },
        },
    } with data.approved_agent_hashes as ["sha256:abc123"]
}

# ── Assurance level ──────────────────────────────────────────────────

test_assurance_level_software if {
    attestation.assurance_level == "software" with input as {
        "context": {
            "attestation": {"assurance_level": "software"},
        },
    }
}

test_assurance_level_hardware if {
    attestation.assurance_level == "hardware" with input as {
        "context": {
            "attestation": {"assurance_level": "hardware"},
        },
    }
}

test_assurance_level_none_when_null if {
    attestation.assurance_level == "none" with input as {
        "context": {"attestation": null},
    }
}
