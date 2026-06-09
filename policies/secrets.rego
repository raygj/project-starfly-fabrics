# Starfly Fabrics — Secret Delivery Policy (ADR-0014)
#
# Determines which secrets a workload identity can receive during
# token exchange. The policy evaluates the subject's identity and
# returns a list of secret_refs to include in the JWT.
#
# Override by mounting custom policies at /etc/starfly/policies/
# or configuring an OPA bundle source.

package starfly.secrets

import future.keywords.in

# Default: no secrets delivered.
default secret_refs = []

# Example: workloads in the "production.example.com" trust domain
# with "db-access" capability get database credentials.
secret_refs := refs if {
    input.subject.trust_domain == "production.example.com"
    "db-access" in input.context.capabilities
    refs := [
        {
            "source": "static",
            "path": "app/db",
            "key": "password",
            "alias": "db_password",
        },
    ]
}

# Example: agent workloads with "api-access" capability get API keys.
secret_refs := refs if {
    input.context.is_agent == true
    "api-access" in input.context.capabilities
    refs := [
        {
            "source": "static",
            "path": "app/api",
            "key": "key",
            "alias": "api_key",
        },
    ]
}
