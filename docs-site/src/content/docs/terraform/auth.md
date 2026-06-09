---
title: Authentication
description: mTLS and JWT authentication for the Terraform provider.
---

The provider supports two authentication modes for Starfly HTTP API resources.

## mTLS (default)

```hcl
provider "starfly" {
  endpoint    = "https://starfly.starfly-system.svc:8694"
  ca_cert     = file("${path.module}/certs/ca.pem")
  client_cert = file("${path.module}/certs/client.pem")
  client_key  = file("${path.module}/certs/client-key.pem")
}
```

Required for `starfly_ssf_stream` in hardened deployments.

## JWT bearer

```hcl
provider "starfly" {
  endpoint  = "https://starfly.starfly-system.svc:8694"
  jwt_token = var.starfly_jwt
}
```

Used by:

- `starfly_mcp_tool`
- `starfly_agent_identity`
- `starfly_encryption_key` (required)

## Migration path

| Phase | CRD resources | API resources |
|-------|---------------|---------------|
| Bootstrap | `kubeconfig_path` only | mTLS from cert-manager or Helm |
| Day-2 | unchanged | exchange → `jwt_token` for MCP/agent/key |
| Production | unchanged | short-lived workload JWT via external secret store |

**Pattern:** Create `starfly_agent_identity`, use emitted `token` as `jwt_token` for encryption key and MCP tool modules.

## Dev / acceptance tests only

CI runs Starfly `--dev` and obtains bearer tokens via `POST /v1/exchange/token`. Never use dev mode credentials in production.
