---
tags: [commune/starfly, terraform, auth]
type: pattern
created: 2026-05-23
---

# Auth — mTLS and JWT

The provider supports two authentication modes for Starfly HTTP API resources.

## mTLS (default)

Use client certificate authentication for API calls. Required for `starfly_ssf_stream` in production deployments.

```hcl
provider "starfly" {
  endpoint    = "https://starfly.starfly-system.svc:8694"
  ca_cert     = file("${path.module}/certs/ca.pem")
  client_cert = file("${path.module}/certs/client.pem")
  client_key  = file("${path.module}/certs/client-key.pem")
}
```

Environment fallbacks: `STARFLY_CA_CERT`, `STARFLY_CLIENT_CERT`, `STARFLY_CLIENT_KEY`.

## JWT bearer (API resources)

Set `jwt_token` for bearer-authenticated endpoints. Used by:

- `starfly_mcp_tool`
- `starfly_agent_identity`
- `starfly_encryption_key` (required — WIMSE bearer)

```hcl
provider "starfly" {
  endpoint  = "https://starfly.starfly-system.svc:8694"
  jwt_token = var.starfly_jwt
}
```

Environment fallback: `STARFLY_JWT_TOKEN`.

## Migration path

| Phase | CRD resources | API resources |
|-------|---------------|---------------|
| v0 bootstrap | `kubeconfig_path` only | mTLS certs from cert-manager or Helm outputs |
| v0 day-2 | unchanged | exchange token → set `jwt_token` for MCP/agent/encryption |
| v1 production | unchanged | workload identity issues short-lived JWT; rotate via TF variable or external secret store |

**Agent contract:** Bootstrap with mTLS for SSF and health checks. After agent identity registration (`starfly_agent_identity`), downstream modules consume the emitted `token` output as `jwt_token` for encryption key and MCP tool resources.

## Dev mode (acceptance tests only)

CI and local acceptance tests run Starfly with `--dev` and obtain a bearer token via `POST /v1/exchange/token`. Do not use dev mode or unsigned JWTs in production.
