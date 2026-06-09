---
title: Token exchange
slug: 1.0/docs/integrators/token-exchange
---

# Integrator guide — token exchange

Wire an agent or service to Starfly's RFC 8693 endpoint.

## Discover the PEP

```bash
export STARFLY_URL=http://localhost:8693   # or your fabric URL
curl -sf "$STARFLY_URL/v1/sys/health" | jq .
```

`locked: true` means the unit is sealed — exchanges are rejected until unseal.

## Exchange request

```bash
curl -s -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<PLATFORM_CREDENTIAL>",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "audience": "https://api.target.example.com",
    "scope": "read:data"
  }' | jq
```

### Required fields

| Field | Value |
|-------|-------|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Raw credential string |
| `subject_token_type` | Credential type URI (see table) |
| `audience` | Target service — becomes `aud` on the WIMSE JWT |

### Common `subject_token_type` values

| URI | Credential |
|-----|------------|
| `urn:ietf:params:oauth:token-type:jwt` | JWT (K8s SA, generic) |
| `urn:starfly:token-type:spiffe-svid` | SPIFFE SVID |
| `urn:starfly:token-type:oidc` | OIDC access token |
| `urn:starfly:token-type:agent-mcp` | MCP agent credential |

Full list: [OpenAPI](../../api/openapi.yaml).

## Response

```json
{
  "access_token": "eyJ…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 300
}
```

Verify with JWKS:

```bash
curl -s "$STARFLY_URL/v1/identity/jwks" | jq
```

## Trust domain and audience

* **`td`** — inbound trust plane ([trust domains](../concepts/trust-domains.md))
* **`aud`** — outbound target you requested

Do not use `aud` as a stand-in for trust domain configuration.

## Agent identity (production)

`POST /v1/identity/agent` issues bootstrap tokens for registered agents. In dev mode, stub JWTs suffice — see [getting started](../getting-started.md).

Production fabrics may require mTLS or bearer auth on identity endpoints.

## Execution-scoped tokens

Bind a token to a specific HTTP action and payload hash via `execution_scope` on the exchange request. Shorter TTL (~30s). See OpenAPI for field definitions.

## Agent bootstrap

For Cursor / Claude Code:

1. Read [AGENTS.md](../../AGENTS.md)
2. `export STARFLY_PROFILE=local && ./sandbox/init.sh`
3. `./sandbox/run.sh exchange`

## Related

* [MCP integration](mcp.md)
* [Exchange concepts](../concepts/exchange.md)
* [Glossary](../glossary.md)
