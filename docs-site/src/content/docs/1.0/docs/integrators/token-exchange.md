---
title: Token exchange
description: Turn any platform credential into a scoped WIMSE JWT in one RFC 8693 call — the front door to the fabric.
slug: 1.0/docs/integrators/token-exchange
---

**Turn a platform credential into a scoped WIMSE JWT in one call** — the front door every agent and service uses before calling tools, APIs, or peers. Starfly implements RFC 8693 token exchange; what you put in `audience` becomes `aud` on the outbound token.

## Why it's worth your time

- **One endpoint for every inbound identity** — Kubernetes SA, SPIFFE, OIDC, MCP agent creds, and more map to the same exchange shape.
- **Scoped by construction** — `audience` and optional `scope` narrow blast radius before the token leaves the PEP.
- **Fast by design** — exchange stays on the hot path; nothing here blocks revocation or async observability.

## How it works

```
Platform credential  →  POST /v1/exchange/token  →  WIMSE JWT (aud, td, scope, ttl)
                              ↓
                    downstream tool / API / verify
```

Locked fabric units (`locked: true` on health) reject exchange until unsealed.

## Wire it up

### 1. Discover the PEP

```bash
export STARFLY_URL=http://localhost:8693   # or your fabric URL
curl -sf "$STARFLY_URL/v1/sys/health" | jq .
```

### 2. Exchange

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

| Field | Value |
|-------|-------|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Raw credential string |
| `subject_token_type` | Credential type URI (table below) |
| `audience` | Target service — becomes `aud` on the WIMSE JWT |

**Common `subject_token_type` values**

| URI | Credential |
|-----|------------|
| `urn:ietf:params:oauth:token-type:jwt` | JWT (K8s SA, generic) |
| `urn:starfly:token-type:spiffe-svid` | SPIFFE SVID |
| `urn:starfly:token-type:oidc` | OIDC access token |
| `urn:starfly:token-type:agent-mcp` | MCP agent credential |

Full list: [OpenAPI](https://starfly.dev/api/operations/exchangetoken/).

### 3. Verify what you got

```json
{
  "access_token": "eyJ…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 300
}
```

```bash
curl -s "$STARFLY_URL/v1/identity/jwks" | jq
```

## Trust domain vs audience

- **`td`** — inbound trust plane ([trust domains](/1.0/docs/concepts/trust-domains/))
- **`aud`** — outbound target you requested in exchange

Do not use `aud` as a stand-in for trust-domain configuration.

## Production patterns

**Agent identity** — `POST /v1/identity/agent` issues bootstrap tokens for registered agents. Dev mode accepts stub JWTs; see [getting started](/1.0/docs/getting-started/).

**Execution-scoped tokens** — bind a token to a specific HTTP action and payload hash via `execution_scope` (~30s TTL). Field definitions in [OpenAPI](https://starfly.dev/api/operations/exchangetoken/).

**Agent bootstrap (Cursor / Claude Code)**

1. Read [AGENTS.md](https://github.com/raygj/project-starfly-fabrics/blob/main/AGENTS.md)
2. `export STARFLY_PROFILE=local && ./sandbox/init.sh`
3. `./sandbox/run.sh exchange`

## Code in this repo

| Path | Status |
|------|--------|
| [`pkg/exchange/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/exchange) | Shipped — exchange pipeline |
| [`pkg/identity/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/identity) | Shipped — credential adapters |

## Subject credentials

What you pass as `subject_token` depends on the platform — SPIFFE/SPIRE, Kubernetes SA, cloud workload identity, or an IdP bridge. Starfly always outputs WIMSE.

→ [Credential patterns](/1.0/docs/integrators/credential-patterns/)

## Related

- [Credential patterns](/1.0/docs/integrators/credential-patterns/) — SPIFFE, K8s, Vault OIDC, cloud WI
- [MCP security](/1.0/docs/integrators/mcp/) — tool-scoped `audience`
- [Exchange concepts](/1.0/docs/concepts/exchange/)
- [Revocation](/1.0/docs/concepts/revocation/)
- [Documentation voice](/1.0/docs/voice/)
