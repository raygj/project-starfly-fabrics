---
title: Exchange
description: How Starfly turns platform credentials into scoped WIMSE JWTs — fast, policy-bound, and the center of the fabric.
---

**Every agent action starts with exchange** — validate the inbound credential, apply policy, mint a short-lived WIMSE JWT scoped to one audience. That is Starfly's core job on the fabric.

## Why it matters

- **One front door** — Kubernetes, SPIFFE, OIDC, and MCP agent creds all use the same RFC 8693 shape.
- **Scoped by default** — `audience` at exchange time becomes `aud` on the JWT; blast radius is chosen up front.
- **Fast by design** — lookup, policy, and sign stay on the hot path; everything else is async.

## How it works

```
Workload credential  →  POST /v1/exchange/token  →  WIMSE JWT
     (inbound)              OPA + validators           (outbound, aud-scoped)
```

1. Client sends an RFC 8693 token exchange request.
2. Starfly identifies credential type (`subject_token_type`).
3. Validators check signature, expiry, and trust domain match.
4. OPA policy allows or denies — see [`policies/`](https://github.com/raygj/project-starfly-fabrics/tree/main/policies).
5. Starfly signs a WIMSE JWT with `sub`, `aud`, `td`, `exp`, and optional delegation claims.

Background work (graph, behavioral profiling, federation relay) runs on **NATS consumers** — never inside the exchange request.

## The latency contract

The exchange path is optimized for sub-millisecond end-to-end latency in production fabrics. Do not add synchronous dependencies (remote calls, blocking I/O) to this pipeline.

Async integrator surfaces — [dashboard](/docs/integrators/dashboard/), [graph](/docs/integrators/starfly-graph/), [UTC](/docs/integrators/utc/) — sit beside exchange, not in it.

## Dev vs production

| Mode | Credential | Policy |
|------|------------|--------|
| `--dev` | Stub JWTs accepted | `policies/dev/` permissive |
| Production | Real platform credentials | Operator-authored Rego |

## Key endpoints

| Path | Purpose |
|------|---------|
| `POST /v1/exchange/token` | Exchange |
| `GET /v1/identity/jwks` | Verify issued tokens |
| `GET /metrics` | `starfly_exchange_*` histograms |

Full reference: [OpenAPI — exchange](https://starfly.dev/api/operations/exchangetoken/).

## Try it

```bash
make build-dev && ./bin/starfly --dev
./sandbox/run.sh exchange
```

Integrator walkthrough: [token exchange](/docs/integrators/token-exchange/).

## Code in this repo

| Path | Role |
|------|------|
| [`pkg/exchange/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/exchange) | Exchange pipeline |
| [`policies/`](https://github.com/raygj/project-starfly-fabrics/tree/main/policies) | OPA Rego bundles |

## Related

- [Getting started](/docs/getting-started/)
- [Trust domains](/docs/trust-domains/)
- [Revocation](/docs/revocation/)
- [Documentation voice](/docs/voice/)
