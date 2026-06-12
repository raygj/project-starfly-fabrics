---
title: Operations dashboard
description: Watch the fabric in real time — exchange, revocation, federation, and MCP health without touching the hot path.
slug: 1.0/docs/integrators/dashboard
---

**Watch exchange rate, revocation cascades, federation peers, and MCP denials in one place — read-only, off the hot path.** The operations dashboard is the human NOC for a fabric unit. If it goes away, tokens still exchange and revocations still propagate; you lose visibility, not security.

## Why it's worth your time

- **Live incident picture** — SSE event feed plus Prometheus metrics on one screen.
- **Demo-ready** — show delegation depth, federation topology, and per-tool MCP outcomes without scripting curls.
- **Zero PEP risk** — the dashboard only reads `/metrics`, `/v1/events`, and health endpoints.

## What you get

| Tab | What you see |
|-----|----------------|
| **Fabric Pulse** | Exchange rate, latency, active agents, live SSE |
| **Delegation** | Depth histogram, blast-radius denials |
| **MCP Security** | Per-tool verification and policy denials |
| **Federation** | Peer health, revocation relay, CAEP cascade |
| **Soul** | Manifest timeline and recovery readiness |
| **Trust Tree** | Trust domain hierarchy |

Screenshots: [starfly.dev/play](https://starfly.dev/play) · [docs/screenshots/](/1.0/docs/screenshots/)

## How it connects

```
Dashboard  →  GET /metrics, /v1/events, /v1/sys/health, /v1/mcp/tools, /v1/sys/trust-domains
                (all read-only, proxied server-side)
```

No writes to the PEP. Revocation and federation actions still go through signals API or operator tooling.

## When to use what

| Goal | Use |
|------|-----|
| Watch a demo or incident | Dashboard Pulse + SSE |
| Scriptable health check | `curl $STARFLY_URL/v1/sys/health` |
| Agent integration | [Token exchange](/1.0/docs/integrators/token-exchange/), [UTC](/1.0/docs/integrators/utc/) |

## Code in this repo

| Path | Status |
|------|--------|
| [`dashboard/`](https://github.com/raygj/project-starfly-fabrics/tree/main/dashboard) | Preview — Next.js app export pending |

Deploy with Helm (`dashboard.enabled=true`) when the app slice is published here.

## Related

- [UTC](/1.0/docs/integrators/utc/) · [Starfly Graph](/1.0/docs/integrators/starfly-graph/) — other async integrator surfaces
- [Getting started](/1.0/docs/getting-started/) — stand up a fabric unit first
- [Documentation voice](/1.0/docs/voice/)
