---
title: Operations dashboard
description: Real-time fabric observability — SSE, Prometheus, federation topology. Not on the exchange or revocation hot paths.
slug: 1.0/docs/integrators/dashboard
---

The **Starfly operations dashboard** is a Next.js app for human operators and demos. It reads metrics and events from a running fabric unit — it does **not** sit in the token exchange or revocation kill-switch paths.

## Hot path boundary

| Path | Dashboard involved? |
|------|---------------------|
| `POST /v1/exchange/token` | **No** — 124ns class pipeline |
| Revocation index / CAEP cascade | **No** — 30ms kill switch |
| `GET /metrics`, `GET /v1/events` | **Read-only** — async poll / SSE |
| AI fabric query bar | **Optional** — proxied read APIs only |

If the dashboard is down, the fabric keeps exchanging and revoking. You lose visibility, not security.

## Views

| Tab | Route | What you see |
|-----|-------|----------------|
| **Fabric Pulse** | `/` | Exchange rate, latency, active agents, live SSE feed |
| **Delegation** | `/delegation` | Delegation depth, blast-radius denials |
| **MCP Security** | `/mcp` | Per-tool verification, policy denials, latency |
| **Federation** | `/federation` | Peer health, revocation relay, CAEP cascade |
| **Soul** | `/soul` | Manifest / anchor timeline, recovery readiness |
| **Trust Tree** | `/trust` | Trust domain hierarchy (sunburst) |

Screenshots: [starfly.dev/play](https://starfly.dev/play) and [docs/screenshots/](../screenshots/).

## Data sources

```
Dashboard (Next.js)
    ├── GET /metrics              → Prometheus (proxied)
    ├── GET /v1/events            → SSE live stream (proxied)
    ├── GET /v1/sys/health
    ├── GET /v1/mcp/tools
    └── GET /v1/sys/trust-domains → Trust Tree tab
```

The dashboard never writes to the PEP.

## Lab access

Deployed fabric labs expose the dashboard on a NodePort (example: `:30423` on the forge Talos cluster). Pair with [Getting started](../getting-started.md) health checks on the PEP itself.

## When to use dashboard vs CLI

| Task | Tool |
|------|------|
| Incident watch / demo | Dashboard SSE + Pulse |
| Scriptable health | `curl $STARFLY_URL/v1/sys/health` |
| Agent integration | [Token exchange](token-exchange.md), [UTC](utc.md) |

## Deploy

The dashboard image deploys via Helm (`dashboard.enabled=true`) alongside fabric units. Source lives in the Starfly operator workspace — not in this public code export.
