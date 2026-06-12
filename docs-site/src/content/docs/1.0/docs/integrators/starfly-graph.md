---
title: Starfly Graph
description: Query who did what — lineage, blast radius, and tool history from fabric events, without slowing exchange or revocation.
slug: 1.0/docs/integrators/starfly-graph
---

**Ask who an agent reached, through what delegation chain, and how fast revocation propagated — without adding latency to exchange or revocation.** Starfly Graph is the fabric's memory: a runtime knowledge graph built from events the PEP already publishes.

## Why it's worth your time

- **Answer investigation questions in seconds** — blast radius, lineage, and tool usage history instead of log archaeology.
- **Safe by design** — a NATS consumer behind the PEP; if graph is slow or down, exchange and kill-switch keep running.
- **Agent-queryable** — MCP tools and read-only REST for automation and IDE agents.

## How it works

```
PEP events  →  NATS JetStream  →  starfly-graph  →  FalkorDB
     ↑                                    │
 hot path                          fabric does not wait
```

The graph subscribes to subjects the fabric already emits (`EXCHANGE.*`, `REVOCATION.*`, `DELEGATION.*`, `MCP.*`, …). Data enters only through that consumer — never via API POST.

## What you can query

### MCP tools

| Tool | Answers |
|------|---------|
| `query_runtime` | What has this agent done? |
| `query_blast_radius` | If compromised, what can it reach? |
| `query_lineage` | Delegation chain to root principal |
| `query_revocation_timeline` | How fast did revocation propagate? |
| `query_tool_usage` | Who calls this tool, allow vs deny |

### REST (read-only)

| Endpoint | Purpose |
|----------|---------|
| `GET /v1/graph/agents` | Agent inventory |
| `GET /v1/graph/agents/{id}/blast-radius` | Transitive reach |
| `GET /v1/graph/agents/{id}/lineage` | Delegation chain |
| `GET /v1/graph/stats` | Node counts, consumer lag |

## Runtime + design-time

Runtime graph (Starfly) pairs with the design-time graph in [CALM Forge](https://github.com/raygj/project-calm-forge). Shared vocabulary (`Capability`, `Source`, `TrustDomain`); `manifests_as` is computed at query time, not stored.

| Surface | Best for |
|---------|----------|
| [Operations dashboard](/1.0/docs/dashboard/) | Human watch — metrics, SSE, topology |
| **Starfly Graph** | Machine query — lineage, blast radius, shadow agents |

## Code in this repo

| Path | Status |
|------|--------|
| [`pkg/graph/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/graph) | Preview — library export pending |
| [`cmd/starfly-graph/`](https://github.com/raygj/project-starfly-fabrics/tree/main/cmd/starfly-graph) | Preview — service binary pending |

## Operator checklist

- [ ] NATS JetStream healthy on the fabric unit
- [ ] `GET /v1/graph/stats` — consumer lag near zero
- [ ] Kill-switch proof via [`sandbox/run.sh`](https://github.com/raygj/project-starfly-fabrics/tree/main/sandbox) — graph optional for that test

## Related

- [Ecosystem overview](/1.0/ecosystem/) — where Graph sits in the fabric
- [CALM Forge](/1.0/ecosystem/calm-forge/) — design-time graph satellite
- [UTC](/1.0/docs/utc/) — multi-protocol tool verification
- [Documentation voice](/1.0/voice/)
