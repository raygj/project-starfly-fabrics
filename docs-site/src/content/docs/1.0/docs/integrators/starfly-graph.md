---
title: Starfly Graph
description: Runtime identity knowledge graph — NATS JetStream consumer to FalkorDB. Zero impact on exchange or revocation hot paths.
slug: 1.0/docs/integrators/starfly-graph
---

The **Starfly Graph** is the fabric's **memory** — a runtime knowledge graph built from events the PEP already publishes. It follows ADR-0031 and the shared ontology in ADR-0024.

It is **not** on the exchange or revocation hot paths.

## Design rule

```
Exchange / revocation  →  NATS JetStream  →  starfly-graph consumer  →  FalkorDB
        ↑                         │
   sacred paths                   └── fabric does not wait for graph
```

If `starfly-graph` is slow or offline:

- Exchanges continue
- Revocations propagate at kill-switch latency
- JetStream buffers; graph catches up on recovery

The fabric does not know the graph exists. The graph knows the fabric exists.

## What gets ingested

| NATS subject | Graph effect (simplified) |
|--------------|---------------------------|
| `EXCHANGE.>` | Agent exchanged toward audience |
| `REVOCATION.>` | Agent revoked, revocation event node |
| `SIGNAL.>` | SSF/CAEP signal ingested |
| `DELEGATION.>` | Delegation edge between agents |
| `MCP.*` | Tool registration, verify decisions |
| `FEDERATION.>` | Cross-unit sync metadata |

Node types include `Agent`, `Exchange`, `Revocation`, `Delegation`, `Tool`, `ToolCall`, `BehavioralProfile`, `SignalEvent`, `FabricUnit`.

## Query surfaces

### MCP tools (for agents in the IDE)

| Tool | Question it answers |
|------|---------------------|
| `query_runtime` | What has this agent done? |
| `query_blast_radius` | If compromised, what can it reach? |
| `query_lineage` | Full delegation chain to root |
| `query_revocation_timeline` | How fast did revocation propagate? |
| `query_tool_usage` | Who calls this MCP tool and with what outcome? |

### REST (read-only)

| Path | Purpose |
|------|---------|
| `GET /v1/graph/agents` | Agent inventory + stats |
| `GET /v1/graph/agents/{id}/blast-radius` | Transitive reach |
| `GET /v1/graph/agents/{id}/lineage` | Delegation chain |
| `GET /v1/graph/tools` | Tool usage summary |
| `GET /v1/graph/stats` | Node/edge counts, consumer lag |
| `GET /v1/graph/query` | Parameterized Cypher (read-only) |

Writes enter **only** through the NATS consumer — never via API POST.

## Federation with design-time graph

Runtime graph (Starfly) federates with design-time graph (CALM Forge):

- Shared types: `Capability`, `Source`, `TrustDomain`
- `manifests_as` is **computed at query time**, not stored

## Dashboard vs graph

| Surface | Role |
|---------|------|
| [Operations dashboard](dashboard.md) | Human NOC — metrics, SSE, topology |
| **Starfly Graph** | Machine query — lineage, blast radius, shadow agents |

Both are async consumers. Neither blocks exchange.

## Operator checklist

- [ ] Confirm NATS JetStream healthy on fabric unit
- [ ] `GET /v1/graph/stats` or graph `/healthz` — consumer lag near zero
- [ ] Revocation still tested via [sandbox](../../sandbox/run.sh) — graph optional for kill-switch proof

## Status

Graph service code is not in this public export yet. Treat as **integrator / operator** infrastructure — deploy from the Starfly operator workspace when ADR-0031 phases reach your environment.
