---
title: Reasoner
description: Coherence engine — compare design-time intent (CALM Forge) with runtime behavior (Starfly Graph).
---

**Ask whether runtime matches architecture** — shadow agents, drifted capabilities, resilience gaps — without blocking a single exchange.** The Reasoner queries federated graph state and returns coherence judgments for operators and automation.

## Why it's worth your time

- **Shadow workloads** — agents active in production with no CALM Forge declaration
- **Drift signal** — declared vs observed capabilities diverge
- **Automation-ready** — MCP/API queries for agents that triage before humans open a ticket

## Relationship to Starfly

| Source | Provides |
|--------|----------|
| **CALM Forge** | Workload, Policy, Placement (design) |
| **Starfly Graph** | Agent, Exchange, ToolCall (runtime) |
| **Reasoner** | `query_coherence`, shadow, gap analysis |

Starfly PEP does not run coherence checks on the exchange path. Reasoner is a **consumer** of graph federation APIs.

## Status

**Preview** — reasoner export pending in this repository.

Code stub: [`reasoner/`](https://github.com/raygj/project-starfly-fabrics/tree/main/reasoner)

## Related

- [How the fabric thinks](/concepts/how-the-fabric-thinks/) — determinism vs probabilism, autonomic loop
- [CALM Forge](/docs/calm-forge/)
- [Starfly Graph](/integrators/starfly-graph/)
- [Ecosystem overview](/docs/)
