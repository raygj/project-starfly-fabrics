---
title: CALM Forge
description: Design-time architecture graph — declare workloads, capabilities, and placement; federate with Starfly's runtime graph.
---

**Know what workloads were *designed* to do — and compare it to what agents *actually* did at runtime.** CALM Forge is the design-time half of the federated semantic graph; Starfly Graph is the runtime half.

## Why it's worth your time

- **Architecture SoR** — workloads, capabilities, policies, placement in one queryable graph
- **Federation seam** — shared vocabulary with Starfly (`Capability`, `Source`, `TrustDomain`); `manifests_as` computed at query time
- **Shadow detection** — agents with no matching declared workload surface in cross-graph queries

Starfly does not replace CALM Forge. Starfly mints WIMSE and records runtime events; CALM Forge holds intent.

## Relationship to Starfly

| Graph | When | Store |
|-------|------|-------|
| **CALM Forge** | Design time | Satellite repo (Kuzu local / scale-out) |
| **Starfly Graph** | Runtime | Preview in Starfly export |

Handshake and shared ontology: federated via ADR-0024 types — see [Starfly Graph integrator guide](/docs/docs/integrators/starfly-graph/).

## Repository

**Satellite** — [github.com/raygj/project-calm-forge](https://github.com/raygj/project-calm-forge)

Same fabric vision, separate repo — design-time graph and intent compilation.

## Related

- [Ecosystem overview](/docs/docs/ecosystem/)
- [Starfly Graph](/docs/docs/integrators/starfly-graph/)
- [Reasoner](/docs/docs/ecosystem/reasoner/) — consumes federated graph state
