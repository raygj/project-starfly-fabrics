---
title: How the fabric thinks
description: Where Starfly draws the line between deterministic enforcement and probabilistic assistance — and how the autonomic loop closes.
---

**Some decisions must never be guessed.** Identity issuance, policy allow/deny, revocation, and whether runtime matches declared architecture are deterministic. Natural language intake, remediation narratives, and triage summaries are probabilistic. The fabric keeps them on opposite sides of a hard boundary.

## The boundary

| Zone | Who decides | Examples |
|------|-------------|----------|
| **Deterministic** | Typed graphs, OPA/Rego, PEPs | Exchange allow/deny, Vault secret issuance, shadow-agent detection, capability ceiling checks |
| **Probabilistic** | LLM-assisted intake | CALM interview, drift summaries, change proposals for human review |

The LLM is a **translator**, not a judge. It helps you declare intent in CALM. It does not decide whether a workload may run, a token may issue, or a connection may leave the node.

Guessing at identity or policy is how shadow agents look legitimate and breaches read fine in a chat log.

## Two graphs, one seam

Design-time and runtime each own their leaf nodes:

| Graph | When | Leaf nodes (examples) |
|-------|------|------------------------|
| [CALM Forge](../ecosystem/calm-forge.md) | Intent declared | `Workload`, `Capability`, `TrustDomain`, `Placement` |
| [Starfly Graph](../integrators/starfly-graph.md) | Fabric observed | `Agent`, `Exchange`, `ToolCall`, `Delegation` |

Shared types (`Capability`, `Source`, `TrustDomain`) are the vocabulary. The `manifests_as` relationship is **computed at query time** when graphs federate — not stored twice, not LLM-inferred.

[Reasoner](../ecosystem/reasoner.md) sits on that seam: *does what happened match what was declared?*

## Three PEPs, one policy muscle

The same enforcement shape repeats at different boundaries:

```
Workload ──► Vault PEP (Sentinel → OPA) ──► secret / IdP token
                    │
                    └──► Starfly PEP (exchange → OPA) ──► WIMSE JWT
                              │
                    Reasoner (graph query) ──► coherence / shadow / drift
```

- **Vault** answers: may this identity receive vault material?
- **Starfly** answers: may this credential become a scoped outbound token?
- **Reasoner** answers: does runtime match architecture?

Each PEP fails closed when its PDP is unreachable. None of them call an LLM.

See [Credential patterns](../integrators/credential-patterns.md) for how Vault and Starfly compose upstream.

## The autonomic loop

The vision is self-regulating infrastructure — observe, evaluate, reconcile — without putting a human on every Tuesday-morning SPIFFE mismatch.

```
observe   Reflector, Starfly Graph, Vault audit, dashboard
    ↓
evaluate  Reasoner + OPA (deterministic drift factors)
    ↓
act       revoke, TC drop, reconcile, escalate
    ↓
re-author CALM front door (LLM helps translate; graph validates)
```

When drift clears threshold, a structured **change proposal** re-enters CALM authoring — not a Slack thread, not a model improvising policy. Humans stay in the loop for judgment calls and novel situations, not for repeatable graph truth.

## What Starfly alone guarantees

You can deploy only Starfly and get a correct PEP: exchange, revocation, MCP verify. The autonomic arc completes when you add satellites — [CALM Forge](../ecosystem/calm-forge.md) for intent, [Reasoner](../ecosystem/reasoner.md) for coherence, [Reflector](../ecosystem/reflector.md) for wire truth — all **async**, none on the exchange or revocation hot paths.

**Starfly alone is enough.** The full loop is optional depth for teams ready to close intent → enforcement → reconciliation.

## Related

- [Ecosystem overview](../ecosystem/index.md) — fabric map
- [Reasoner](../ecosystem/reasoner.md) — coherence engine
- [CALM Forge](../ecosystem/calm-forge.md) — design-time graph satellite
- [Documentation voice](../VOICE.md) — how we write for integrators
