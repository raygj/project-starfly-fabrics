---
title: Starfly Fabrics ecosystem
description: Starfly is the identity PEP — companions sense, remember, relay, and judge asynchronously, never on the hot path.
---

**Starfly alone is enough.** Everything on this page is optional — companions that extend the fabric when you are ready. None of them sit on the exchange or revocation hot paths.

## The map

```
     [ Reflector · SSF Relay · Reasoner · CALM Forge ]
                  async · sense · relay · judge
                            │
           [ Graph · Dashboard · LPA Crypto Heart ]
                  memory · watch · signed policy
                            │
                    ┌───────────────┐
                    │    Starfly    │  ← deploy this first
                    │  identity PEP │
                    └───────────────┘
                            ▲
        [ Credential patterns · SPIFFE · K8s · Vault · cloud ]
                  upstream issuers (public) → private PEP (WIMSE)
```

## Companion picker

| Companion | Why it exists | Status |
|-----------|---------------|--------|
| **Starfly** | Exchange, revoke, MCP verify — the fabric core | **Shipped** — [this repo](https://github.com/raygj/project-starfly-fabrics) |
| [Credential patterns](../integrators/credential-patterns.md) | SPIFFE, K8s, Vault, cloud WI feed exchange | Shipped |
| [CALM Forge](calm-forge.md) | Design-time graph — what workloads *should* do | Partner — [project-calm-forge](https://github.com/raygj/project-calm-forge) |
| [Starfly Graph](../integrators/starfly-graph.md) | Runtime memory — lineage, blast radius | Preview |
| [Dashboard](../integrators/dashboard.md) | Human NOC — metrics, SSE, federation watch | Preview |
| [Reflector](reflector.md) | eBPF senses — observe MCP/tool traffic on the platform | Preview — [workload-ebpf-reflector](https://github.com/raygj/workload-ebpf-reflector) |
| [SSF Relay](ssf-relay.md) | Motor layer — fan CAEP/SET to enterprise sinks | Preview |
| [Reasoner](reasoner.md) | Coherence — design vs runtime drift, shadow agents | Preview |
| [LPA Crypto Heart](lpa-crypto-heart.md) | Signed policy bundles and provenance heartbeats | Preview |

## Layers (how to think about it)

| Layer | Question it answers | Members |
|-------|---------------------|---------|
| **Upstream** | Who attested this workload? | SPIFFE/SPIRE, K8s, Vault OIDC, cloud WI → [credential patterns](../integrators/credential-patterns.md) |
| **Core** | What token may leave the fabric? | **Starfly PEP** |
| **Memory & ops** | What happened? What should have? | Graph, Dashboard, CALM Forge |
| **Sense & motion** | What does the platform see? Where do signals go? | Reflector, SSF Relay |
| **Judgment** | Does runtime match intent? | Reasoner |
| **Provenance** | Is policy tamper-evident? | LPA Crypto Heart |

## Start here

1. [Getting started](../getting-started.md) — first WIMSE JWT in 15 minutes  
2. [Integrators](../integrators/token-exchange.md) — wire agents and tools  
3. Pick **one** companion when you have a concrete need — not all at once  

## Related

- [Glossary](../glossary.md)
- [Documentation voice](../VOICE.md)
