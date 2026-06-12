---
title: Starfly Fabrics ecosystem
description: Starfly is the identity PEP — companions sense, remember, relay, and judge asynchronously, never on the hot path.
slug: 1.0/docs/ecosystem
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
| [Credential patterns](/1.0/docs/ecosystem/integrators/credential-patterns/) | SPIFFE, K8s, Vault, cloud WI feed exchange | Shipped |
| [CALM Forge](/1.0/docs/ecosystem/index/calm-forge/) | Design-time graph — what workloads *should* do | Satellite — [project-calm-forge](https://github.com/raygj/project-calm-forge) |
| [Starfly Graph](/1.0/docs/ecosystem/integrators/starfly-graph/) | Runtime memory — lineage, blast radius | Preview |
| [Dashboard](/1.0/docs/ecosystem/integrators/dashboard/) | Human NOC — metrics, SSE, federation watch | Preview |
| [Reflector](/1.0/docs/ecosystem/index/reflector/) | eBPF senses — observe MCP/tool traffic on the platform | Preview — [workload-ebpf-reflector](https://github.com/raygj/workload-ebpf-reflector) |
| [SSF Relay](/1.0/docs/ecosystem/index/ssf-relay/) | Motor layer — fan CAEP/SET to enterprise sinks | Preview |
| [Reasoner](/1.0/docs/ecosystem/index/reasoner/) | Coherence — design vs runtime drift, shadow agents | Preview |
| [LPA Crypto Heart](/1.0/docs/ecosystem/index/lpa-crypto-heart/) | Signed policy bundles and provenance heartbeats | Preview |

## Layers (how to think about it)

| Layer | Question it answers | Members |
|-------|---------------------|---------|
| **Upstream** | Who attested this workload? | SPIFFE/SPIRE, K8s, Vault OIDC, cloud WI → [credential patterns](/1.0/docs/ecosystem/integrators/credential-patterns/) |
| **Core** | What token may leave the fabric? | **Starfly PEP** |
| **Memory & ops** | What happened? What should have? | Graph, Dashboard, CALM Forge |
| **Sense & motion** | What does the platform see? Where do signals go? | Reflector, SSF Relay |
| **Judgment** | Does runtime match intent? | Reasoner |
| **Provenance** | Is policy tamper-evident? | LPA Crypto Heart |

## Start here

1. [Getting started](/1.0/docs/ecosystem/getting-started/) — first WIMSE JWT in 15 minutes  
2. [How the fabric thinks](/1.0/docs/ecosystem/concepts/how-the-fabric-thinks/) — determinism, graphs, autonomic loop  
3. [Integrators](/1.0/docs/ecosystem/integrators/token-exchange/) — wire agents and tools  
4. Pick **one** companion when you have a concrete need — not all at once  

## Related

- [Glossary](/1.0/docs/ecosystem/glossary/)
- [Documentation voice](/1.0/docs/ecosystem/voice/)
