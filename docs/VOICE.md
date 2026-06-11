---
title: Documentation voice
description: How Starfly docs should read on starfly.dev and in this repository.
---

Editorial lane for public documentation. Architecture decisions live in ADRs (private workspace); user-facing docs lead with outcomes.

## Lead with outcomes

Every page opens with **why this is worth your time** — one or two sentences a busy integrator or operator can skim.

| Weak | Strong |
|------|--------|
| "ADR-0022 introduces a protocol abstraction layer." | "Call the same tool from MCP, REST, or A2A with one token and one audit trail." |
| "The graph is a NATS consumer to FalkorDB." | "Ask who an agent reached, through what delegation chain, without touching the exchange path." |

Then: how it works → how to wire it → where the code lives.

## Naming

| Term | Use when |
|------|----------|
| **Starfly** | Product, fabric, PEP |
| **Fabric unit** | A running Starfly deployment |
| **WIMSE JWT** | Agent credential after exchange |
| **UTC** | Universal Tool-Calling Layer (spell out once per page) |
| **Preview** | Docs live; code or export not GA yet |

Avoid: ADR numbers, commune paths, "operator workspace," vendor names in committed prose.

## Status badges

| Badge | Meaning |
|-------|---------|
| *(none)* | Shipped in this repo |
| **Preview** | Integrator doc is canonical; code stub or partial export |
| **Satellite** | Sibling repo in the Starfly Fabrics ecosystem (e.g. CALM Forge) |

One badge per page max. No phase gates or sprint language in user-facing copy.

## Links

- **Docs** → `starfly.dev/1.0/docs/...` or relative paths in-repo
- **Code** → `github.com/raygj/project-starfly-fabrics/tree/main/<path>`
- **Never** → `communes/starfly/...`, private monorepo, mandala-fiam handshakes

If code is not exported yet, link to a **stub README** at the public path (see `dashboard/README.md`).

## Invariants (say once, plainly)

1. Token exchange stays fast — nothing new blocks the exchange pipeline.
2. Revocation stays fast — kill-switch propagation is not negotiable.

Async surfaces (dashboard, graph, UTC middleware) must state they are **off the hot path**.

## Page shape (integrators)

```
Outcome (1–2 sentences)
Why it's worth your time (3 bullets)
How it works (diagram or short flow)
Wire it up (numbered steps)
Code in this repo (links)
Related docs
```

## Review checklist

- [ ] First paragraph answers "why should I care?"
- [ ] No ADR or internal path leakage
- [ ] Every code link resolves in this public repo
- [ ] Preview components link to stub README + integrator doc
- [ ] Tone: precise, calm, no hype
