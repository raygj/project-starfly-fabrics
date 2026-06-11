---
title: LPA Crypto Heart
description: Signed policy bundles and provenance heartbeats — tamper-evident policy state for the fabric.
slug: 1.0/docs/ecosystem/lpa-crypto-heart
---

**Know policy bundles were not tampered with between compile and load** — signed artifacts, published hashes, and heartbeats that tie runtime units to declared intent.

## Why it's worth your time

- **Supply-chain for policy** — OPA bundles signed before fabric units load them
- **Provenance** — heartbeats link a running PEP to a known policy generation
- **Pairs with CALM Forge** — compiled intent becomes verifiable runtime state

## Relationship to Starfly

```
CALM Forge (compile) → signed bundle (LPA) → Starfly unit verifies hash → loads policy
                              │
                         heartbeats → graph / audit
```

Exchange and revocation do not wait on signing — verification happens at bundle load and on schedule.

## Status

**Preview** — LPA crypto heart export pending in this repository.

Code stub: [`lpa-crypto-heart/`](https://github.com/raygj/project-starfly-fabrics/tree/main/lpa-crypto-heart)

## Related

- [Exchange concepts](../concepts/exchange.md) — OPA on the hot path uses loaded bundles
- [CALM Forge](calm-forge.md)
- [Ecosystem overview](index.md)
