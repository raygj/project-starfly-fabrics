---
title: Reflector
description: eBPF platform senses — observe MCP and tool traffic without touching the Starfly exchange path.
---

**See what agents actually call on the platform — MCP sessions, tool latency, denials — from the kernel up.** Reflector is the sense layer: eBPF observers that wrap the platform without the platform knowing it is being secured.

## Why it's worth your time

- **Ground truth at the wire** — complement PEP audit with host-level visibility
- **Zero hot-path coupling** — Starfly exchange and revocation unchanged; reflector consumes and exports
- **Pairs with dashboard** — metrics and events feed the same NOC mental model

## Relationship to Starfly

```
Agent → tool call → platform network
                         │
                    Reflector (eBPF) → metrics / events
                         │
                    Starfly PEP (parallel) → identity / policy
```

Reflector does not mint WIMSE. Starfly does not load eBPF programs. Sovereign concerns.

## Status

**Preview** — DaemonSet and sidecar export pending in this repository.

Code stub: [`reflector/`](https://github.com/raygj/project-starfly-fabrics/tree/main/reflector)

## Related

- [Ecosystem overview](index.md)
- [Operations dashboard](../integrators/dashboard.md)
- [UTC](../integrators/utc.md)
