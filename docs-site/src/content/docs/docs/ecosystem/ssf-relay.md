---
title: SSF Relay
description: Fan CAEP and SSF security events to enterprise sinks — the motor layer after Starfly ingests signals.
---

**Starfly ingests the kill switch; SSF Relay delivers it everywhere your enterprise listens.** After signals hit the PEP, the relay fans out to SIEM, webhooks, and peer fabrics — async, never blocking revocation index update.

## Why it's worth your time

- **Enterprise plumbing** — CAEP `session-revoked` and SSF streams reach Splunk, Sentinel, or custom webhooks
- **Decoupled from PEP** — ingestion stays fast; delivery retries on its own schedule
- **Federation-friendly** — complements cross-fabric hash sync on Starfly

## Relationship to Starfly

```
IdP / operator → POST /v1/signals/events → Starfly (index + NATS)
                                                │
                                          SSF Relay → sinks
```

Starfly owns **acceptance and index**. Relay owns **fan-out**.

## Status

**Preview** — relay service export pending in this repository.

Code stub: [`ssf-relay/`](https://github.com/raygj/project-starfly-fabrics/tree/main/ssf-relay)

## Related

- [Revocation concepts](/docs/docs/concepts/revocation/)
- [Ecosystem overview](/docs/docs/ecosystem/)
- [OpenAPI — signals](https://starfly.dev/api/operations/tags/signals/)
