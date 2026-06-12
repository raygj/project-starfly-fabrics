---
title: Revocation
description: Kill compromised credentials in milliseconds — surgical revocation without stopping the fabric.
slug: 1.0/docs/concepts/revocation
---

**When a credential is compromised, waiting for expiry is not a plan.** Starfly maintains a revocation index fed by CAEP/SSF signals and denies exchanges immediately — surgical, not scorched-earth.

## Why it matters

- **Kill switch, not cooldown** — revoked workloads fail exchange on the next request, not at token expiry.
- **Surgical scope** — revoke one agent or tool; clean identities keep exchanging.
- **Federation-aware** — peers sync revocation state without a shared database.

## How it works

```
CAEP session-revoked  →  POST /v1/signals/events  →  policy  →  revocation index
                                                              ↓
                                                    NATS → federation peers
```

1. Operator or IdP sends a CAEP event naming the subject (`sub_id.uri`).
2. Starfly accepts (202) after policy check.
3. Index updates — subsequent exchanges for that workload return **403**.
4. Federation relay propagates hash and state to peers.

The revocation lookup stays on the fast path (~30ms budget in production fabrics). Do not add blocking hops between signal ingestion and index update.

## Federation without shared state

Cross-fabric sync uses revocation hashes — no central DB:

```bash
curl -s "$STARFLY_URL/v1/federation/revocation-hash" | jq
```

Lab profile: `STARFLY_PROFILE=lab ./sandbox/run.sh federation`

## Try it

```bash
./sandbox/run.sh revocation
```

Narrated demo: [`demos/02-real-time-revocation.sh`](https://github.com/raygj/project-starfly-fabrics/blob/main/demos/02-real-time-revocation.sh)

## Key endpoints

| Path | Purpose |
|------|---------|
| `POST /v1/signals/events` | Ingest CAEP/SSF events |
| `GET /v1/federation/revocation-hash` | Peer sync fingerprint |

Full reference: [OpenAPI — signals](https://starfly.dev/api/operations/tags/signals/).

## Related

- [Exchange](../exchange/)
- [Glossary: revocation](../glossary/#revocation--kill-switch)
- [Operations dashboard](../integrators/dashboard/) — watch CAEP cascade live
- [Documentation voice](../voice/)
