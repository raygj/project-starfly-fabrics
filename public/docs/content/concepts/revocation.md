# Revocation

When a credential is compromised, expiry is too slow. Starfly maintains a **revocation index** updated by CAEP/SSF signals and denies exchanges immediately.

## The 30ms invariant

Revocation propagation is the **kill switch**. The fabric must deny revoked identities on the exchange hot path within the documented latency budget (~30ms index lookup). Do not introduce blocking hops on the revocation path.

## Signal flow

```
CAEP session-revoked  →  POST /v1/signals/events  →  policy  →  revocation index
                                                              ↓
                                                    NATS flash → federation peers
```

1. Operator or IdP sends a CAEP event naming the subject (`sub_id.uri`).
2. Starfly accepts (202) after policy check.
3. Index updated — subsequent exchanges for that workload ID return 403.
4. Federation relay propagates hash/state to peers.

## Surgical, not scorched earth

Revocation targets a **workload identity** or tool — not the entire fabric. Clean agents continue exchanging.

## Try it

```bash
./sandbox/run.sh revocation
# or narrated:
./demos/02-real-time-revocation.sh
```

## Federation

Cross-fabric sync uses revocation hashes — no shared DB:

```bash
curl -s http://localhost:8693/v1/federation/revocation-hash | jq
```

Lab sandbox peers to `fabric-alpha` for federation demos (`STARFLY_PROFILE=lab ./sandbox/run.sh federation`).

## Related

- [Glossary: revocation](../glossary.md#revocation--kill-switch)
- [CAEP ingestion](../api/openapi.yaml)
