# Exchange

Starfly's core job: validate a workload credential, evaluate OPA policy, mint a short-lived WIMSE JWT.

## Flow

```
Workload credential  →  POST /v1/exchange/token  →  WIMSE JWT
     (inbound)              OPA + validators           (outbound, aud-scoped)
```

1. Client sends RFC 8693 token exchange request.
2. Starfly identifies credential type (`subject_token_type`).
3. Validators check signature, expiry, and trust domain match.
4. OPA policy (`policies/`) allows or denies.
5. Starfly signs a WIMSE JWT with `sub`, `aud`, `td`, `exp`, optional delegation claims.

## The 124ns invariant

The exchange **hot path** — lookup, policy eval, sign — is optimized for sub-millisecond end-to-end latency in production fabrics. **Do not add synchronous dependencies** (remote calls, blocking I/O) to this pipeline without an explicit ADR.

Background work (graph updates, behavioral profiling, federation relay) runs on **NATS consumers**, not in the exchange request path.

## Dev vs production

| Mode | Credential | Policy |
|------|------------|--------|
| `--dev` | Stub JWTs accepted | `policies/dev/` permissive |
| Production | Real platform credentials | Operator-authored Rego |

## Endpoints

| Path | Purpose |
|------|---------|
| `POST /v1/exchange/token` | Exchange |
| `GET /v1/identity/jwks` | Verify issued tokens |
| `GET /metrics` | `starfly_exchange_*` histograms |

## Try it

```bash
make build-dev && ./bin/starfly --dev
./sandbox/run.sh exchange
```

## Related

- [Getting started](../getting-started.md)
- [Integrator: token exchange](../integrators/token-exchange.md)
