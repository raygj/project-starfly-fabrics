---
title: Trust domains
description: The inbound identity plane — how Starfly knows which credential to trust before minting a JWT.
slug: 1.0/docs/concepts/trust-domains
---

**Before Starfly mints a JWT, it must know which identity plane the credential came from.** Trust domains are that inbound boundary — the validator, policy slice, and subject namespace that apply to the credential you present.

## Why it matters

- **Many platforms, one fabric** — K8s service accounts, OIDC issuers, SPIFFE, cloud IAM each map to a trust domain.
- **Prevents category errors** — trust domain (`td`) answers *who sent this*; audience (`aud`) answers *who may receive the JWT*.
- **MCP security depends on it** — same trust domain, different tools still need different `aud` values.

## Trust domain vs audience

The most confused pair in NHI work:

```
┌─────────────────────────────────────────────────────────────┐
│  INBOUND (trust domain)          OUTBOUND (audience)        │
│  "Who sent this credential?"     "Who may receive this JWT?" │
│  td claim on issued JWT          aud claim on issued JWT     │
│  Fabric configuration            Requested at exchange time  │
└─────────────────────────────────────────────────────────────┘
```

**Example:** A K8s service account from cluster `prod` exchanges for audience `https://analytics.example.com`.

- **Trust domain** — how Starfly validated the SA (cluster trust, namespace, name).
- **Audience** — the analytics API; the only downstream resource this JWT targets.

A token with `aud` for tool A must not work at tool B — even when both tools sit in the same trust domain. That is the confused-deputy fix in [MCP security](/1.0/docs/concepts/integrators/mcp/).

## Dev mode

```bash
./bin/starfly --dev
```

Uses synthetic `dev.local`. Stub JWTs in [getting started](/1.0/docs/concepts/getting-started/) exercise exchange without a real IdP.

## Production configuration

Declare trust domains in fabric configuration (Helm values or [Terraform provider](https://starfly.dev/terraform/)). Each enabled domain activates validators and policy paths for credentials from that plane.

## Try it

```bash
./sandbox/run.sh exchange
```

Watch `td` on the issued JWT — [token exchange integrator guide](/1.0/docs/concepts/integrators/token-exchange/).

## Related

- [Glossary: trust domain vs audience](/1.0/docs/concepts/glossary/#audience)
- [Exchange](/1.0/docs/concepts/exchange/)
- [Documentation voice](/1.0/docs/concepts/voice/)
