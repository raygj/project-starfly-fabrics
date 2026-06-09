---
title: Trust Domains
slug: 1.0/docs/concepts/trust-domains
---

# Trust domains

A trust domain is Starfly's name for the **issuer-side boundary** — the zone of identity Starfly trusts when validating an incoming credential.

## Why it exists

Workloads arrive with credentials from many platforms: Kubernetes service accounts, OIDC issuers, SPIFFE trust domains, cloud IAM. Starfly must know **which validator, which policy slice, and which subject namespace** apply before minting a WIMSE JWT.

The trust domain answers: *"This credential belongs to identity plane X."*

## Trust domain vs audience

These are the most confused pair in NHI docs.

```
┌─────────────────────────────────────────────────────────────┐
│  INBOUND (trust domain)          OUTBOUND (audience)        │
│  "Who sent this credential?"     "Who may receive this JWT?" │
│  td claim on issued JWT          aud claim on issued JWT     │
│  Configured in Starfly           Requested at exchange time  │
└─────────────────────────────────────────────────────────────┘
```

**Example:** A K8s SA from cluster `prod` exchanges for audience `https://analytics.example.com`.

* Trust domain: maps to how Starfly validated the SA (cluster trust, namespace, SA name).
* Audience: the analytics API — the only downstream resource this JWT targets.

Conflating them breaks MCP security: a token with `aud` for tool A must not work at tool B even if both sit in the same trust domain.

## Dev mode

`./bin/starfly --dev` uses synthetic `dev.local`. Stub JWTs in [getting started](../getting-started.md) exercise exchange without a real IdP.

## Configuration

Production fabrics declare trust domains in Helm values (`starfly.trustDomains`). Each enabled domain activates validators and policy paths for credentials from that plane.

## Related

* [Glossary: trust domain vs audience](../glossary.md#audience)
* [Token exchange integrator guide](../integrators/token-exchange.md)
