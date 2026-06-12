---
title: Vault as PEP with external PDP
description: One Sentinel rule calls OPA — Vault issues scoped agent credentials or it does not. Policy scales without policy sprawl.
slug: 1.0/docs/integrators/vault-pep-pdp
---

**Stop writing thousands of Sentinel policies per agent.** Vault stays the enforcement point closest to secrets and dynamic credentials; OPA (or your existing policy engine) stays the decision point. One Endpoint Governing Policy, one HTTP call, binary outcome — issue the token or don't.

This is the upstream seam in [credential patterns](credential-patterns/): Vault attests and issues; Starfly mints WIMSE downstream when the fabric needs revocation, audience binding, and federation.

## Why it's worth your time

- **Policy complexity is the blocker** — building blocks exist; per-agent Sentinel sprawl does not scale as agent adoption grows.
- **Enforcement stays at the vault** — decisions happen where secrets are issued, not through a distant gateway that adds latency and a new SPOF.
- **Agents must not hold long-lived credentials** — short-lived, scope-bound tokens with full audit attribution; credential separation via sidecar or gateway injection.
- **Delegation depth is infrastructure** — multi-hop `act` chains enforced at issuance, not trusted because the application said so.

## Architecture

```
Agent identity (AppRole / JWT / K8s auth)
        │
        ▼
┌───────────────────┐
│ Vault auth        │  bind principal, scope, delegation metadata
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Sentinel EGP        │  single rule — http import to external PDP
│ (one rule)          │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ OPA / policy engine │  evaluate payload → 200 + allow, or deny
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Vault issues        │  short-lived token + metadata (principal, intent, chain)
│ or denies           │  full audit log on the PEP
└───────────────────┘
```

**Vault = PEP.** It performs the irreversible act.  
**OPA = PDP.** It returns allow/deny (and optional constraints).  
Policy growth happens in Rego, not in Vault configuration churn.

## The Sentinel contract

Sentinel's job is orchestration, not encoding every agent scenario:

```python
import "http"
import "json"

payload = json.marshal({
    "agent_id":         request.data.agent_id,
    "requested_scope":  request.data.requested_scope,
    "principal":        identity.entity.metadata.principal,
    "delegation_chain": identity.entity.metadata.delegation_chain,
    "auth_method":      request.auth.accessor,
    "timestamp":        time.now,
})

resp = http.post("https://policy-engine.internal/evaluate", {
    "body":    payload,
    "headers": {"Content-Type": "application/json"},
})

main = rule { resp.status_code == 200 and resp.body.decision == "allow" }
```

| Response | Vault behavior |
|----------|----------------|
| `200` + `decision: allow` | Issue scoped token / secret |
| Anything else | Deny — fail closed by default |

Include a **correlation ID** in the payload and response so Vault audit logs and PDP evaluation logs stitch together.

## Guardrails (absolute, in Sentinel)

These run **regardless** of PDP outcome — non-negotiable boundaries:

| Guardrail | What it enforces |
|-----------|------------------|
| Agent TTL ceiling | Agent tokens cannot exceed org max (e.g. 15 min) |
| Delegation depth cap | `delegation_chain` cannot exceed N hops |
| Scope monotonicity | Scope may narrow per hop, never widen |
| Jurisdiction / recording | Agent sessions meet compliance constraints (e.g. Boundary recording) |

The PDP handles intent and context. Sentinel guardrails handle physics.

## Delegation chain (RFC 8693)

Multi-hop on-behalf-of uses nested `act` claims — audit provenance in the token, flattened `delegation_chain` in the PDP payload:

```json
{
  "sub": "<user-entity-id>",
  "aud": "<target-service>",
  "scope": "resource:read",
  "act": {
    "client_id": "agent-b",
    "sub": "<agent-b-entity>",
    "act": {
      "client_id": "agent-a",
      "sub": "<agent-a-entity>"
    }
  }
}
```

Only the top-level actor is validated against the subject's `may_act` claim. Nested `act` carries lineage for forensics. Starfly exchange uses the same RFC 8693 vocabulary when minting WIMSE — the wire shape stays consistent across vault and fabric.

**Token type URIs:** `id_token` (subject), `jwt` (actor), `access_token` (delegated output).

## Compose with Starfly

Two PEPs, one policy vocabulary:

| Layer | Question | Output |
|-------|----------|--------|
| **Vault PEP** | May this agent receive vault material / IdP token? | Scoped secret or OIDC token |
| **Starfly PEP** | May this credential leave the fabric as WIMSE? | Audience-bound JWT + revocation |

```
Agent ──► Vault (Sentinel → OPA) ──► dynamic cred / IdP token
              │
              └──► Starfly exchange (OPA) ──► WIMSE JWT
```

Your in-house token exchange or Starfly can **be** the PDP Vault calls — same team, same Rego, new architecture. Vault becomes the PEP you already operate at scale.

The [OIDC plugin](credential-patterns/#vault-oidc-plugin-preview) adds IdP bridge mode when downstream APIs require Azure/Okta/Google tokens. FIAM preflight runs **before** the IdP request — role-level context gates, analogous to PDP input shaping.

## Observation feeds policy (autonomic loop)

Behavioral signals — [Reflector](../ecosystem/reflector/) wire truth, [SSF Relay](../ecosystem/ssf-relay/) CAEP fan-out, SIEM alerts — feed the PDP as **policy information**, not as enforcement. Discovery → observation → policy refinement → Vault enforces on the next issuance. That is the entitlement development lifecycle without LLM guesswork at the seam.

[Reasoner](../ecosystem/reasoner/) answers a different question: does runtime match declared architecture? PDP + Reasoner + graphs share typed evidence when CALM Forge leaf nodes federate with Starfly Graph.

## Operations

| Concern | Guidance |
|---------|----------|
| PDP availability | Deploy HA; default **fail-closed** on engine timeout |
| Latency | Co-locate PDP with Vault; cache repeated decisions where safe |
| Engine compromise | mTLS between Vault and PDP; engine behind network policy |
| Audit | Correlate Vault audit + PDP eval logs via shared request ID |

## Standards alignment

| Standard | Fit |
|----------|-----|
| IETF agentic auth drafts | Policy out of scope for standardization — PEP/PDP split matches |
| WIMSE workload credentials | Vault-issued scoped tokens + Starfly exchange for fabric JWTs |
| RFC 8693 token exchange | Delegation chain wire format |
| NIST ABAC | Classic PEP / PDP / PIP separation |
| OpenID SSF / CAEP | Continuous evaluation signals feed PDP input |

## Status

**Preview** — Sentinel http import and OPA PDP pattern documented; OIDC plugin export stub: [`providers/oidc-engine/`](https://github.com/raygj/project-starfly-fabrics/tree/main/providers/oidc-engine).

## Related

- [How the fabric thinks](../concepts/how-the-fabric-thinks/) — determinism boundary
- [Credential patterns](credential-patterns/) — full upstream composition
- [Token exchange](token-exchange/) — Starfly PEP downstream
- [Ecosystem overview](../ecosystem/)
