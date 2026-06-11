---
title: Credential patterns
description: Platform credentials and public issuers compose with Starfly — SPIFFE, Kubernetes, credential vaults, and cloud identity feed exchange; Starfly mints WIMSE.
slug: 1.0/docs/integrators/credential-patterns
---

**Starfly mints WIMSE JWTs; it does not replace how you attest workloads or satisfy downstream IdPs.** These patterns show what feeds `POST /v1/exchange/token` — and when you chain a **public issuer** with the **private PEP**.

## The seam

```
Platform credential          Starfly PEP              Downstream
(public issuer)              (private broker)         (aud-scoped)
      │                            │                        │
 SPIFFE SVID ──────────────► exchange/token ──────────► WIMSE JWT
 K8s SA JWT ───────────────►      │                 ──► tool / API
 Vault → IdP token ──(opt)──►     │                 ──► MCP verify
 Cloud WI token ───────────►      │                 ──► federation
```

Starfly is always the **outbound** broker: scoped `aud`, `td`, revocation, audit. Upstream issuers prove *who the workload is*; Starfly decides *what token may leave*.

## Pattern picker

| Pattern | Upstream proves | Starfly adds | Status |
|---------|-----------------|--------------|--------|
| [SPIFFE / SPIRE](#spiffe--spire) | Workload identity (attestation) | WIMSE + policy + kill switch | Shipped |
| [Kubernetes SA](#kubernetes-service-account) | Pod identity (platform JWT) | Same | Shipped |
| [Vault OIDC plugin](#vault-oidc-plugin-preview) | External IdP token (Azure, Okta, …) | Optional WIMSE layer | Preview |
| [Cloud workload identity](#cloud-workload-identity) | AWS / GCP / Azure runtime cred | Same | Shipped |

---

## SPIFFE / SPIRE

**Why it's worth your time:** SPIFFE is the OG universal workload identity vocabulary — `spiffe://` is in WIMSE for a reason. SPIRE attests the workload; Starfly adds governance Starfly alone does not claim to replace.

**Roles:**

| Layer | Component | Job |
|-------|-----------|-----|
| Attestation | SPIRE (or compatible) | Issue X.509 or JWT **SVID** after workload proof |
| Broker | Starfly PEP | Exchange SVID → **WIMSE JWT** with `aud`, delegation, revocation |

SPIRE is a **complement**, not a replacement. Do not expect SPIRE to enforce MCP audience, CAEP kill switch, or cross-fabric federation — that is the fabric.

**Exchange:**

```bash
curl -s -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<JWT-SVID or presented SVID>",
    "subject_token_type": "urn:starfly:token-type:spiffe-svid",
    "audience": "https://api.target.example.com"
  }' | jq
```

Trust domains often mirror SPIFFE trust domains (`spiffe://production.example.com`). See [trust domains](../concepts/trust-domains.md).

**Code:** [`pkg/identity/spiffe/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/identity/spiffe)

---

## Kubernetes service account

**Why it's worth your time:** Fastest path on-cluster — the pod already has a projected SA token; Starfly exchanges it without a parallel identity stack.

```bash
curl -s -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<K8S_SA_JWT>",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "audience": "https://mcp.example.com/tools/search"
  }' | jq
```

Pair with [MCP security](mcp.md) when `audience` is a tool `resource_uri`.

**Code:** [`pkg/identity/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/identity) (Kubernetes validators in production fabrics)

---

## Vault OIDC plugin (Preview)

**Why it's worth your time:** Some targets **only** accept tokens from Azure AD, Okta, or Google — not your fabric JWKS. A credential vault can broker that IdP token while Starfly still governs fabric-side access.

**Two modes — do not conflate:**

| Mode | Flow | Output |
|------|------|--------|
| **IdP bridge** | Workload → Vault auth → OIDC plugin → **IdP-native token** | Token the IdP signed (downstream trusts IdP) |
| **Fabric compose** | IdP token (or other cred) → **Starfly exchange** → WIMSE JWT | Fabric-governed outbound token |

Mode 1 solves *"the API wants Azure."* Mode 2 solves *"the fabric wants revocation, audience, and audit."* You can chain them when both are true.

```
Workload ──► Vault ──► OIDC plugin ──► IdP access token
                              │
                              └──(optional)──► Starfly exchange ──► WIMSE JWT
```

**Status:** Preview — plugin lives in operator workspace; public export stub: [`providers/oidc-engine/`](https://github.com/raygj/project-starfly-fabrics/tree/main/providers/oidc-engine).

FIAM signaling (preflight + claim enrichment) sits **before** the IdP request — analogous in spirit to OPA on the Starfly side, but on the vault path.

---

## Cloud workload identity

**Why it's worth your time:** AWS, GCP, and Azure already issue short-lived runtime credentials — exchange them instead of inventing a parallel bootstrap.

| Cloud | `subject_token_type` |
|-------|----------------------|
| AWS | `urn:starfly:token-type:aws-sts` |
| GCP | `urn:starfly:token-type:gcp-wif` |
| Azure | `urn:starfly:token-type:azure-mi` |

Full enum: [OpenAPI — exchange](https://starfly.dev/api/operations/exchangetoken/).

---

## After exchange

| Goal | Doc |
|------|-----|
| Tool-scoped token | [MCP security](mcp.md) |
| Multi-protocol middleware | [UTC](utc.md) |
| Kill compromised cred | [Revocation](../concepts/revocation.md) |

## Related

- [Token exchange](token-exchange.md) — wire-up guide
- [Glossary: WIMSE JWT](../glossary.md#wimse-jwt)
- [Documentation voice](../VOICE.md)
