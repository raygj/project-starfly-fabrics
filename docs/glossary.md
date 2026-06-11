---
title: Glossary
description: Starfly terms in plain language — the vocabulary for docs, agents, and the ops dashboard.
---

**Shared vocabulary for humans, agents, and the dashboard AI bar.** If two terms sound alike — trust domain vs audience, fabric vs unit — start here before diving into integrator guides.

## Quick reference

| Term | One-line meaning |
|------|------------------|
| [Trust domain](#trust-domain) | Inbound identity plane (`td`) |
| [Audience](#audience) | Outbound target (`aud`) |
| [Token exchange](#token-exchange) | Credential in → WIMSE JWT out |
| [Revocation](#revocation--kill-switch) | Immediate deny for compromised IDs |
| [PEP](#pep-policy-enforcement-point) | Starfly at runtime |
| [UTC](#utc-universal-tool-calling-layer) | One verifier, many protocols |

---

## Trust domain

**Why you care:** Starfly must know *which platform credential* you presented before it mints a JWT.

The issuer-side identity boundary. Names who Starfly believes issued the inbound credential and which validators and policy bundle apply.

- Configured in fabric config (dev: synthetic `dev.local`; production: Helm or [Terraform](https://starfly.dev/terraform/)).
- Appears as the `td` claim on issued WIMSE JWTs.

Deep dive: [trust domains](concepts/trust-domains.md).

## Audience

**Why you care:** A valid token should only work at the resource you scoped — not at a lookalike tool or API.

The downstream resource a token may reach — API URL, MCP `resource_uri`, or service identifier.

- Requested at exchange via the `audience` field (RFC 8693).
- Appears as the `aud` claim on the issued JWT.
- MCP binds `aud` to one tool; using it elsewhere is a [confused deputy](integrators/mcp.md).

| Term | Question it answers |
|------|---------------------|
| Trust domain | *Where did this identity come from?* |
| Audience | *What is this token allowed to call?* |

## Fabric unit

One running Starfly PEP — StatefulSet pod, local `bin/starfly`, or lab sandbox. Identified by `unit_id` in `/v1/sys/health`.

## Fabric

A logical security domain: one or more fabric units sharing policy, revocation state, and optional federation peers. Lab examples: `fabric-alpha`, `fabric-sandbox`.

## PEP (Policy Enforcement Point)

**Why you care:** This is what you deploy — the runtime that secures agents without replacing your IdP.

Starfly's runtime role: validate credentials, evaluate OPA policy, mint WIMSE JWTs, verify MCP audience, ingest CAEP/SSF signals, maintain the revocation index.

Starfly is **not** an identity provider. It routes identity: supported credential in, scoped JWT out.

## WIMSE JWT

Workload Identity in Multi-System Environments — the issued token profile. Short-lived, audience-bound, signed by Starfly's keys. Verify via `GET /v1/identity/jwks`.

Starfly **issues** WIMSE; SPIFFE SVIDs, K8s tokens, and IdP tokens are common **inputs** to exchange — not alternate WIMSE implementations. See [credential patterns](integrators/credential-patterns.md).

## Token exchange

RFC 8693 at `POST /v1/exchange/token`. Trade a platform credential (K8s SA, OIDC, SPIFFE, stub JWT in dev) for a WIMSE JWT.

Guide: [token exchange integrator](integrators/token-exchange.md) · Concepts: [exchange](concepts/exchange.md).

## Delegation

An agent acting on behalf of another principal. Reflected in delegation depth and chain claims on issued tokens. Visible on the dashboard Delegation tab.

## Revocation / kill switch

**Why you care:** Compromise response cannot wait for JWT expiry.

CAEP `session-revoked` and related signals at `POST /v1/signals/events`. Starfly updates a local revocation index and propagates to peers. Target: deny on the exchange path within the documented ~30ms budget.

Concepts: [revocation](concepts/revocation.md) · Try: `./sandbox/run.sh revocation`

## Federation

Cross-fabric revocation sync without shared databases. Peers exchange hashes (`GET /v1/federation/revocation-hash`) and relay signals over configured transports.

## SET / CAEP / SSF

Shared Signals Framework — standardized security event tokens (e.g. OpenID CAEP). Ingested at `/v1/signals/events`; discovery at `/.well-known/ssf-configuration`.

Reference: [OpenAPI — signals](https://starfly.dev/api/operations/tags/signals/).

## MCP (Model Context Protocol)

Tool-calling protocol for AI agents. Starfly registers tools and verifies calls with audience binding.

Guide: [MCP security](integrators/mcp.md) · Code: [`pkg/mcp/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/mcp)

## UTC (Universal Tool-Calling Layer)

**Why you care:** Your agents won't all speak MCP — UTC keeps one identity story across wire formats.

Protocol-agnostic middleware: adapters normalize MCP, HTTP, A2A (and more) into one verification path.

Guide: [UTC](integrators/utc.md) · Code: [`pkg/toolcall/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/toolcall)

## Starfly Graph

Runtime identity knowledge graph — lineage, blast radius, tool history from fabric events. Async NATS consumer; does not block exchange.

Guide: [Starfly Graph](integrators/starfly-graph.md)

## Behavioral profile / Soul

Runtime behavior summary computed asynchronously (not on the exchange hot path). Surfaced on the dashboard Soul tab.

## Related

- [Getting started](getting-started.md)
- [Documentation voice](VOICE.md)
