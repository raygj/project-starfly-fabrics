# Glossary

Canonical terms for Starfly docs, the dashboard AI bar, and agent tooling.

## Trust domain

The **issuer-side identity boundary**. A trust domain names *who Starfly believes issued the incoming credential* and *which signing keys and policy bundle apply* on the way in.

- Configured in Starfly (`trustDomains` in Helm values or dev config).
- Appears as the `td` claim on issued WIMSE JWTs.
- Example: `dev.local` (synthetic dev mode), `sandbox.starfly.local` (lab fabric).

**Not the same as audience.** See below.

## Audience

The **downstream resource** a token is scoped to reach — an API URL, MCP tool resource URI, or service identifier.

- Requested at exchange time via the `audience` field (RFC 8693).
- Appears as the `aud` claim on the issued WIMSE JWT.
- MCP tools bind `aud` to a single `resource_uri`; presenting the token elsewhere is a [confused deputy](integrators/mcp.md) risk.

| Term | Question it answers |
|------|---------------------|
| Trust domain | *Where did this identity come from?* |
| Audience | *What is this token allowed to call?* |

## Fabric unit

One running Starfly PEP instance — a StatefulSet pod, local dev binary, or lab sandbox. Identified by `unit_id` in `/v1/sys/health`.

## Fabric

A logical security domain: one or more fabric units sharing policy, revocation state, and (optionally) federation peers. Lab example: `fabric-alpha`, `fabric-sandbox`.

## PEP (Policy Enforcement Point)

Starfly's runtime role. Validates credentials, evaluates OPA policy, mints WIMSE JWTs, enforces MCP tool audience, ingests CAEP/SSF signals, and maintains the revocation index.

Starfly is **not** an identity provider — it routes identity: any supported credential in, scoped JWT out.

## WIMSE JWT

Workload Identity in Multi-System Environments — the issued token profile. Short-lived, audience-bound, signed by Starfly's keys (JWKS at `/v1/identity/jwks`).

## Token exchange

RFC 8693 flow at `POST /v1/exchange/token`. Trade a platform credential (K8s SA, OIDC, SPIFFE, stub JWT in dev) for a WIMSE JWT.

## Delegation

An agent operating on behalf of another principal. Reflected in delegation depth and chain claims on issued tokens. Visible on the dashboard Delegation tab.

## Revocation / kill switch

CAEP `session-revoked` (and related) signals at `POST /v1/signals/events`. Starfly updates a local revocation index and propagates to peers. Target: **deny within 30ms** on the hot path.

## Federation

Cross-fabric revocation sync without shared databases. Peers exchange revocation hashes (`GET /v1/federation/revocation-hash`) and relay signals over configured transports.

## SET / CAEP / SSF

Shared Signals Framework events — standardized security event tokens (e.g. OpenID CAEP). Starfly ingests them at `/v1/signals/events` and exposes SSF discovery at `/.well-known/ssf-configuration`.

## MCP (Model Context Protocol)

Tool-calling protocol for AI agents. Starfly registers tools (`POST /v1/mcp/tools`) and verifies calls (`POST /v1/mcp/verify`) with audience binding.

## Behavioral profile / Soul

Runtime graph of agent behavior computed asynchronously (not on the exchange hot path). Surfaced on the dashboard Soul tab.
