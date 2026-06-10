---
title: UTC — Universal Tool-Calling Layer
description: Protocol-agnostic tool verification beyond MCP — adapters, Verifier, and the same WIMSE identity on every wire shape.
---

Starfly's core enforcement is **not MCP-specific**. The **Universal Tool-Calling Layer (UTC)** — ADR-0022 — normalizes any inbound tool call into one structure, verifies one token, and applies one policy surface.

MCP is the first adapter. HTTP generic and A2A adapters ship in `pkg/toolcall/`. More protocols plug in without touching the exchange hot path.

## Why UTC exists

Enterprises run multiple agent protocols at once:

| Protocol | Typical use |
|----------|-------------|
| **MCP** | LLM-native tool calling |
| **HTTP / REST** | Wrapped microservices, legacy APIs |
| **A2A** | Multi-agent task handoff |
| **Custom** | Internal RPC, framework plugins |

The security question is the same regardless of wire format: *Who called? Were they allowed? Can I revoke them? Can I audit it?*

UTC answers that once. Adapters only translate wire shape → `ToolCallRequest`.

## Architecture (off the exchange hot path)

```
Workload credential
       ↓
POST /v1/exchange/token  ← sacred hot path (124ns class)
       ↓
   WIMSE JWT
       ↓
┌──────────────────────────────────────┐
│  UTC middleware (pkg/toolcall)       │
│  Adapter (mcp | http | a2a) →        │
│  ToolCallRequest → Verifier → allow/deny │
└──────────────────────────────────────┘
       ↓
   Tool handler
```

Token exchange stays on the PEP. UTC sits **in front of tool handlers** — same revocation index, same audience rules, same audit semantics as [MCP security](mcp.md).

## Core types

| Concept | Role |
|---------|------|
| `ToolCallRequest` | Normalized call: protocol, tool ID, operation, params, token |
| `Verifier` | Single policy + audience + revocation gate (protocol-agnostic) |
| `Adapter` | Maps native request (JSON-RPC, REST, A2A) → `ToolCallRequest` |
| `VerifiedIdentity` | Subject, capabilities, blast radius, delegation depth |

Adapters compete on **confidence** — the highest-confidence match wins, then the Verifier runs protocol-aware checks.

## Supported adapters (today)

| Adapter | Package | Detects |
|---------|---------|---------|
| MCP | `pkg/toolcall/adapters/mcp` | JSON-RPC `tools/call`, MCP transports |
| HTTP generic | `pkg/toolcall/adapters/httpgeneric` | REST paths + Bearer token |
| A2A | `pkg/toolcall/adapters/a2a` | Agent-to-agent task shapes |

Register tools with optional **protocol scope** — e.g. MCP-only tools reject plain HTTP even when the token is valid.

## Integration pattern

1. Exchange platform credential → WIMSE JWT ([token exchange](token-exchange.md))
2. Register tool with `resource_uri` and allowed `protocols`
3. Mount UTC middleware on your tool server (`pkg/toolcall/middleware.go`)
4. Point `JWKSResolver` at `GET /v1/identity/jwks` on your fabric unit

**MCP client example:**

```bash
curl -s -X POST "$TOOL_URL/" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $WIMSE_JWT" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{"q":"starfly"}},"id":1}'
```

**HTTP client (same token, same tool):**

```bash
curl -s "$TOOL_URL/api/search?q=starfly" \
  -H "Authorization: Bearer $WIMSE_JWT"
```

## What UTC proves

| Story | Outcome |
|-------|---------|
| One tool, any client | Same tool via MCP or REST — one registration, one token |
| Wrong protocol | MCP-only tool + REST call → **403** `capability_denied` |
| Confused deputy | Token for tool A presented to tool B → **403** (audience mismatch) |
| Audit | Every decision logged with `protocol`, `tool_id`, `subject` |

## Relationship to MCP integrator guide

| Topic | Doc |
|-------|-----|
| Register tools, verify calls on the PEP | [MCP security](mcp.md) |
| Multi-protocol middleware in your app | This page (UTC) |
| Exchange + revocation invariants | [Exchange](../concepts/exchange.md), [Revocation](../concepts/revocation.md) |

## Status

`pkg/toolcall` is in this repo's public export. Full multi-protocol demo server ships in the private Starfly workspace; integrators can wire middleware using the packages above.
