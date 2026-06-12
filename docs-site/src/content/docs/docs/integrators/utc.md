---
title: UTC — Universal Tool-Calling Layer
description: One token, any protocol — MCP, REST, or A2A tool calls with the same identity, policy, and audit trail.
---

**Call the same tool from MCP, REST, or A2A with one WIMSE token and one audit trail.** The Universal Tool-Calling Layer (UTC) normalizes whatever arrives on the wire, verifies it once, and applies the same revocation and audience rules everywhere.

## Why it's worth your time

- **One registration, many clients** — agents pick the protocol their framework supports; you do not re-register or re-policy per wire format.
- **Same security story as MCP** — confused-deputy checks, audience binding, and kill-switch revocation apply to every adapter.
- **Off the exchange path** — UTC sits in front of your tool handlers; token exchange latency stays unchanged.

## How it works

```
Platform credential  →  POST /v1/exchange/token  →  WIMSE JWT
                              ↓
                    UTC middleware (your tool server)
                    adapter → verify → allow / deny
                              ↓
                         tool handler
```

Adapters translate native requests into one `ToolCallRequest`. A single **Verifier** checks token, audience, and revocation regardless of protocol.

| Adapter | Detects |
|---------|---------|
| MCP | JSON-RPC `tools/call` |
| HTTP | REST paths + Bearer token |
| A2A | Agent-to-agent task shapes |

Register tools with optional **protocol scope** — an MCP-only tool returns **403** on REST even when the token is valid.

## Wire it up

1. Exchange a platform credential for a WIMSE JWT — [token exchange](../token-exchange/).
2. Register the tool on the PEP (resource URI + allowed protocols) — [MCP security](../mcp/) covers PEP-side registration.
3. Mount UTC middleware on your tool server — [`pkg/toolcall`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/toolcall).
4. Point JWKS resolution at `GET /v1/identity/jwks` on your fabric unit.

**MCP:**

```bash
curl -s -X POST "$TOOL_URL/" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $WIMSE_JWT" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{"q":"starfly"}},"id":1}'
```

**HTTP (same token, same tool):**

```bash
curl -s "$TOOL_URL/api/search?q=starfly" \
  -H "Authorization: Bearer $WIMSE_JWT"
```

## What you should see

| Scenario | Result |
|----------|--------|
| MCP or HTTP with valid token | Same `subject`, same `tool_id`, protocol recorded in audit |
| Valid token, wrong protocol | **403** `capability_denied` |
| Token for tool A at tool B | **403** audience mismatch |

## Code in this repo

| Path | Status |
|------|--------|
| [`pkg/toolcall/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/toolcall) | Shipped — middleware, verifier, adapters |
| [`examples/multi-protocol-tool/`](https://github.com/raygj/project-starfly-fabrics/tree/main/examples/multi-protocol-tool) | Preview — demo export pending |

## Related

- [MCP security](../mcp/) — register and verify on the PEP
- [Exchange](../concepts/exchange/) · [Revocation](../concepts/revocation/) — fabric invariants
- [Documentation voice](../voice/) — how these pages are written
