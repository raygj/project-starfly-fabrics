---
title: MCP security
description: Stop the confused deputy — bind every MCP tool call to the right WIMSE token and resource URI.
---

**Stop agents from presenting a valid token for tool A to tool B.** Starfly registers MCP tools with a `resource_uri`, binds that value to `aud` on the WIMSE JWT, and returns **403** when they do not match — the confused-deputy fix for agentic tool calling.

## Why it's worth your time

- **One check, every MCP call** — verify audience before the tool executes, not after an incident.
- **Works with your existing exchange flow** — same RFC 8693 endpoint; `audience` must equal the tool's `resource_uri`.
- **Visible in ops** — denials show on the [MCP Security dashboard tab](/docs/docs/integrators/dashboard/) and in audit.

## How it works

```
Register tool (resource_uri)  →  Exchange with audience = resource_uri  →  WIMSE JWT
                                        ↓
                              POST /v1/mcp/verify on each call
                                        ↓
                              200 match · 403 confused deputy
```

For multi-protocol tool servers, add [UTC](/docs/docs/integrators/utc/) middleware in front of handlers; PEP-side registration and verify stay the same.

## Wire it up

### 1. Register the tool

```bash
curl -s -X POST "$STARFLY_URL/v1/mcp/tools" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "code-search",
    "name": "Code Search",
    "resource_uri": "https://mcp.example.com/tools/code-search",
    "server_id": "my-mcp-server"
  }' | jq
```

List registered tools: `GET /v1/mcp/tools`

### 2. Exchange for a tool-scoped token

```bash
curl -s -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<AGENT_OR_STUB_JWT>",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "audience": "https://mcp.example.com/tools/code-search"
  }' | jq -r .access_token
```

The `audience` **must** equal the tool's `resource_uri`. See [token exchange](/docs/docs/integrators/token-exchange/) for credential types and fields.

### 3. Verify on each call

```bash
curl -s -X POST "$STARFLY_URL/v1/mcp/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<WIMSE_JWT>",
    "tool_id": "code-search"
  }' | jq
```

| Result | Meaning |
|--------|---------|
| HTTP 200 | Token audience matches tool |
| HTTP 403 | Wrong tool or audience — confused deputy blocked |

### 4. Revoke when compromised

Send CAEP `session-revoked` or tool-specific signals via `POST /v1/signals/events`. See [revocation](/docs/docs/concepts/revocation/).

## Prove it in the sandbox

```bash
./sandbox/run.sh mcp
```

Expected: allow on `code-search`, **403** on `sql-admin` with the same token.

## Code in this repo

| Path | Status |
|------|--------|
| [`pkg/mcp/`](https://github.com/raygj/project-starfly-fabrics/tree/main/pkg/mcp) | Shipped — registry, verify middleware, client |
| [OpenAPI — MCP operations](https://starfly.dev/api/operations/tags/mcp/) | Reference |

## Related

- [Token exchange](/docs/docs/integrators/token-exchange/)
- [UTC](/docs/docs/integrators/utc/) — same identity on non-MCP wire shapes
- [Glossary: MCP](/docs/docs/glossary/#mcp-model-context-protocol)
- [Documentation voice](/docs/docs/voice/)
