# Integrator guide — MCP security

Register MCP tools and verify that presented tokens match the tool's resource URI.

## Threat: confused deputy

An agent holds a valid token scoped to **tool A** and presents it to **tool B**. Without audience checks, tool B executes under A's authority.

Starfly binds `aud` on the WIMSE JWT to the tool's `resource_uri` and returns **403** on mismatch.

## Register tools

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

List: `GET /v1/mcp/tools`

## Exchange for a tool-scoped token

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

The `audience` **must** equal the tool's `resource_uri`.

## Verify a tool call

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
| HTTP 403 | Confused deputy — wrong tool or audience |

## Revoke a compromised tool

Send CAEP `session-revoked` or tool-specific signals via `POST /v1/signals/events`. See [revocation concepts](../concepts/revocation.md).

## Sandbox proof

```bash
./sandbox/run.sh mcp
```

Expected: allow on `code-search`, 403 on `sql-admin` with the same token.

## Dashboard

MCP tool calls and policy denials appear on the MCP Security tab — see [screenshots](../screenshots/).

## Related

- [Token exchange](token-exchange.md)
- [Glossary: MCP](../glossary.md#mcp-model-context-protocol)
